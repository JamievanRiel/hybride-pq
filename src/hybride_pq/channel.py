"""Encrypted connection: hybrid X25519 + ML-KEM-768 handshake, ChaCha20-Poly1305 frames.

The handshake alone is *unauthenticated*: it stops eavesdroppers, not an active
man in the middle. Call :meth:`SecureChannel.authenticate` to bind known signing
keys to the connection.
"""

import asyncio
from collections.abc import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import ChannelError, InvalidSignature, MalformedEncoding
from .hashing import sha3_256
from .keys import KeyPair
from .sign import _sign, _verify

MAGIC = b"PBP1N1"
INFO_DOMAIN = b"PBP1.net.v1"
AUTH_DOMAIN = b"PBP1.auth.v1\x00"
# FIPS 204/205 context string: session proofs can never be ordinary signatures.
AUTH_CONTEXT = b"PBP1.auth.v1"
MAX_FRAME = 8 * 1024 * 1024
TAG_SIZE = 16
MAX_MESSAGE = MAX_FRAME - TAG_SIZE
X25519_SIZE = 32
MLKEM_EK_SIZE = 1184
MLKEM_CT_SIZE = 1088
HELLO_I_SIZE = len(MAGIC) + X25519_SIZE + MLKEM_EK_SIZE
HELLO_R_SIZE = len(MAGIC) + X25519_SIZE + MLKEM_CT_SIZE
_MAX_COUNTER = 2**64 - 1


async def _read_exact(reader, n: int) -> bytes:
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, OSError) as e:
        raise ChannelError(f"connection lost: {e}") from None


async def _write(writer, data: bytes) -> None:
    try:
        writer.write(data)
        await writer.drain()
    except OSError as e:
        raise ChannelError(f"connection lost: {e}") from None


def _nonce(counter: int) -> bytes:
    if counter > _MAX_COUNTER:
        raise ChannelError("nonce space exhausted; open a new channel")
    return bytes(4) + counter.to_bytes(8, "big")


def derive_keys(
    ss_x25519: bytes, ss_mlkem: bytes, hello_i: bytes, hello_r: bytes
) -> tuple[bytes, bytes, bytes]:
    """Turn both shared secrets and the full transcript into session keys.

    Returns ``(key initiator->responder, key responder->initiator, session_id)``.
    HKDF output blocks do not depend on the requested length, so the two traffic
    keys (bytes 0..64) are the same as in Pingobit, which derives only 64 bytes.
    """
    out = HKDF(
        algorithm=hashes.SHA3_256(),
        length=96,
        salt=None,
        info=INFO_DOMAIN + hello_i + hello_r,
    ).derive(ss_x25519 + ss_mlkem)
    return out[:32], out[32:64], out[64:]


def session_proof_message(
    signer_is_initiator: bool, session_id: bytes, signer_public: bytes, peer_public: bytes
) -> bytes:
    """The bytes a session proof signs: role, session, and who proves it to whom.

    The role byte stops a proof from being reflected back to its maker; the two
    fingerprints stop it from being presented to anyone but the intended peer.
    """
    return (
        AUTH_DOMAIN
        + (b"I" if signer_is_initiator else b"R")
        + session_id
        + sha3_256(signer_public)
        + sha3_256(peer_public)
    )


class SecureChannel:
    """An encrypted, integrity-protected message stream over asyncio streams.

    Create one with :meth:`initiate` (the side that connects) or :meth:`respond`
    (the side that accepts). After any failure the channel refuses further use.
    """

    def __init__(self, reader, writer, *, send_key, recv_key, session_id, initiator):
        self._reader = reader
        self._writer = writer
        self._send_aead = ChaCha20Poly1305(send_key)
        self._recv_aead = ChaCha20Poly1305(recv_key)
        self._send_counter = 0
        self._recv_counter = 0
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._usable = True
        self._session_id = session_id
        self._initiator = initiator

    @property
    def session_id(self) -> bytes:
        """32 bytes that both ends share only if no one sits in between."""
        return self._session_id

    @property
    def is_initiator(self) -> bool:
        return self._initiator

    @classmethod
    async def initiate(cls, reader, writer) -> "SecureChannel":
        x_sk = x25519.X25519PrivateKey.generate()
        kem_sk = mlkem.MLKEM768PrivateKey.generate()
        hello_i = (
            MAGIC
            + x_sk.public_key().public_bytes_raw()
            + kem_sk.public_key().public_bytes_raw()
        )
        await _write(writer, hello_i)
        hello_r = await _read_exact(reader, HELLO_R_SIZE)
        if hello_r[: len(MAGIC)] != MAGIC:
            raise ChannelError("handshake: wrong magic from responder")
        try:
            peer_x = x25519.X25519PublicKey.from_public_bytes(
                hello_r[len(MAGIC) : len(MAGIC) + X25519_SIZE]
            )
            ss_x = x_sk.exchange(peer_x)
            ss_kem = kem_sk.decapsulate(hello_r[len(MAGIC) + X25519_SIZE :])
        except ValueError as e:
            raise ChannelError(f"handshake failed: {e}") from None
        key_i2r, key_r2i, session_id = derive_keys(ss_x, ss_kem, hello_i, hello_r)
        return cls(
            reader, writer,
            send_key=key_i2r, recv_key=key_r2i, session_id=session_id, initiator=True,
        )

    @classmethod
    async def respond(cls, reader, writer) -> "SecureChannel":
        hello_i = await _read_exact(reader, HELLO_I_SIZE)
        if hello_i[: len(MAGIC)] != MAGIC:
            raise ChannelError("handshake: wrong magic from initiator")
        try:
            peer_x = x25519.X25519PublicKey.from_public_bytes(
                hello_i[len(MAGIC) : len(MAGIC) + X25519_SIZE]
            )
            peer_ek = mlkem.MLKEM768PublicKey.from_public_bytes(
                hello_i[len(MAGIC) + X25519_SIZE :]
            )
            ss_kem, ct = peer_ek.encapsulate()
            x_sk = x25519.X25519PrivateKey.generate()
            ss_x = x_sk.exchange(peer_x)
        except ValueError as e:
            raise ChannelError(f"handshake failed: {e}") from None
        hello_r = MAGIC + x_sk.public_key().public_bytes_raw() + ct
        await _write(writer, hello_r)
        key_i2r, key_r2i, session_id = derive_keys(ss_x, ss_kem, hello_i, hello_r)
        return cls(
            reader, writer,
            send_key=key_r2i, recv_key=key_i2r, session_id=session_id, initiator=False,
        )

    def _check_usable(self) -> None:
        if not self._usable:
            raise ChannelError("channel is closed or failed earlier")

    async def send(self, data: bytes) -> None:
        """Encrypt and send one message of at most :data:`MAX_MESSAGE` bytes."""
        data = bytes(memoryview(data))  # count bytes, not items; reject int/str
        if len(data) > MAX_MESSAGE:
            raise ChannelError(f"message too large: {len(data)} bytes, limit {MAX_MESSAGE}")
        async with self._send_lock:
            self._check_usable()
            try:
                frame = self._send_aead.encrypt(_nonce(self._send_counter), data, MAGIC)
                self._send_counter += 1
                await _write(self._writer, len(frame).to_bytes(4, "big") + frame)
            except ChannelError:
                self._usable = False
                raise

    async def recv(self) -> bytes:
        """Receive and decrypt the next message, in order.

        Cancelling a pending ``recv`` (for example with ``asyncio.wait_for``) may
        interrupt it mid-frame, so it leaves the channel unusable.
        """
        async with self._recv_lock:
            self._check_usable()
            try:
                length = int.from_bytes(await _read_exact(self._reader, 4), "big")
                if length > MAX_FRAME:
                    raise ChannelError(f"frame too large: {length} bytes")
                frame = await _read_exact(self._reader, length)
                try:
                    data = self._recv_aead.decrypt(_nonce(self._recv_counter), frame, MAGIC)
                except InvalidTag:
                    raise ChannelError(
                        "frame failed authentication (tampered, replayed, reordered or wrong key)"
                    ) from None
            except BaseException:
                self._usable = False
                raise
            self._recv_counter += 1
            return data

    def sign_session(self, my_keys: KeyPair, peer_public_bytes: bytes) -> bytes:
        """Proof that ``my_keys``' owner is on *this* connection, meant for that peer.

        Blocks for as long as :func:`hybride_pq.sign` (well under a second); in
        async code prefer :meth:`authenticate`, which runs it in a thread.
        """
        message = session_proof_message(
            self._initiator, self._session_id, my_keys.public_bytes(), peer_public_bytes
        )
        return _sign(my_keys, message, AUTH_CONTEXT)

    def verify_peer(self, my_public_bytes: bytes, peer_public_bytes: bytes, proof: bytes) -> None:
        """Check a peer's :meth:`sign_session` proof against the key you expect.

        Raises :class:`~hybride_pq.errors.InvalidSignature` (or
        :class:`~hybride_pq.errors.MalformedEncoding`) if the proof was made by
        another key, on another connection (a man in the middle), for another
        peer, or is not a session proof at all. This check alone leaves the
        channel usable, so you can try several allowed keys; stop using the
        channel if none of them matches.
        """
        message = session_proof_message(
            not self._initiator, self._session_id, peer_public_bytes, my_public_bytes
        )
        _verify(peer_public_bytes, message, proof, AUTH_CONTEXT)

    async def authenticate(
        self, my_keys: KeyPair, peer_public_bytes: bytes | Iterable[bytes]
    ) -> bytes:
        """Mutual authentication against public keys you already trust.

        Both sides call this right after the handshake, and nothing else may use
        the channel until it returns. The initiator names the one key it expects;
        the responder may pass a collection of allowed keys. Returns the peer key
        that matched.

        The initiator proves first; the responder only signs after that proof
        checks out, so an anonymous connection cannot make it spend CPU on
        signing. On any failure the channel becomes unusable and is closed.
        """
        if isinstance(peer_public_bytes, (bytes, bytearray, memoryview)):
            allowed = [bytes(peer_public_bytes)]
        else:
            allowed = [bytes(key) for key in peer_public_bytes]
        if not allowed or (self._initiator and len(allowed) != 1):
            raise ValueError("initiator needs exactly one peer key, responder at least one")
        my_public = my_keys.public_bytes()
        try:
            if self._initiator:
                await self._send_proof(my_keys, allowed[0])
                self.verify_peer(my_public, allowed[0], await self.recv())
                return allowed[0]
            proof = await self.recv()
            for candidate in allowed:
                try:
                    self.verify_peer(my_public, candidate, proof)
                except (InvalidSignature, MalformedEncoding):
                    continue
                await self._send_proof(my_keys, candidate)
                return candidate
            raise InvalidSignature("peer's session proof matches none of the allowed keys")
        except BaseException:
            self._usable = False
            self._writer.close()  # tell the peer right away instead of letting it time out
            raise

    async def _send_proof(self, my_keys: KeyPair, peer_public_bytes: bytes) -> None:
        proof = await asyncio.to_thread(self.sign_session, my_keys, peer_public_bytes)
        await self.send(proof)

    async def close(self) -> None:
        self._usable = False
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except OSError:
            pass
