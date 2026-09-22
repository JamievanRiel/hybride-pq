"""Encrypted connection: hybrid X25519 + ML-KEM-768 handshake, ChaCha20-Poly1305 frames.

The handshake (PBP1N2) ends with key confirmation, so a tampered handshake is
caught by the handshake itself: the side that checks the changed value fails in
:meth:`SecureChannel.initiate` or :meth:`SecureChannel.respond`, and the other side
sees the connection close. It is still *unauthenticated*: it stops eavesdroppers, not an active
man in the middle. Call :meth:`SecureChannel.authenticate` to bind known signing
keys to the connection.
"""

import asyncio
import hmac
from collections.abc import Iterable
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import ChannelError, InvalidSignature, MalformedEncoding
from .hashing import sha3_256
from .keys import KeyPair
from .sign import _sign, _verify

MAGIC = b"PBP1N2"
_V1_MAGIC = b"PBP1N1"  # only recognised to name the mismatch
INFO_DOMAIN = b"PBP1.net.v2"
ROLE_I = b"I"
ROLE_R = b"R"
AUTH_DOMAIN = b"PBP1.auth.v1\x00"
# FIPS 204/205 context string: session proofs can never be ordinary signatures.
AUTH_CONTEXT = b"PBP1.auth.v1"
MAX_FRAME = 8 * 1024 * 1024
TAG_SIZE = 16
MAX_MESSAGE = MAX_FRAME - TAG_SIZE
X25519_SIZE = 32
MLKEM_EK_SIZE = 1184
MLKEM_CT_SIZE = 1088
CONFIRM_SIZE = 32
_HEADER_SIZE = len(MAGIC) + len(ROLE_I)
HELLO_I_SIZE = _HEADER_SIZE + X25519_SIZE + MLKEM_EK_SIZE
HELLO_R_SIZE = _HEADER_SIZE + X25519_SIZE + MLKEM_CT_SIZE
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


class SessionKeys(NamedTuple):
    key_i2r: bytes
    key_r2i: bytes
    session_id: bytes
    confirm_r: bytes
    confirm_i: bytes

    def __repr__(self) -> str:
        return "SessionKeys(<secret>)"  # keep traffic keys out of logs and tracebacks


def derive_keys(ss_x25519: bytes, ss_mlkem: bytes, hello_i: bytes, hello_r: bytes) -> SessionKeys:
    """Turn both shared secrets and the full transcript into five 32-byte blocks.

    Two traffic keys, the session id, and the values the responder and the
    initiator send to show they derived the same keys. Knowing one block
    reveals no other, so the confirmation values can travel in the clear.
    """
    out = HKDF(
        algorithm=hashes.SHA3_256(),
        length=160,
        salt=None,
        info=INFO_DOMAIN + hello_i + hello_r,
    ).derive(ss_x25519 + ss_mlkem)
    return SessionKeys(*(out[i : i + 32] for i in range(0, 160, 32)))


async def _read_hello(reader, expected_role: bytes, size: int) -> bytes:
    """Read the peer's hello, checking magic and role before waiting for the rest."""
    try:
        header = await _read_exact(reader, _HEADER_SIZE)
    except ChannelError:
        raise ChannelError(
            "handshake: the peer closed the connection before sending its hello "
            "(it may have rejected ours, for example because it speaks PBP1N1)"
        ) from None
    magic, role = header[: len(MAGIC)], header[len(MAGIC) :]
    if magic == _V1_MAGIC:
        raise ChannelError("handshake: the peer speaks PBP1N1; this library speaks PBP1N2")
    if magic != MAGIC:
        raise ChannelError("handshake: wrong magic; the peer does not speak PBP1N2")
    if role != expected_role:
        if role == ROLE_I:
            raise ChannelError("handshake: the peer is also an initiator; one side must respond")
        raise ChannelError("handshake: unexpected role byte from the peer")
    return header + await _read_exact(reader, size - _HEADER_SIZE)


def _check_confirmation(received: bytes, expected: bytes) -> None:
    if not hmac.compare_digest(received, expected):
        raise ChannelError(
            "handshake: key confirmation failed (tampered handshake, or the peer derived other keys)"
        )


def session_proof_message(
    signer_is_initiator: bool, session_id: bytes, signer_public: bytes, peer_public: bytes
) -> bytes:
    """The bytes a session proof signs: role, session, and who proves it to whom.

    The role byte stops a proof from being reflected back to its maker; the two
    fingerprints stop it from being presented to anyone but the intended peer.
    """
    return (
        AUTH_DOMAIN
        + (ROLE_I if signer_is_initiator else ROLE_R)
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
        self._authenticating = False
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
        """Run the handshake as the side that connects.

        Returns once the responder's key confirmation checked out. The
        responder checks ours afterwards; if it rejects it, this side learns
        that as a closed connection at its next ``recv``. On any failure,
        including cancellation, the transport is closed.
        """
        try:
            x_sk = x25519.X25519PrivateKey.generate()
            kem_sk = mlkem.MLKEM768PrivateKey.generate()
            hello_i = (
                MAGIC + ROLE_I
                + x_sk.public_key().public_bytes_raw()
                + kem_sk.public_key().public_bytes_raw()
            )
            await _write(writer, hello_i)
            hello_r = await _read_hello(reader, ROLE_R, HELLO_R_SIZE)
            try:
                peer_x = x25519.X25519PublicKey.from_public_bytes(
                    hello_r[_HEADER_SIZE : _HEADER_SIZE + X25519_SIZE]
                )
                ss_x = x_sk.exchange(peer_x)
                ss_kem = kem_sk.decapsulate(hello_r[_HEADER_SIZE + X25519_SIZE :])
            except ValueError as e:
                raise ChannelError(f"handshake failed: {e}") from None
            keys = derive_keys(ss_x, ss_kem, hello_i, hello_r)
            _check_confirmation(await _read_exact(reader, CONFIRM_SIZE), keys.confirm_r)
            await _write(writer, keys.confirm_i)
        except BaseException:
            writer.close()  # tell the peer right away instead of letting it time out
            raise
        return cls(
            reader, writer,
            send_key=keys.key_i2r, recv_key=keys.key_r2i, session_id=keys.session_id,
            initiator=True,
        )

    @classmethod
    async def respond(cls, reader, writer) -> "SecureChannel":
        """Run the handshake as the side that accepts.

        Returns once the initiator's key confirmation checked out. On any
        failure, including cancellation, the transport is closed.
        """
        try:
            hello_i = await _read_hello(reader, ROLE_I, HELLO_I_SIZE)
            try:
                peer_x = x25519.X25519PublicKey.from_public_bytes(
                    hello_i[_HEADER_SIZE : _HEADER_SIZE + X25519_SIZE]
                )
                peer_ek = mlkem.MLKEM768PublicKey.from_public_bytes(
                    hello_i[_HEADER_SIZE + X25519_SIZE :]
                )
                ss_kem, ct = peer_ek.encapsulate()
                x_sk = x25519.X25519PrivateKey.generate()
                ss_x = x_sk.exchange(peer_x)
            except ValueError as e:
                raise ChannelError(f"handshake failed: {e}") from None
            hello_r = MAGIC + ROLE_R + x_sk.public_key().public_bytes_raw() + ct
            keys = derive_keys(ss_x, ss_kem, hello_i, hello_r)
            await _write(writer, hello_r + keys.confirm_r)
            _check_confirmation(await _read_exact(reader, CONFIRM_SIZE), keys.confirm_i)
        except BaseException:
            writer.close()
            raise
        return cls(
            reader, writer,
            send_key=keys.key_r2i, recv_key=keys.key_i2r, session_id=keys.session_id,
            initiator=False,
        )

    def _check_usable(self) -> None:
        if not self._usable:
            raise ChannelError("channel is closed or failed earlier")

    def _check_not_authenticating(self) -> None:
        if self._authenticating:
            raise ChannelError("authenticate is running; nothing else may use the channel")

    async def send(self, data: bytes) -> None:
        """Encrypt and send one message of at most :data:`MAX_MESSAGE` bytes."""
        self._check_not_authenticating()
        await self._send(data)

    async def _send(self, data: bytes) -> None:
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
        self._check_not_authenticating()
        return await self._recv()

    async def _recv(self) -> bytes:
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
        the channel until it returns. The channel enforces that: this raises
        :class:`~hybride_pq.errors.ChannelError`, leaving the channel as it was,
        if a frame was already sent or received or a ``send``/``recv`` is still
        pending, and ``send``/``recv`` raise while it runs. The initiator names
        the one key it expects; the responder may pass a collection of allowed
        keys. Returns the peer key that matched.

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
        # A pending send has already counted its frame; a pending recv has not.
        if self._authenticating or self._send_counter or self._recv_counter or self._recv_lock.locked():
            raise ChannelError(
                "authenticate must run directly after the handshake, with nothing else using the channel"
            )
        my_public = my_keys.public_bytes()
        self._authenticating = True
        try:
            if self._initiator:
                await self._send_proof(my_keys, allowed[0])
                self.verify_peer(my_public, allowed[0], await self._recv())
                return allowed[0]
            proof = await self._recv()
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
        finally:
            self._authenticating = False

    async def _send_proof(self, my_keys: KeyPair, peer_public_bytes: bytes) -> None:
        proof = await asyncio.to_thread(self.sign_session, my_keys, peer_public_bytes)
        await self._send(proof)

    async def close(self) -> None:
        self._usable = False
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except OSError:
            pass
