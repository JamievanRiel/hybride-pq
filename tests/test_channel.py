import asyncio
import socket
from array import array

import pytest

from hybride_pq.channel import (
    AUTH_CONTEXT,
    HELLO_I_SIZE,
    HELLO_R_SIZE,
    MAGIC,
    MAX_MESSAGE,
    SecureChannel,
    _nonce,
    session_proof_message,
)
from hybride_pq.errors import ChannelError, InvalidSignature
from hybride_pq.keys import KeyPair
from hybride_pq.sign import _verify, sign, verify


@pytest.fixture(scope="module")
def alice():
    return KeyPair.generate()


@pytest.fixture(scope="module")
def bob():
    return KeyPair.generate()


@pytest.fixture(scope="module")
def mallory():
    return KeyPair.generate()


class _Net:
    """Makes connected stream pairs and closes every one of them afterwards."""

    def __init__(self):
        self._writers = []
        self._tasks = []

    async def streams(self):
        s1, s2 = socket.socketpair()
        (r1, w1), (r2, w2) = (
            await asyncio.open_connection(sock=s1),
            await asyncio.open_connection(sock=s2),
        )
        self._writers += [w1, w2]
        return (r1, w1), (r2, w2)

    async def channels(self):
        (r1, w1), (r2, w2) = await self.streams()
        return await asyncio.gather(
            SecureChannel.initiate(r1, w1), SecureChannel.respond(r2, w2)
        )

    async def relayed(self, flip_i2r=None, flip_r2i=None):
        """Initiator and responder connected through a relay that can flip one bit.

        ``flip_i2r``/``flip_r2i`` is the stream offset of the byte to change in that
        direction. Returns the results of initiate and respond, exceptions included.
        """
        (ri, wi), (rx1, wx1) = await self.streams()
        (rx2, wx2), (rr, wr) = await self.streams()
        self._tasks += [
            asyncio.create_task(_pump(rx1, wx2, flip_i2r)),
            asyncio.create_task(_pump(rx2, wx1, flip_r2i)),
        ]
        return await asyncio.wait_for(
            asyncio.gather(
                SecureChannel.initiate(ri, wi),
                SecureChannel.respond(rr, wr),
                return_exceptions=True,
            ),
            5,
        )

    async def close(self):
        for task in self._tasks:
            task.cancel()
        for writer in self._writers:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def _run(scenario):
    async def main():
        net = _Net()
        try:
            await scenario(net)
        finally:
            await net.close()

    asyncio.run(main())


async def _raw_frame(channel, counter, data):
    ct = channel._send_aead.encrypt(_nonce(counter), data, MAGIC)
    channel._writer.write(len(ct).to_bytes(4, "big") + ct)
    await channel._writer.drain()


async def _pump(reader, writer, flip_at):
    """Copy bytes until EOF, flipping the lowest bit of the byte at ``flip_at``."""
    offset = 0
    try:
        while data := await reader.read(65536):
            if flip_at is not None and offset <= flip_at < offset + len(data):
                data = bytearray(data)
                data[flip_at - offset] ^= 1
            offset += len(data)
            writer.write(bytes(data))
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


def test_messages_both_directions():
    async def scenario(net):
        a, b = await net.channels()
        await a.send(b"ping")
        assert await b.recv() == b"ping"
        await b.send(b"")
        await b.send(bytes(range(256)))
        assert await a.recv() == b""
        assert await a.recv() == bytes(range(256))

    _run(scenario)


def test_both_sides_share_a_fresh_session_id():
    async def scenario(net):
        a, b = await net.channels()
        c, d = await net.channels()
        assert a.session_id == b.session_id
        assert len(a.session_id) == 32
        assert a.session_id != c.session_id
        assert (a.is_initiator, b.is_initiator) == (True, False)

    _run(scenario)


def test_tampered_frame_rejected_and_channel_fails_closed():
    async def scenario(net):
        a, b = await net.channels()
        ct = bytearray(a._send_aead.encrypt(_nonce(0), b"x", MAGIC))
        ct[-1] ^= 1
        a._writer.write(len(ct).to_bytes(4, "big") + bytes(ct))
        await a._writer.drain()
        with pytest.raises(ChannelError):
            await b.recv()
        await _raw_frame(a, 0, b"a valid frame after the attack")
        with pytest.raises(ChannelError):
            await b.recv()

    _run(scenario)


def test_replayed_frame_rejected():
    async def scenario(net):
        a, b = await net.channels()
        await _raw_frame(a, 0, b"pay 5")
        await _raw_frame(a, 0, b"pay 5")
        assert await b.recv() == b"pay 5"
        with pytest.raises(ChannelError):
            await b.recv()

    _run(scenario)


def test_reordered_frames_rejected():
    async def scenario(net):
        a, b = await net.channels()
        await _raw_frame(a, 1, b"second")
        await _raw_frame(a, 0, b"first")
        with pytest.raises(ChannelError):
            await b.recv()

    _run(scenario)


def test_oversized_frame_rejected():
    async def scenario(net):
        a, b = await net.channels()
        a._writer.write((9 * 1024 * 1024).to_bytes(4, "big"))
        await a._writer.drain()
        with pytest.raises(ChannelError):
            await b.recv()

    _run(scenario)


def test_message_size_counts_bytes_not_items():
    async def scenario(net):
        a, b = await net.channels()
        wide = memoryview(array("I", bytes(4 * (MAX_MESSAGE // 4 + 1))))
        assert len(wide) <= MAX_MESSAGE < wide.nbytes
        with pytest.raises(ChannelError):
            await a.send(wide)
        with pytest.raises(TypeError):
            await a.send(5)

    _run(scenario)


def test_cancelled_recv_leaves_channel_unusable():
    async def scenario(net):
        a, b = await net.channels()
        a._writer.write((100).to_bytes(4, "big"))  # a header, but the body never comes
        await a._writer.drain()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(b.recv(), 0.2)
        await _raw_frame(a, 0, b"would be misparsed")
        with pytest.raises(ChannelError, match="failed earlier"):
            await b.recv()

    _run(scenario)


def test_oversized_message_refused_before_sending():
    async def scenario(net):
        a, b = await net.channels()
        with pytest.raises(ChannelError):
            await a.send(bytes(MAX_MESSAGE + 1))
        await a.send(b"still usable")
        assert await b.recv() == b"still usable"

    _run(scenario)


def test_closed_connection_raises():
    async def scenario(net):
        a, b = await net.channels()
        await a.close()
        with pytest.raises(ChannelError):
            await b.recv()
        with pytest.raises(ChannelError):
            await a.send(b"after close")

    _run(scenario)


def test_wrong_handshake_magic_rejected_and_transport_closed():
    async def scenario(net):
        (r1, w1), (r2, w2) = await net.streams()
        w1.write(b"XXXXXX" + bytes(HELLO_I_SIZE - 6))
        await w1.drain()
        with pytest.raises(ChannelError, match="wrong magic"):
            await SecureChannel.respond(r2, w2)
        assert w2.is_closing()
        assert await asyncio.wait_for(r1.read(), 2) == b""  # the peer sees EOF at once

    _run(scenario)


@pytest.mark.parametrize(
    ("direction", "offset", "checker"),
    [
        ("i2r", 10, "initiator"),  # X25519 value in hello_i
        ("r2i", 10, "initiator"),  # X25519 value in hello_r
        ("r2i", 1000, "initiator"),  # ML-KEM ciphertext in hello_r
        ("r2i", HELLO_R_SIZE + 5, "initiator"),  # confirm_r
        ("i2r", HELLO_I_SIZE + 5, "responder"),  # confirm_i
    ],
)
def test_tampered_handshake_fails_key_confirmation(direction, offset, checker):
    async def scenario(net):
        a, b = await net.relayed(**{f"flip_{direction}": offset})
        if checker == "initiator":
            assert isinstance(a, ChannelError) and "key confirmation" in str(a)
            assert isinstance(b, ChannelError)  # the initiator hung up; b did not wait
        else:
            assert isinstance(b, ChannelError) and "key confirmation" in str(b)
            with pytest.raises(ChannelError):
                await asyncio.wait_for(a.recv(), 5)

    _run(scenario)


def test_untampered_relay_works():
    async def scenario(net):
        a, b = await net.relayed()
        await a.send(b"through the relay")
        assert await b.recv() == b"through the relay"

    _run(scenario)


def test_two_initiators_fail_at_once():
    async def scenario(net):
        (r1, w1), (r2, w2) = await net.streams()
        results = await asyncio.wait_for(
            asyncio.gather(
                SecureChannel.initiate(r1, w1),
                SecureChannel.initiate(r2, w2),
                return_exceptions=True,
            ),
            5,
        )
        for result in results:
            assert isinstance(result, ChannelError) and "also an initiator" in str(result)

    _run(scenario)


def test_v1_peer_gets_a_version_error_not_a_hang():
    async def scenario(net):
        # a complete PBP1N1 hello_i is one byte shorter than a PBP1N2 one
        (r1, w1), (r2, w2) = await net.streams()
        w1.write(b"PBP1N1" + bytes(1222 - 6))
        await w1.drain()
        with pytest.raises(ChannelError, match="PBP1N1"):
            await asyncio.wait_for(SecureChannel.respond(r2, w2), 2)
        # and a PBP1N1 hello_r reaching a PBP1N2 initiator
        (r3, w3), (r4, w4) = await net.streams()
        w4.write(b"PBP1N1" + bytes(1126 - 6))
        await w4.drain()
        with pytest.raises(ChannelError, match="PBP1N1"):
            await asyncio.wait_for(SecureChannel.initiate(r3, w3), 2)

    _run(scenario)


def test_authenticate_both_sides(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        await asyncio.gather(
            a.authenticate(alice, bob.public_bytes()),
            b.authenticate(bob, alice.public_bytes()),
        )
        await a.send(b"authenticated")
        assert await b.recv() == b"authenticated"

    _run(scenario)


def test_responder_picks_the_matching_allowed_key(alice, bob, mallory):
    async def scenario(net):
        a, b = await net.channels()
        matched = await asyncio.gather(
            a.authenticate(alice, bob.public_bytes()),
            b.authenticate(bob, [mallory.public_bytes(), alice.public_bytes()]),
        )
        assert matched == [bob.public_bytes(), alice.public_bytes()]

    _run(scenario)


def test_initiator_must_name_exactly_one_key(alice, bob, mallory):
    async def scenario(net):
        a, b = await net.channels()
        with pytest.raises(ValueError):
            await a.authenticate(alice, [bob.public_bytes(), mallory.public_bytes()])

    _run(scenario)


def test_responder_rejects_unexpected_key_before_signing(alice, bob, mallory):
    async def scenario(net):
        a, b = await net.channels()
        await a.send(a.sign_session(mallory, bob.public_bytes()))
        with pytest.raises(InvalidSignature):
            await b.authenticate(bob, [alice.public_bytes()])
        with pytest.raises(ChannelError, match="failed earlier"):
            await b.send(b"nothing after a failed authentication")
        # the connection is closed, so the initiator learns it at once (no proof came back)
        with pytest.raises(ChannelError, match="connection lost"):
            await a.recv()

    _run(scenario)


def test_man_in_the_middle_is_detected(alice, bob):
    async def scenario(net):
        # Mallory accepts Alice's connection and opens her own to Bob, relaying.
        alice_to_mallory, mallory_from_alice = await net.channels()
        mallory_to_bob, bob_from_mallory = await net.channels()
        # Both legs are working encrypted channels, but their session ids differ,
        # and Alice's proof is bound to *her* leg: relaying it fails.
        assert alice_to_mallory.session_id != bob_from_mallory.session_id
        relayed = alice_to_mallory.sign_session(alice, bob.public_bytes())
        with pytest.raises(InvalidSignature):
            bob_from_mallory.verify_peer(bob.public_bytes(), alice.public_bytes(), relayed)

    _run(scenario)


def test_proof_meant_for_another_peer_is_rejected(alice, bob, mallory):
    async def scenario(net):
        # Alice thinks she talks to Mallory, who just forwards the bytes to Bob.
        a, b = await net.channels()
        proof = a.sign_session(alice, mallory.public_bytes())
        with pytest.raises(InvalidSignature):
            b.verify_peer(bob.public_bytes(), alice.public_bytes(), proof)

    _run(scenario)


def test_reflected_proof_rejected(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        # a peer that bounces our own proof back is not accepted as us
        own_proof = a.sign_session(alice, alice.public_bytes())
        with pytest.raises(InvalidSignature):
            a.verify_peer(alice.public_bytes(), alice.public_bytes(), own_proof)

    _run(scenario)


def test_session_proofs_and_ordinary_signatures_never_mix(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        message = session_proof_message(
            True, a.session_id, alice.public_bytes(), bob.public_bytes()
        )
        # an ordinary signature over exactly the proof bytes is not a proof...
        with pytest.raises(InvalidSignature):
            b.verify_peer(bob.public_bytes(), alice.public_bytes(), sign(alice, message))
        # ...and a proof is not an ordinary signature over anything
        proof = a.sign_session(alice, bob.public_bytes())
        with pytest.raises(InvalidSignature):
            verify(alice.public_bytes(), message, proof)
        # the separation really comes from the context string, not just the label
        assert AUTH_CONTEXT
        with pytest.raises(InvalidSignature):
            _verify(alice.public_bytes(), message, proof, b"")
        # it is a valid proof, and checking it alone leaves the channel usable
        b.verify_peer(bob.public_bytes(), alice.public_bytes(), proof)
        b.verify_peer(bob.public_bytes(), alice.public_bytes(), proof)

    _run(scenario)


def test_recv_refused_while_authenticate_runs(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        auth_b = asyncio.create_task(b.authenticate(bob, alice.public_bytes()))
        await asyncio.sleep(0)  # b now waits for the initiator's proof
        with pytest.raises(ChannelError, match="authenticate is running"):
            await asyncio.wait_for(b.recv(), 2)
        await a.authenticate(alice, bob.public_bytes())
        await auth_b

    _run(scenario)


def test_send_refused_while_authenticate_runs(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        auth_b = asyncio.create_task(b.authenticate(bob, alice.public_bytes()))
        await asyncio.sleep(0)
        with pytest.raises(ChannelError, match="authenticate is running"):
            await b.send(b"would arrive where the initiator expects a proof")
        await a.authenticate(alice, bob.public_bytes())
        await auth_b

    _run(scenario)


def test_authenticate_refused_after_the_channel_carried_data(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        await a.send(b"too early")
        assert await b.recv() == b"too early"
        with pytest.raises(ChannelError, match="directly after the handshake"):
            await asyncio.wait_for(a.authenticate(alice, bob.public_bytes()), 2)
        with pytest.raises(ChannelError, match="directly after the handshake"):
            await asyncio.wait_for(b.authenticate(bob, alice.public_bytes()), 2)

    _run(scenario)


def test_authenticate_refused_while_a_recv_is_pending(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        reader = asyncio.create_task(b.recv())  # would swallow the initiator's proof
        await asyncio.sleep(0)
        with pytest.raises(ChannelError, match="directly after the handshake"):
            await asyncio.wait_for(b.authenticate(bob, alice.public_bytes()), 2)
        reader.cancel()

    _run(scenario)


def test_authenticate_refused_while_another_authenticate_runs(alice, bob):
    async def scenario(net):
        a, b = await net.channels()
        auth_a = asyncio.create_task(a.authenticate(alice, bob.public_bytes()))
        await asyncio.sleep(0)  # a is still signing its proof: no frame, no lock yet
        with pytest.raises(ChannelError, match="directly after the handshake"):
            await asyncio.wait_for(a.authenticate(alice, bob.public_bytes()), 2)
        await b.authenticate(bob, alice.public_bytes())
        await auth_a

    _run(scenario)
