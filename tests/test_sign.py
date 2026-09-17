import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa
from pqcrypto.sign import slh_dsa_shake_128s as slh

from hybride_pq import constants
from hybride_pq.errors import InvalidSignature, MalformedEncoding
from hybride_pq.keys import KeyPair
from hybride_pq.sign import sign, verify

SPLIT = constants.HEADER_SIZE + constants.MLDSA_SIG_SIZE


@pytest.fixture(scope="module")
def kp():
    return KeyPair.generate()


@pytest.fixture(scope="module")
def signed(kp):
    msg = b"send 5 coins to Alice"
    return msg, sign(kp, msg)


def test_roundtrip(kp, signed):
    msg, sig = signed
    assert len(sig) == constants.SIGNATURE_SIZE
    verify(kp.public_bytes(), msg, sig)  # must not raise


def test_tampered_message_fails(kp, signed):
    _, sig = signed
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), b"send 500 coins to Alice", sig)


def test_wrong_key_fails(signed):
    msg, sig = signed
    with pytest.raises(InvalidSignature):
        verify(KeyPair.generate().public_bytes(), msg, sig)


def _flip(sig: bytes, index: int) -> bytes:
    out = bytearray(sig)
    out[index] ^= 1
    return bytes(out)


def test_tampered_mldsa_component_fails(kp, signed):
    msg, sig = signed
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), msg, _flip(sig, constants.HEADER_SIZE + 10))


def test_tampered_slh_component_fails(kp, signed):
    # both-required rule: breaking only the SLH-DSA component must already fail
    msg, sig = signed
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), msg, _flip(sig, SPLIT + 10))


def test_components_from_different_messages_fail(kp, signed):
    # each half is a genuine signature by this key, but not over the same message
    msg, sig = signed
    other = sign(kp, b"send 5 coins to Mallory")
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), msg, sig[:SPLIT] + other[SPLIT:])
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), msg, other[:SPLIT] + sig[SPLIT:])


def test_signatures_without_domain_separation_fail(kp):
    # raw signatures over the bare message must not pass as PBP-1 signatures
    msg = b"send 5 coins to Alice"
    raw_mldsa = mldsa.MLDSA65PrivateKey.from_seed_bytes(kp.mldsa_seed).sign(msg)
    raw_slh = slh.sign(kp.slh_sk, msg)
    forged = constants.MAGIC + bytes([constants.SUITE_V1]) + raw_mldsa + raw_slh
    with pytest.raises(InvalidSignature):
        verify(kp.public_bytes(), msg, forged)


def test_signing_is_randomized(kp, signed):
    msg, sig = signed
    assert sign(kp, msg) != sig


def test_malformed_signature_rejected(kp, signed):
    msg, sig = signed
    with pytest.raises(MalformedEncoding):
        verify(kp.public_bytes(), msg, sig[:-1])
    with pytest.raises(MalformedEncoding):
        verify(kp.public_bytes(), msg, b"XXXX" + sig[4:])


def test_malformed_public_key_rejected(kp, signed):
    msg, sig = signed
    with pytest.raises(MalformedEncoding):
        verify(kp.public_bytes()[:-1], msg, sig)
