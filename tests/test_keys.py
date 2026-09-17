import pytest

from hybride_pq import constants
from hybride_pq.errors import MalformedEncoding
from hybride_pq.keys import KeyPair, parse_public_bytes


def test_generate_produces_correct_sizes():
    kp = KeyPair.generate()
    assert len(kp.public_bytes()) == constants.PUBLIC_KEY_SIZE
    assert len(kp.secret_bytes()) == constants.SECRET_KEY_SIZE
    assert kp.public_bytes()[:5] == constants.MAGIC + bytes([constants.SUITE_V1])


def test_two_keypairs_differ():
    assert KeyPair.generate().public_bytes() != KeyPair.generate().public_bytes()


def test_secret_roundtrip_restores_same_public_key():
    kp = KeyPair.generate()
    kp2 = KeyPair.from_secret_bytes(kp.secret_bytes())
    assert kp2.public_bytes() == kp.public_bytes()


def test_parse_public_bytes_splits_components():
    kp = KeyPair.generate()
    mldsa_pk, slh_pk = parse_public_bytes(kp.public_bytes())
    assert len(mldsa_pk) == constants.MLDSA_PK_SIZE
    assert len(slh_pk) == constants.SLH_PK_SIZE


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b"XXXX" + b[4:],  # wrong magic
        lambda b: b[:4] + b"\x02" + b[5:],  # unknown suite
        lambda b: b[:-1],  # too short
        lambda b: b + b"\x00",  # too long
    ],
    ids=["magic", "suite", "short", "long"],
)
def test_malformed_blobs_rejected(mutate):
    kp = KeyPair.generate()
    with pytest.raises(MalformedEncoding):
        parse_public_bytes(mutate(kp.public_bytes()))
    with pytest.raises(MalformedEncoding):
        KeyPair.from_secret_bytes(mutate(kp.secret_bytes()))


def test_components_with_wrong_length_rejected():
    with pytest.raises(MalformedEncoding):
        KeyPair(b"", b"")
    with pytest.raises(MalformedEncoding):
        KeyPair(bytes(32), bytes(63))
    with pytest.raises(TypeError):
        KeyPair("a" * 32, "b" * 64)


def test_secret_bytes_accepts_bytearray():
    kp = KeyPair.generate()
    assert KeyPair.from_secret_bytes(bytearray(kp.secret_bytes())) == kp


def test_repr_leaks_no_secrets():
    kp = KeyPair.generate()
    assert kp.mldsa_seed.hex() not in repr(kp)
    assert kp.slh_sk.hex() not in repr(kp)
