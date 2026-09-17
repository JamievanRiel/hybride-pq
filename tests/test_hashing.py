from hybride_pq import constants
from hybride_pq.hashing import sha3_256


def test_sha3_256_known_answer():
    # NIST test vector for SHA3-256("abc")
    assert sha3_256(b"abc").hex() == (
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    )


def test_sha3_256_returns_32_bytes():
    assert len(sha3_256(b"")) == 32


def test_encoding_sizes_consistent():
    assert constants.PUBLIC_KEY_SIZE == 5 + 1952 + 32 == 1989
    assert constants.SECRET_KEY_SIZE == 5 + 32 + 64 == 101
    assert constants.SIGNATURE_SIZE == 5 + 3309 + 7856 == 11170
