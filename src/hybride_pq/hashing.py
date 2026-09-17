import hashlib


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 (FIPS 202), the general-purpose hash of PBP-1."""
    return hashlib.sha3_256(data).digest()
