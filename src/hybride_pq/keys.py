from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import mldsa
from pqcrypto.sign import slh_dsa_shake_128s as _slh

from . import constants
from .errors import MalformedEncoding

_HEADER = constants.MAGIC + bytes([constants.SUITE_V1])


def _strip_header(blob: bytes, expected_size: int, kind: str) -> bytes:
    if len(blob) != expected_size:
        raise MalformedEncoding(f"{kind}: length {len(blob)}, expected {expected_size}")
    if blob[:4] != constants.MAGIC:
        raise MalformedEncoding(f"{kind}: missing magic")
    if blob[4] != constants.SUITE_V1:
        raise MalformedEncoding(f"{kind}: unknown suite {blob[4]:#04x}")
    return blob[constants.HEADER_SIZE :]


def parse_public_bytes(blob: bytes) -> tuple[bytes, bytes]:
    """Split an encoded public key into its (ML-DSA, SLH-DSA) components."""
    body = _strip_header(blob, constants.PUBLIC_KEY_SIZE, "public key")
    return body[: constants.MLDSA_PK_SIZE], body[constants.MLDSA_PK_SIZE :]


@dataclass(frozen=True)
class KeyPair:
    """A hybrid signing key: one ML-DSA-65 key plus one SLH-DSA-SHAKE-128s key."""

    mldsa_seed: bytes = field(repr=False)
    slh_sk: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.mldsa_seed) is not bytes or type(self.slh_sk) is not bytes:
            raise TypeError("key pair components must be bytes")
        if (len(self.mldsa_seed), len(self.slh_sk)) != (
            constants.MLDSA_SEED_SIZE,
            constants.SLH_SK_SIZE,
        ):
            raise MalformedEncoding("key pair: component has the wrong length")

    @classmethod
    def generate(cls) -> "KeyPair":
        """Create a fresh key pair; all randomness comes from the OS CSPRNG."""
        mldsa_key = mldsa.MLDSA65PrivateKey.generate()
        _slh_pk, slh_sk = _slh.keygen()
        return cls(mldsa_key.private_bytes_raw(), slh_sk)

    @classmethod
    def from_secret_bytes(cls, blob: bytes) -> "KeyPair":
        """Restore a key pair from :meth:`secret_bytes` output."""
        body = _strip_header(bytes(blob), constants.SECRET_KEY_SIZE, "secret key")
        return cls(body[: constants.MLDSA_SEED_SIZE], body[constants.MLDSA_SEED_SIZE :])

    @property
    def slh_pk(self) -> bytes:
        # FIPS 205: the public key (PK.seed || PK.root) is the second half of sk
        return self.slh_sk[constants.SLH_PK_SIZE :]

    def public_bytes(self) -> bytes:
        """Encoded public key: ``PBP1 || 0x01 || mldsa_pk || slh_pk`` (1989 bytes)."""
        mldsa_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(self.mldsa_seed)
        mldsa_pk = mldsa_key.public_key().public_bytes_raw()
        return _HEADER + mldsa_pk + self.slh_pk

    def secret_bytes(self) -> bytes:
        """Encoded secret key: ``PBP1 || 0x01 || mldsa_seed || slh_sk`` (101 bytes)."""
        return _HEADER + self.mldsa_seed + self.slh_sk
