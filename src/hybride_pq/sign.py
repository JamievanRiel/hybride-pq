from cryptography.exceptions import InvalidSignature as _MLDSAInvalid
from cryptography.hazmat.primitives.asymmetric import mldsa
from pqcrypto import InvalidSignatureError as _SLHInvalid
from pqcrypto.sign import slh_dsa_shake_128s as _slh

from . import constants
from .errors import InvalidSignature, MalformedEncoding
from .keys import KeyPair, parse_public_bytes

_HEADER = constants.MAGIC + bytes([constants.SUITE_V1])


def _parse_signature(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) != constants.SIGNATURE_SIZE:
        raise MalformedEncoding(
            f"signature: length {len(blob)}, expected {constants.SIGNATURE_SIZE}"
        )
    if blob[:4] != constants.MAGIC or blob[4] != constants.SUITE_V1:
        raise MalformedEncoding("signature: wrong magic or suite")
    body = blob[constants.HEADER_SIZE :]
    return body[: constants.MLDSA_SIG_SIZE], body[constants.MLDSA_SIG_SIZE :]


def _sign(keypair: KeyPair, data: bytes, context: bytes) -> bytes:
    mldsa_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(keypair.mldsa_seed)
    mldsa_sig = mldsa_key.sign(data, context)
    slh_sig = _slh.sign(keypair.slh_sk, data, context)
    return _HEADER + mldsa_sig + slh_sig


def _verify(public_bytes: bytes, data: bytes, signature: bytes, context: bytes) -> None:
    mldsa_pk, slh_pk = parse_public_bytes(public_bytes)
    mldsa_sig, slh_sig = _parse_signature(signature)
    try:
        mldsa_key = mldsa.MLDSA65PublicKey.from_public_bytes(mldsa_pk)
    except ValueError as e:
        raise MalformedEncoding(f"public key: invalid ML-DSA component: {e}") from None
    try:
        mldsa_key.verify(mldsa_sig, data, context)
    except _MLDSAInvalid:
        raise InvalidSignature("ML-DSA component does not verify") from None
    try:
        _slh.verify(slh_pk, data, slh_sig, context)
    except _SLHInvalid:
        raise InvalidSignature("SLH-DSA component does not verify") from None


def sign(keypair: KeyPair, message: bytes) -> bytes:
    """Sign ``message`` with both schemes; returns the 11 170-byte hybrid signature.

    Both schemes sign the same domain-separated bytes independently. Signing is
    randomized, so signing the same message twice gives different signatures.
    """
    return _sign(keypair, constants.SIGN_DOMAIN + message, b"")


def verify(public_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Return ``None`` only if *both* components verify.

    Raises :class:`MalformedEncoding` for a malformed key or signature and
    :class:`InvalidSignature` if either component fails.
    """
    _verify(public_bytes, constants.SIGN_DOMAIN + message, signature, b"")
