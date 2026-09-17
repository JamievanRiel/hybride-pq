"""hybride-pq: PBP-1 hybrid post-quantum signatures, channels and key storage."""

from . import keystore
from .channel import SecureChannel
from .errors import (
    ChannelError,
    InvalidSignature,
    KeystoreDecryptError,
    KeystoreError,
    MalformedEncoding,
    PBP1Error,
)
from .hashing import sha3_256
from .keys import KeyPair
from .sign import sign, verify

__version__ = "0.1.0"

__all__ = [
    "ChannelError",
    "InvalidSignature",
    "KeyPair",
    "KeystoreDecryptError",
    "KeystoreError",
    "MalformedEncoding",
    "PBP1Error",
    "SecureChannel",
    "keystore",
    "sha3_256",
    "sign",
    "verify",
]
