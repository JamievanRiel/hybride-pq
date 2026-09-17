"""Passphrase-protected storage for secrets: Argon2id + ChaCha20-Poly1305."""

import json
import os
import tempfile
from pathlib import Path

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .errors import KeystoreDecryptError, KeystoreError

V1 = "PBP1-keystore-1"
V2 = "PBP1-keystore-2"
VERSIONS = (V1, V2)
# RFC 9106, section 4, second recommended option: 3 passes over 64 MiB.
DEFAULT_KDF = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32}
SALT_SIZE = 16
NONCE_SIZE = 12

# Limits for parameters read from a file. They stop a crafted file from
# demanding, say, 100 GiB of memory; they are not a strength requirement.
_KDF_LIMITS = {"time_cost": (1, 16), "memory_cost": (8, 1024 * 1024), "parallelism": (1, 16)}


def _derive_key(passphrase: str, salt: bytes, params: dict) -> bytes:
    # The passphrase is used as exact UTF-8, without Unicode normalization.
    try:
        return hash_secret_raw(
            passphrase.encode("utf-8"),
            salt,
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
            hash_len=params["hash_len"],
            type=Type.ID,
        )
    except UnicodeEncodeError:
        raise KeystoreError("passphrase is not valid Unicode text") from None
    except HashingError as e:
        raise KeystoreError(f"key derivation failed: {e}") from None


def _checked_kdf(kdf: dict) -> dict:
    if kdf.get("name") != "argon2id":
        raise KeystoreError(f"unsupported KDF {kdf.get('name')!r}")
    params = {}
    for name, (low, high) in _KDF_LIMITS.items():
        value = kdf.get(name)
        if type(value) is not int or not low <= value <= high:
            raise KeystoreError(f"KDF parameter {name}={value!r} outside {low}..{high}")
        params[name] = value
    if params["memory_cost"] < 8 * params["parallelism"]:
        raise KeystoreError("KDF parameter memory_cost must be at least 8 x parallelism")
    if kdf.get("hash_len") != DEFAULT_KDF["hash_len"]:
        raise KeystoreError(f"KDF parameter hash_len={kdf.get('hash_len')!r}, expected 32")
    params["hash_len"] = DEFAULT_KDF["hash_len"]
    return params


def _write_private(path: Path, text: str) -> None:
    """Replace ``path`` atomically with a file only the owner can read (0600)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    if os.name == "posix":
        # Best effort: make the rename itself survive a crash. The new file is
        # already in place, so a failure here must not be reported as a failed save.
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


def save(path: str | Path, secret: bytes, passphrase: str, version: str = V1) -> None:
    """Encrypt ``secret`` under ``passphrase`` and write it to ``path``.

    Every call uses a fresh random salt and nonce, so the derived key (and the
    file) differ each time even for the same passphrase and secret.
    """
    if version not in VERSIONS:
        raise KeystoreError(f"unknown keystore version {version!r}")
    if not passphrase:
        raise KeystoreError("refusing to save with an empty passphrase")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(passphrase, salt, DEFAULT_KDF)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, secret, version.encode())
    doc = {
        "version": version,
        "kdf": {"name": "argon2id", **DEFAULT_KDF, "salt": salt.hex()},
        "cipher": {"name": "chacha20poly1305", "nonce": nonce.hex()},
        "ciphertext": ciphertext.hex(),
    }
    try:
        _write_private(Path(path), json.dumps(doc, indent=2))
    except OSError as e:
        raise KeystoreError(f"cannot write keystore: {e}") from None


def load_versioned(path: str | Path, passphrase: str) -> tuple[str, bytes]:
    """Decrypt a keystore; returns ``(version, secret)``.

    Raises :class:`KeystoreDecryptError` for a wrong passphrase *or* any
    tampering (the two are cryptographically indistinguishable) and
    :class:`KeystoreError` for a file that is unreadable or out of spec.
    """
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        version = doc["version"]
        kdf = doc["kdf"]
        cipher = doc["cipher"]
        salt = bytes.fromhex(kdf["salt"])
        nonce = bytes.fromhex(cipher["nonce"])
        ciphertext = bytes.fromhex(doc["ciphertext"])
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        raise KeystoreError(f"unreadable keystore: {e}") from None
    if version not in VERSIONS:
        raise KeystoreError(f"unknown keystore version {version!r}")
    if cipher.get("name") != "chacha20poly1305":
        raise KeystoreError(f"unsupported cipher {cipher.get('name')!r}")
    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
        raise KeystoreError("salt or nonce has the wrong length")
    key = _derive_key(passphrase, salt, _checked_kdf(kdf))
    try:
        return version, ChaCha20Poly1305(key).decrypt(nonce, ciphertext, version.encode())
    except InvalidTag:
        raise KeystoreDecryptError(
            "wrong passphrase or tampered keystore (indistinguishable)"
        ) from None


def load(path: str | Path, passphrase: str) -> bytes:
    """Decrypt a keystore and return only the secret."""
    return load_versioned(path, passphrase)[1]
