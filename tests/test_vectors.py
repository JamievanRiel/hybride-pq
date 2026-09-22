"""Known-answer tests: they pin every byte format, so accidental changes fail loudly."""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from hybride_pq import keystore
from hybride_pq.channel import (
    AUTH_CONTEXT,
    MAGIC,
    ROLE_I,
    ROLE_R,
    X25519_SIZE,
    _nonce,
    derive_keys,
    session_proof_message,
)
from hybride_pq.hashing import sha3_256
from hybride_pq.keys import KeyPair
from hybride_pq.sign import _verify, sign, verify

VECTORS = Path(__file__).parent / "vectors"
SIG = json.loads((VECTORS / "signature_v1.json").read_text())
CHANNEL = json.loads((VECTORS / "channel_v2.json").read_text())
PROOF = json.loads((VECTORS / "session_proof_v1.json").read_text())


def _hex(vector, name):
    return bytes.fromhex(vector[name])


def test_stored_signature_still_verifies():
    verify(_hex(SIG, "public_bytes"), _hex(SIG, "message"), _hex(SIG, "signature"))


def test_public_key_still_derives_from_secret():
    kp = KeyPair.from_secret_bytes(_hex(SIG, "secret_bytes"))
    assert kp.public_bytes().hex() == SIG["public_bytes"]


def test_fresh_signature_with_vector_key_verifies():
    kp = KeyPair.from_secret_bytes(_hex(SIG, "secret_bytes"))
    msg = _hex(SIG, "message")
    verify(_hex(SIG, "public_bytes"), msg, sign(kp, msg))


def test_hash_vector():
    assert sha3_256(_hex(SIG, "message")).hex() == SIG["sha3_256_of_message"]


def test_stored_keystore_still_opens():
    path = VECTORS / "keystore_v1.json"
    passphrase = json.loads(path.read_text())["test_passphrase"]
    assert keystore.load_versioned(path, passphrase) == (
        keystore.V1,
        _hex(SIG, "secret_bytes"),
    )


def test_channel_handshake_derives_pinned_keys():
    x_i = x25519.X25519PrivateKey.from_private_bytes(_hex(CHANNEL, "x25519_sk_initiator"))
    x_r = x25519.X25519PrivateKey.from_private_bytes(_hex(CHANNEL, "x25519_sk_responder"))
    kem_i = mlkem.MLKEM768PrivateKey.from_seed_bytes(_hex(CHANNEL, "mlkem768_seed_initiator"))
    hello_i, hello_r = _hex(CHANNEL, "hello_i"), _hex(CHANNEL, "hello_r")
    header = len(MAGIC) + len(ROLE_R)

    assert hello_i == (
        MAGIC + ROLE_I + x_i.public_key().public_bytes_raw()
        + kem_i.public_key().public_bytes_raw()
    )
    assert hello_r[: header + X25519_SIZE] == MAGIC + ROLE_R + x_r.public_key().public_bytes_raw()

    ss_x = x_i.exchange(x_r.public_key())
    ss_kem = kem_i.decapsulate(hello_r[header + X25519_SIZE :])
    keys = derive_keys(ss_x, ss_kem, hello_i, hello_r)
    for name, value in keys._asdict().items():
        assert value.hex() == CHANNEL[name], name


def test_channel_first_frame_is_pinned():
    aead = ChaCha20Poly1305(_hex(CHANNEL, "key_i2r"))
    assert aead.encrypt(_nonce(0), _hex(CHANNEL, "frame0_plaintext"), MAGIC).hex() == (
        CHANNEL["frame0_i2r"]
    )


def test_session_proof_message_and_proof_are_pinned():
    assert PROOF["context"] == AUTH_CONTEXT.hex()
    message = session_proof_message(
        True,
        _hex(PROOF, "session_id"),
        _hex(PROOF, "initiator_public"),
        _hex(PROOF, "responder_public"),
    )
    assert message.hex() == PROOF["initiator_proof_message"]
    _verify(_hex(PROOF, "initiator_public"), message, _hex(PROOF, "initiator_proof"), AUTH_CONTEXT)
