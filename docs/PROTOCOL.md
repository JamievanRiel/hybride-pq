# PBP-1 protocol specification (cipher suite 1)

This document describes every byte hybride-pq produces or accepts. It is normative for
this library: when the code and this document disagree, that is a bug. `‖` means
concatenation. All integers are big-endian.

## 1. Primitives

| Role | Algorithm | Standard | Implementation |
|---|---|---|---|
| Signature A | ML-DSA-65 | FIPS 204 | OpenSSL via `cryptography` |
| Signature B | SLH-DSA-SHAKE-128s | FIPS 205 | Rust crates via `pqcrypto` |
| Key exchange A | X25519 | RFC 7748 | OpenSSL via `cryptography` |
| Key exchange B | ML-KEM-768 | FIPS 203 | OpenSSL via `cryptography` |
| Key derivation | HKDF with SHA3-256 | RFC 5869, FIPS 202 | OpenSSL via `cryptography` |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | OpenSSL via `cryptography` |
| Password hashing | Argon2id | RFC 9106 | `argon2-cffi` |
| Hash | SHA3-256 | FIPS 202 | Python `hashlib` |

All randomness comes from the operating system's CSPRNG, directly (`os.urandom`) or
inside the libraries above.

## 2. Encodings

Every key and signature starts with the 5-byte header `"PBP1" ‖ 0x01` (magic and
suite byte) and has exactly one valid length.

| Object | Total | Body after the header |
|---|---|---|
| Public key | 1989 | ML-DSA-65 public key (1952) ‖ SLH-DSA public key (32) |
| Secret key | 101 | ML-DSA-65 seed ξ (32) ‖ SLH-DSA secret key (64) |
| Signature | 11170 | ML-DSA-65 signature (3309) ‖ SLH-DSA signature (7856) |

The SLH-DSA public key is the second half of the SLH-DSA secret key
(`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`, FIPS 205), so it is not stored twice.

Parsers MUST reject a wrong length, a wrong magic or an unknown suite byte with
`MalformedEncoding`, before running any cryptographic operation.

## 3. Hybrid signature

```
to_sign   = "PBP1.sig.v1" ‖ 0x00 ‖ message
signature = "PBP1" ‖ 0x01 ‖ ML-DSA-65.Sign(sk_A, to_sign) ‖ SLH-DSA.Sign(sk_B, to_sign)
```

- Both schemes use their "pure" mode with an empty context string, and randomized
  (hedged) signing. Session proofs (4.4) use the same encoding but a non-empty
  context string, so the two can never be confused.
- A signature is valid **if and only if both** components verify over `to_sign`
  against the matching halves of the public key. Every other outcome is
  `InvalidSignature`.

## 4. Secure channel

### 4.1 Handshake

```
Initiator: x_i  ← X25519 key pair, (ek, dk) ← ML-KEM-768.KeyGen()
           hello_i = "PBP1N1" ‖ X25519_pub(x_i) (32) ‖ ek (1184)            = 1222 bytes
Responder: (ss_k, ct) ← ML-KEM-768.Encaps(ek), x_r ← X25519 key pair
           hello_r = "PBP1N1" ‖ X25519_pub(x_r) (32) ‖ ct (1088)            = 1126 bytes
Both:      ss_x = X25519(own private, peer public)
           ss_k = (Initiator) ML-KEM-768.Decaps(dk, ct)
           out  = HKDF-SHA3-256(salt = none, IKM = ss_x ‖ ss_k,
                                info = "PBP1.net.v1" ‖ hello_i ‖ hello_r, L = 96)
           key_i2r = out[0:32], key_r2i = out[32:64], session_id = out[64:96]
```

- A wrong magic, a low-order X25519 point (all-zero shared secret) or an invalid ML-KEM
  key is a `ChannelError`. The handshake message lengths are fixed.
- HKDF output blocks do not depend on `L`. Pingobit derives only `L = 64`, and its
  traffic keys are identical to `out[0:64]`.
- The handshake alone authenticates nobody. See 4.4.

### 4.2 Frames

```
frame = length (4, big-endian) ‖ ChaCha20-Poly1305.Encrypt(key, nonce, plaintext, aad = "PBP1N1")
nonce = 0x00000000 ‖ counter (8, big-endian)
```

- Each direction has its own key and its own counter. The counter starts at 0 and
  increases by 1 per frame. The receiver always decrypts with the counter it expects,
  so replays, reordering, drops and injected frames fail authentication. A drop at the
  very end looks the same as a closed connection.
- `length` covers the ciphertext including the 16-byte tag and MUST NOT exceed
  8 MiB (8 388 608). The plaintext is therefore at most 8 388 592 bytes.
- The plaintext is opaque bytes. Pingobit sends UTF-8 JSON objects.
- After any failure (connection loss, oversized frame, failed tag, exhausted counter,
  a `recv` that was cancelled or interrupted, a failed `authenticate`), the channel
  refuses all further `send` and `recv` calls.

### 4.3 Limits

A channel carries at most 2^64 frames per direction. After that it raises instead of
reusing a nonce.

### 4.4 Session binding (authentication)

```
proof_message(role, signer_pk, peer_pk) =
    "PBP1.auth.v1" ‖ 0x00 ‖ role ‖ session_id ‖ SHA3-256(signer_pk) ‖ SHA3-256(peer_pk)
    role = "I" (0x49) for the initiator, "R" (0x52) for the responder

proof = "PBP1" ‖ 0x01 ‖ ML-DSA-65.Sign(sk_A, proof_message, ctx = "PBP1.auth.v1")
                     ‖ SLH-DSA.Sign(sk_B, proof_message, ctx = "PBP1.auth.v1")
```

- Keys are the encoded 1989-byte public keys from section 2. A proof is valid if and
  only if both components verify with that context string. Note that no
  `"PBP1.sig.v1"` prefix is added: the context string is what separates proofs from
  ordinary signatures (FIPS 204/205 put `0x00 ‖ len(ctx) ‖ ctx` in front of the message).
- **Verification:** the verifier rebuilds `proof_message` with the *peer's* role,
  `signer_pk` = the public key it expects for the peer, and `peer_pk` = its own public
  key. A man in the middle holds two handshakes with two different `session_id` values,
  so a proof from one connection does not verify on the other. The role byte stops a
  proof from being reflected back to its maker. The fingerprints stop it from being
  accepted by anyone other than the intended peer.
- **Order (`authenticate`):** directly after the handshake, the initiator sends its
  proof as one frame, naming the one responder key it expects. The responder checks it
  against each allowed initiator key and, only if one matches, sends its own proof
  (naming that key) as one frame. The initiator verifies that one.
- Callers MUST NOT send or receive anything else on the channel, from any task, until
  `authenticate` has returned. Nothing in the channel enforces this.
- Any failure inside `authenticate` makes the channel unusable and closes the transport.
  A failed `verify_peer` on its own does neither, so custom flows can try several keys.
  They MUST close the channel themselves if no key matches.

## 5. Keystore

UTF-8 JSON file:

```json
{
  "version": "PBP1-keystore-1",
  "kdf": {
    "name": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "hash_len": 32,
    "salt": "<16 bytes, hex>"
  },
  "cipher": { "name": "chacha20poly1305", "nonce": "<12 bytes, hex>" },
  "ciphertext": "<hex>"
}
```

```
key        = Argon2id(passphrase as UTF-8, salt, t = time_cost, m = memory_cost KiB, p = parallelism, 32 bytes)
ciphertext = ChaCha20-Poly1305.Encrypt(key, nonce, secret, aad = version as ASCII)
```

- **Writing:** a fresh 16-byte salt and 12-byte nonce for every save, with fixed
  parameters (RFC 9106, second recommended option). An empty passphrase is refused. The
  file is written to a temporary file, synced, and atomically renamed over the target.
  On POSIX the file has mode `0600` and the directory is synced too.
- **Passphrase:** encoded as UTF-8 exactly as given, without Unicode normalization.
  Text that can't be encoded (such as lone surrogates) is a `KeystoreError`.
- **Versions:** `PBP1-keystore-1` and `PBP1-keystore-2` are cryptographically
  identical. The label is authenticated. Pingobit uses `-2` to mark a keyring payload.
- **Reading:** unknown fields are ignored. The loader MUST reject, with
  `KeystoreError`, an unknown version, a KDF other than `argon2id`, a cipher other than
  `chacha20poly1305`, a salt that isn't 16 bytes, a nonce that isn't 12 bytes,
  `hash_len ≠ 32`, and parameters that aren't integers in these ranges:
  `time_cost` 1–16, `memory_cost` 8–1 048 576 KiB (1 GiB) with
  `memory_cost ≥ 8 × parallelism`, and `parallelism` 1–16. Unreadable JSON (including
  excessive nesting) and hex that doesn't decode are also a `KeystoreError`.
- A failed tag is `KeystoreDecryptError`. A wrong passphrase and tampering are
  indistinguishable by design.

## 6. Agility

A future algorithm set gets a new suite byte (keys and signatures), new domain labels
and a new keystore version. Implementations MUST NOT guess: an unknown suite or
version is an error, never a fallback.

## 7. Test vectors

| File | Pins |
|---|---|
| `tests/vectors/signature_v1.json` | Secret key → public key, a stored signature, SHA3-256 (generated by Pingobit) |
| `tests/vectors/keystore_v1.json` | A keystore file that must keep opening with its test passphrase |
| `tests/vectors/channel_v1.json` | Handshake private keys → hello messages, traffic keys, session id and the first frame |
| `tests/vectors/session_proof_v1.json` | A session proof message and a proof over it, for the session id above |
