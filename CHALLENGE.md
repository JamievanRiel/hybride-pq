# Break PBP-1

The README says it up front: the way PBP-1 *combines* its standardized primitives has
**not** been reviewed by independent cryptographers. This page is an open invitation to
do exactly that. It lists every security claim hybride-pq makes, what counts as
breaking one, and how a confirmed finding is credited.

There's no money involved. What you get is your name on this page and on the advisory,
and the knowledge that you broke a post-quantum protocol that claims to need two breaks
for every attack.

## Contents

- [What counts as a finding](#what-counts-as-a-finding)
- [The claims](#the-claims)
- [Rules](#rules)
- [Where to start](#where-to-start)
- [Hall of fame](#hall-of-fame)

## What counts as a finding

| Level | Meaning |
|---|---|
| **Break** | A claim below is false: you can do something it says is impossible, under the assumptions it names. |
| **Weakness** | A claim holds, but is weaker than stated, or rests on an assumption the documentation doesn't name or doesn't justify for the way PBP-1 uses a primitive. |
| **Bug** | The code disagrees with [`docs/PROTOCOL.md`](docs/PROTOCOL.md) (which is normative, so any mismatch is a bug), a parser accepts what it must reject, a data error isn't a `PBP1Error`, or the documentation states something that isn't true. |

These are **not** findings on their own:

- The known limits in the README section
  [What it does NOT protect against](README.md#what-it-does-not-protect-against) and in
  [What the model does not cover](formal/README.md#what-the-model-does-not-cover).
  Showing that one of them is *worse* than described does count.
- A break of a primitive itself (ML-DSA, SLH-DSA, ML-KEM, X25519, ChaCha20-Poly1305,
  Argon2id, SHA3). That's news for the whole world, not for this repository, though a
  note on how it affects PBP-1 is welcome.
- Bugs inside OpenSSL, `cryptography`, `pqcrypto` or `argon2-cffi`. See
  [SECURITY.md](SECURITY.md#scope).

## The claims

Each claim links to where the documentation makes it. Unless a claim says otherwise,
it assumes that the primitives are secure and that HKDF-SHA3-256 is a sound way to
combine the X25519 and ML-KEM secrets.

### Signatures

| # | Claim | Source |
|---|---|---|
| S1 | Forging a PBP-1 signature, or a session proof, for a message the key holder never signed requires breaking **both** ML-DSA-65 and SLH-DSA-SHAKE-128s (or Keccak, which both use). | [README §1](README.md#1-hybrid-signatures-two-locks-from-two-different-locksmiths), [PROTOCOL §3](docs/PROTOCOL.md#3-hybrid-signature) |
| S2 | An ordinary `sign()` signature never passes as a session proof, and a session proof never passes as an ordinary signature, even over identical bytes. A raw ML-DSA or SLH-DSA signature over the bare message never passes as a PBP-1 signature. | [README §9](README.md#9-domain-separation-and-strict-parsing), [PROTOCOL §4.4](docs/PROTOCOL.md#44-session-binding-authentication) |
| S3 | A key or signature with a wrong length, magic or suite byte is rejected with `MalformedEncoding` before any cryptography runs. | [PROTOCOL §2](docs/PROTOCOL.md#2-encodings) |

Turning one valid signature into a *different* valid signature for the same message is
explicitly only as hard as the weaker half ([README §1](README.md#1-hybrid-signatures-two-locks-from-two-different-locksmiths)).
That alone is not a break of S1.

### Channel

| # | Claim | Source |
|---|---|---|
| C1 | **Secrecy.** Data sent after `authenticate` to an honest peer stays secret, unless both signature schemes are broken while the session runs, or X25519 **and** ML-KEM-768 are both broken, then or later. | [formal: scenarios and claims](formal/README.md#scenarios-and-claims) |
| C2 | **Integrity.** Frame *n* received after `authenticate` from an honest peer is that peer's frame *n* on this session: nothing can be replayed, reordered, injected, reflected or dropped from the middle of the stream. This holds unless both signature schemes, or X25519 and ML-KEM-768 together, are broken while the session runs. Cutting off the end is a known limit. | [README §5](README.md#5-every-message-is-sealed), [PROTOCOL §4.2](docs/PROTOCOL.md#42-frames), [formal: scenarios and claims](formal/README.md#scenarios-and-claims) |
| C3 | **Authentication.** If `authenticate` accepts an honest key, exactly one session of that key accepted the other side's key, with the same session id and traffic keys, unless both signature schemes are broken while the session runs. | [README §6](README.md#6-knowing-who-is-on-the-other-end-session-binding), [formal: properties](formal/README.md#properties) |
| C4 | **Key confirmation.** A handshake that was changed in transit fails inside `initiate` or `respond`, unless X25519 and ML-KEM-768 are both broken while it runs. | [README §3](README.md#3-hybrid-key-exchange-safe-if-either-half-survives), [PROTOCOL §4.1](docs/PROTOCOL.md#41-handshake) |
| C5 | **Forward secrecy.** Stealing a signing key or keystore after a connection has ended doesn't make that recorded connection readable. | [README §4](README.md#4-forward-secrecy) |
| C6 | **Fail closed.** After a `send` that fails while encrypting or writing, or any failure listed in PROTOCOL §4.2 (including a cancelled `recv` and a failed `authenticate`), the channel refuses every further `send` and `recv`. A message over the size limit is refused before anything happens and leaves the channel as it was. | [README §5](README.md#5-every-message-is-sealed), [PROTOCOL §4.2](docs/PROTOCOL.md#42-frames) |

### Keystore

| # | Claim | Source |
|---|---|---|
| K1 | Without the passphrase, there is no faster way to the secret in a keystore file than one full Argon2id evaluation (64 MiB, 3 passes) per guess. | [README §7](README.md#7-a-keystore-that-makes-guessing-expensive) |
| K2 | Changing the ciphertext, salt, nonce, version label or any Argon2 parameter makes loading fail. Only cosmetic changes, such as upper-case hex or extra JSON fields, are ignored. | [README §7](README.md#7-a-keystore-that-makes-guessing-expensive), [PROTOCOL §5](docs/PROTOCOL.md#5-keystore) |
| K3 | Every out-of-spec file listed in PROTOCOL §5 is rejected with `KeystoreError`, and loading never uses more than 1 GiB of memory for Argon2id. | [PROTOCOL §5](docs/PROTOCOL.md#5-keystore) |

### Everything

| # | Claim | Source |
|---|---|---|
| G1 | The code produces and accepts exactly the bytes [`docs/PROTOCOL.md`](docs/PROTOCOL.md) describes, and nothing else. | [PROTOCOL](docs/PROTOCOL.md) |
| G2 | Every error caused by the data (malformed keys, invalid signatures, broken or tampered files, failed connections) is a subclass of `PBP1Error`. | [README: API overview](README.md#api-overview) |

## Rules

- **Work on your own machine.** Everything you need is in this repository. There is no
  hosted PBP-1 service in scope, and Pingobit's network is not part of this challenge.
  Don't attack anyone's systems.
- **Show it.** A finding needs a way to check it: a script or test against a named
  commit of this repository, or, for a design-level finding, a written argument
  precise enough to verify.
- **Report privately** through the **Security** tab of this repository (**Report a
  vulnerability**), as described in [SECURITY.md](SECURITY.md). A documentation
  mistake that has no security impact can be an ordinary issue.
- **What happens next.** You'll get a first response within 7 days. Once a fix is
  available, the advisory is published with credit to you, unless you'd rather stay
  anonymous.
- The challenge covers the latest release and the `main` branch.

## Where to start

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) describes every byte hybride-pq produces or
  accepts.
- [`formal/README.md`](formal/README.md) explains what the ProVerif model proves, under
  which scenarios, and which mutants it catches. Its section
  [What the model does not cover](formal/README.md#what-the-model-does-not-cover) lists
  everything the model leaves to the tests and to review.
- [`tests/`](tests) and the known-answer vectors in [`tests/vectors/`](tests/vectors)
  show what is already checked.
- Set it up with the commands under
  [Installation](README.md#installation).

## Hall of fame

| Date | Who | Level | Finding | Advisory |
|---|---|---|---|---|
| | *No confirmed findings yet. This could be you.* | | | |
