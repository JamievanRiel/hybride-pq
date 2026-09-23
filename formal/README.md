# Formal model of the PBP-1 channel

[`pbp1_channel.pvl`](pbp1_channel.pvl) is a symbolic model of the PBP-1 secure channel
([`docs/PROTOCOL.md`](../docs/PROTOCOL.md) section 4) for
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/).
[`verify.py`](verify.py) runs it under every combination of broken primitives and
checks each result against what PBP-1 claims.

> [!IMPORTANT]
> **This is not an audit.** A model can be wrong in ways that make it agree with its
> author, and it only covers what is listed below. It's meant to make an independent
> review faster and more precise, not to replace one.

## Running it

ProVerif 2.05 must be installed, for example with `opam install proverif`.

```bash
python formal/verify.py            # all scenarios and mutants, one job per CPU core
python formal/verify.py --jobs 4
python formal/verify.py --shard 2/8   # every 8th job, starting with the 2nd
```

The script finds `proverif` on `PATH`, in `~/.opam/default/bin`, or through the
`PROVERIF` environment variable. A full run needs about 110 CPU minutes, which took
about 15 minutes on 12 threads. `--shard I/K` splits the work over K machines. The
script exits with status 1 if any result differs from the claims below. The ProVerif output of a failed run is kept in a temporary
directory, and the script prints its path.

Continuous integration ([`formal.yml`](../.github/workflows/formal.yml)) builds
ProVerif 2.05 once from its checksummed source and runs the script in 8 shards in
parallel. It does this for every change to `formal/`, to `docs/PROTOCOL.md` or to
the workflow itself.

## What is modelled

| Part | Model |
|---|---|
| Handshake (4.1) | Version 2: `hello_i` and `hello_r` with their role byte, X25519 as Diffie-Hellman, ML-KEM-768 with implicit rejection, HKDF over both shared secrets and the full transcript, and key confirmation with two more HKDF blocks (`confirm_r`, `confirm_i`) sent in the clear |
| Frames (4.2) | ChaCha20-Poly1305 with separate keys per direction and `"PBP1N2"` as associated data. Counter 0 carries the session proof. After `authenticate()`, each side runs one loop per direction that sends or receives frames 1, 2, 3, … without limit. A frame that fails to decrypt ends the receiving loop (fail-closed) |
| Session binding (4.4) | `authenticate()`: the initiator proves first, the responder verifies against an allowed key and then proves, with role byte, session id, both fingerprints and the context string `"PBP1.auth.v1"` |
| Signatures (3) | ML-DSA-65 **and** SLH-DSA, both must verify. Next to the channel, every honest key also signs *any* message the attacker asks for with ordinary `sign()` |

The attacker controls the network (Dolev-Yao model). There is an unbounded number
of honest identities and sessions. A key may talk to itself, and honest parties
will also connect to keys that the attacker made.

## Properties

| Query | Meaning |
|---|---|
| `key_confirmation_initiator` | If an initiator finishes the handshake and the responder's hello reached it unchanged, that responder derived the same keys from the same transcript. So a change to `hello_i` on its way is caught before `initiate()` returns. |
| `key_confirmation_responder` | The same for a responder whose initiator's hello reached it unchanged. A change to `hello_r` is caught before `respond()` returns. |
| `auth_initiator` | If an initiator accepts an honest responder key, exactly one responder session with that key accepted the same initiator key, session id and traffic keys (injective agreement). |
| `auth_responder` | The same in the other direction, for a responder that accepts an honest initiator key. |
| `secrecy_i2r`, `secrecy_r2i` | Data sent after `authenticate()` to an honest peer stays secret. This includes an attacker who records everything and breaks more later. |
| `integrity_i2r`, `integrity_r2i` | Data received after `authenticate()` from an honest peer as frame *n* was sent by that peer as its frame *n*, on this session. A sender sends one message per counter, so no frame can be replayed, reordered, injected or dropped from the middle of the stream. |
| `signature_separation` | An ordinary signature that verifies for an honest key was issued by `sign()`. So a session proof never passes as one. |
| `reachable_*` | Sanity check: honest parties can finish the protocol. ProVerif must find this trace, or the other results could hold only because the model blocks somewhere. |

## Scenarios and claims

A *break* gives the attacker the secret behind every public value of that primitive.
That is what Shor's algorithm does to X25519, or what a new attack could do to any
of the others. A break happens either **now**, while sessions run, or **later**,
after they have ended and their ephemeral keys are gone. Breaking a signature scheme
later means the same as stealing every long-term signing key after the fact.

`verify.py` runs all 16 combinations of primitives broken now, and all 15 non-empty
combinations broken later. For each one it expects exactly this:

- **Authentication and signature separation** hold unless ML-DSA **and** SLH-DSA are
  both broken now.
- **Secrecy** holds unless both signatures are broken now (a man in the middle), or
  X25519 **and** ML-KEM are both broken, now or later ("harvest now, decrypt later").
  Breaking signatures later changes nothing: that is forward secrecy.
- **Integrity** holds unless both signatures are broken now, or both key exchanges
  are broken now.
- **Key confirmation** holds unless X25519 **and** ML-KEM are both broken now. An
  attacker who can compute the keys can also compute the confirmation values.
  Signatures play no part in it: key confirmation catches tampering, not
  impersonation.

A mismatch in either direction fails the run. So an attack that the claims say is
impossible fails it, and so does a property that holds where the claims say it
can't. The second kind of mismatch would mean the model is too weak to find attacks.

## Mutants

A model that agrees with every claim could still be vacuous. The mutants each remove
one design element from a copy of the model. ProVerif must then find a concrete
attack trace. That shows the element is needed, and that the model is able to fail.

| Removed | Scenario | Attack ProVerif must find |
|---|---|---|
| Context string on session proofs | nothing broken | An ordinary `sign()` signature becomes a valid session proof, and the reverse |
| Role byte in the proof | nothing broken | The attacker plays responder for a key that talks to itself, and reflects the initiator's own proof back |
| Peer fingerprint in the proof | nothing broken | Unknown key share: the responder accepts an initiator that meant to reach someone else |
| ML-KEM from the key derivation | X25519 broken | Traffic readable and forgeable |
| X25519 from the key derivation | ML-KEM broken | Traffic readable and forgeable |
| Separate traffic key per direction | nothing broken | A frame reflected back to its sender is accepted as the peer's message |
| Separate counters for the proof and application data (data starts at 0) | nothing broken | The initiator's session proof, replayed, is accepted as application data |
| Frame counter in the nonce of application frames | nothing broken | A replayed frame is accepted at another position. ProVerif no longer proves integrity, but cannot rebuild the attack it derives as a trace, so here "not proved" counts as caught |
| Key confirmation checks | nothing broken | Both sides finish a handshake that was changed in transit |
| Separate confirmation value per direction | nothing broken | `confirm_r`, reflected back to the responder, passes as `confirm_i` |
| Key separation of the confirmation values | nothing broken | With `confirm_r` equal to the traffic key r→i, that traffic is readable and forgeable |
| SLH-DSA check in hybrid verify | ML-DSA broken | Forged session proofs and signatures |

## What the model does not cover

Read these before you rely on a result.

- **Symbolic, not computational.** Primitives are perfect unless a scenario breaks
  them completely. Partial weaknesses, probabilities and concrete security levels are
  outside the model.
- **HKDF is a random oracle that needs both secrets.** This is the assumption that
  HKDF-SHA3-256 is a sound combiner of X25519 and ML-KEM. The model assumes it; it
  doesn't prove it.
- **Encoding details.** Messages are tuples. The byte layout is justified by fixed
  field lengths, but isn't checked here. X25519 low-order points and non-canonical
  encodings aren't modelled. Scenarios that break X25519 give the attacker more than
  those would.
- **Bytes and limits of frames.** The length field, the 8 MiB limit and nonce
  exhaustion after 2^64 frames are not modelled. The counter in the model has no
  upper bound; the code raises before it would reuse a nonce.
- **Truncation.** An attacker who cuts off the end of a stream is not detected. This
  is a known limitation of the protocol (README limitation 11), and the integrity
  queries do not claim otherwise.
- **Integrity is per position, not injective.** The queries say that frame *n* came
  from the peer's frame *n*. The injective version ("each frame is accepted at most
  once") cannot be proved: ProVerif treats the counters on the private channels as
  never consumed. It follows from the per-position result, because a receiver takes
  each counter only once.
- **Fail-closed is modelled but makes no difference.** A variant in which a failed
  frame leaves the channel usable, with the same counter, still satisfies every
  query. The symbolic attacker cannot forge a frame, so more attempts don't help it.
  Fail-closed matters for what the model leaves out: forgery attempts that each
  succeed with a small probability, and a byte stream that has lost its framing
  after a cancelled `recv`. `tests/test_channel.py` checks it.
- **Key confirmation assumes that one hello arrived unchanged.** Each query covers a
  handshake in which the peer's hello arrived unchanged. So it shows that a side
  catches a change to its *own* hello on the way out. That a side catches a change
  to the hello it *receives* is checked by `tests/test_channel.py`, not by a query. No query covers an attacker
  who changes *both* hellos without knowing the keys. The stronger statement, that
  the peer derived the same keys or the attacker knows them, needs `attacker(k1)` in
  the conclusion. ProVerif did not finish that version: after 11 minutes and 4.5 GB on
  a single scenario it was stopped.
- **Exclusive use during `authenticate()` is not modelled, and the claims don't
  need it.** In the model nothing else uses the channel until `authenticate()`
  returns. Without that rule the claims would still hold: accepting gives
  injective agreement on both traffic keys, so every frame under those keys comes
  from that one honest session, whatever the order of proof and data. What the
  rule prevents is an `authenticate()` that fails because an application frame took
  the proof's place. The channel code enforces the rule, and `tests/test_channel.py`
  checks it.
- **Allowed keys.** The attacker picks which allowed key a responder checks. That
  choice is at least as strong as any real allow list.
- **Secrecy is reachability secrecy** of the data sent. Indistinguishability
  properties, such as strong secrecy or the privacy of the initiator's identity
  (known not to hold), aren't checked.
- **The model describes the specification, not the Python code.** That the code
  matches the specification is up to the tests and the known-answer vectors in
  [`tests/vectors/`](../tests/vectors).
- **Not modelled:** the keystore, side channels, denial of service, metadata, and
  bugs in OpenSSL, `pqcrypto` or `argon2-cffi`.
