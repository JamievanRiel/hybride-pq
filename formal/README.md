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
```

The script finds `proverif` on `PATH`, in `~/.opam/default/bin`, or through the
`PROVERIF` environment variable. A full run needs about 40 CPU minutes, which took
just over 4 minutes on 12 threads. It exits with status 1 if any result differs from
the claims below. The ProVerif output of a failed run is kept in a temporary
directory, and the script prints its path.

## What is modelled

| Part | Model |
|---|---|
| Handshake (4.1) | `hello_i`, `hello_r`, X25519 as Diffie-Hellman, ML-KEM-768 with implicit rejection, HKDF over both shared secrets and the full transcript |
| Frames (4.2) | ChaCha20-Poly1305 with separate keys per direction, counter 0 (session proof) and counter 1 (first application message), `"PBP1N1"` as associated data |
| Session binding (4.4) | `authenticate()`: the initiator proves first, the responder verifies against an allowed key and then proves, with role byte, session id, both fingerprints and the context string `"PBP1.auth.v1"` |
| Signatures (3) | ML-DSA-65 **and** SLH-DSA, both must verify. Next to the channel, every honest key also signs *any* message the attacker asks for with ordinary `sign()` |

The attacker controls the network (Dolev-Yao model). There is an unbounded number
of honest identities and sessions. A key may talk to itself, and honest parties
will also connect to keys that the attacker made.

## Properties

| Query | Meaning |
|---|---|
| `auth_initiator` | If an initiator accepts an honest responder key, exactly one responder session with that key accepted the same initiator key, session id and traffic keys (injective agreement). |
| `auth_responder` | The same in the other direction, for a responder that accepts an honest initiator key. |
| `secrecy_i2r`, `secrecy_r2i` | Data sent after `authenticate()` to an honest peer stays secret. This includes an attacker who records everything and breaks more later. |
| `integrity_i2r`, `integrity_r2i` | Data received after `authenticate()` from an honest peer was sent by that peer, on this session. |
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
- **Only the first frames.** Per direction the model covers counter 0 and 1. It does
  not cover longer streams, the length field and 8 MiB limit, truncation (a known
  limitation), nonce exhaustion or the fail-closed channel state.
- **Concurrency rules are assumed.** The requirement that nothing else uses the
  channel until `authenticate()` returns is taken as given.
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
