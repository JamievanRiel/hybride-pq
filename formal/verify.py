"""Check the ProVerif model of the PBP-1 channel against what PBP-1 claims.

Each scenario lets the attacker break a different set of primitives, either now
(while sessions run) or later (after recording them). For every scenario this
script works out which properties PBP-1 claims still hold, runs ProVerif, and
fails on any difference.

A model can also agree with the claims because it is wrong, so the script runs
mutants too: copies of the model with one design element removed. Each mutant
must lose a property through an attack trace that ProVerif reconstructs.

Run from the repository root: python formal/verify.py
Needs ProVerif 2.05 on PATH, in ~/.opam/default/bin, or named in $PROVERIF.
"""

import argparse
import itertools
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import NamedTuple

MODEL = Path(__file__).with_name("pbp1_channel.pvl")
PRIMITIVES = ("x25519", "mlkem", "mldsa", "slh")
KEY_EXCHANGE = frozenset({"x25519", "mlkem"})
SIGNATURES = frozenset({"mldsa", "slh"})
TIMEOUT = 3600

# ProVerif echoes every query; its first event and its conclusion identify it.
QUERY_NAMES = {
    ("InitReceives", "false"): "reachable_initiator",
    ("RespReceives", "false"): "reachable_responder",
    ("InitAccepts", "RespAccepts"): "auth_initiator",
    ("RespAccepts", "InitProves"): "auth_responder",
    ("secret_i2r", None): "secrecy_i2r",
    ("secret_r2i", None): "secrecy_r2i",
    ("RespReceives", "InitSends"): "integrity_i2r",
    ("InitReceives", "RespSends"): "integrity_r2i",
    ("SigAccepted", "SigIssued"): "signature_separation",
}
RESULT = re.compile(r"^RESULT (.*) (is true|is false|cannot be proved)\.$", re.MULTILINE)


class Mutant(NamedTuple):
    name: str
    edits: tuple[tuple[str, str], ...]
    now: frozenset[str]
    must_fail: tuple[str, ...]


MUTANTS = (
    Mutant(
        "session proofs signed without their context string",
        (
            ("hybrid_sign(a, b, AUTH_CONTEXT, m)", "hybrid_sign(a, b, EMPTY_CONTEXT, m)"),
            ("hybrid_verify(pk, AUTH_CONTEXT, m, s)", "hybrid_verify(pk, EMPTY_CONTEXT, m, s)"),
        ),
        frozenset(),
        ("auth_initiator", "auth_responder", "signature_separation"),
    ),
    Mutant(
        "session proof without the role byte",
        (
            (
                "(AUTH_DOMAIN, role, session, sha3(signer), sha3(peer))",
                "(AUTH_DOMAIN, session, sha3(signer), sha3(peer))",
            ),
        ),
        frozenset(),
        ("auth_initiator",),
    ),
    Mutant(
        "session proof without the peer's fingerprint",
        (
            (
                "(AUTH_DOMAIN, role, session, sha3(signer), sha3(peer))",
                "(AUTH_DOMAIN, role, session, sha3(signer))",
            ),
        ),
        frozenset(),
        ("auth_responder",),
    ),
    Mutant(
        "keys derived from X25519 alone",
        (
            ("letfun derive(", "const LEFT_OUT: bitstring.\nletfun derive("),
            ("hkdf(ss_x, ss_k,", "hkdf(ss_x, LEFT_OUT,"),
        ),
        frozenset({"x25519"}),
        ("secrecy_i2r", "secrecy_r2i", "integrity_i2r", "integrity_r2i"),
    ),
    Mutant(
        "keys derived from ML-KEM alone",
        (
            ("letfun derive(", "const LEFT_OUT: G.\nletfun derive("),
            ("hkdf(ss_x, ss_k,", "hkdf(LEFT_OUT, ss_k,"),
        ),
        frozenset({"mlkem"}),
        ("secrecy_i2r", "secrecy_r2i", "integrity_i2r", "integrity_r2i"),
    ),
    Mutant(
        "one traffic key for both directions",
        (
            (
                "fun block_key_r2i(bitstring): key.",
                "letfun block_key_r2i(okm: bitstring) = block_key_i2r(okm).",
            ),
        ),
        frozenset(),
        ("integrity_i2r", "integrity_r2i"),
    ),
    Mutant(
        "every frame under the same nonce",
        (("const N1: nonce.  (* counter 1: the first application message *)", "letfun N1 = N0."),),
        frozenset(),
        ("integrity_i2r", "integrity_r2i"),
    ),
    Mutant(
        "hybrid signature that only checks ML-DSA",
        (
            (
                "verify_mldsa(pka, ctx, m, sa) && verify_slh(pkb, ctx, m, sb)",
                "verify_mldsa(pka, ctx, m, sa)",
            ),
        ),
        frozenset({"mldsa"}),
        ("auth_initiator", "auth_responder", "signature_separation"),
    ),
)


def claims(now: frozenset[str], later: frozenset[str]) -> dict[str, bool]:
    """ProVerif's expected answer per query: True = holds, False = attack found.

    A forged signature only helps while sessions run, so later signature breaks
    change nothing (forward secrecy). Recorded traffic stays secret unless both
    key exchanges fall, now or later.
    """
    signatures = not SIGNATURES <= now
    keys_now = not KEY_EXCHANGE <= now
    keys_ever = not KEY_EXCHANGE <= now | later
    return {
        "reachable_initiator": False,
        "reachable_responder": False,
        "auth_initiator": signatures,
        "auth_responder": signatures,
        "signature_separation": signatures,
        "secrecy_i2r": signatures and keys_ever,
        "secrecy_r2i": signatures and keys_ever,
        "integrity_i2r": signatures and keys_now,
        "integrity_r2i": signatures and keys_now,
    }


def query_name(text: str) -> str:
    if text.startswith("secret "):
        key = (text.split()[1], None)
    else:
        events = re.findall(r"event\((\w+)\(", text)
        key = (events[0], events[-1] if "==>" in text else "false")
    if key not in QUERY_NAMES:
        raise ValueError(f"unknown query in ProVerif output: {text}")
    return QUERY_NAMES[key]


def parse(output: str) -> dict[str, bool | None]:
    verdicts = {"is true": True, "is false": False, "cannot be proved": None}
    return {query_name(text): verdicts[verdict] for text, verdict in RESULT.findall(output)}


def mutate(model: str, edits) -> str:
    for old, new in edits:
        if model.count(old) != 1:
            raise ValueError(f"mutant edit must match exactly once: {old!r}")
        model = model.replace(old, new)
    return model


def label(broken: frozenset[str]) -> str:
    return "+".join(p for p in PRIMITIVES if p in broken) or "-"


def run_proverif(proverif, model, now, later, workdir: Path):
    workdir.mkdir(parents=True)
    flags = [p in now for p in PRIMITIVES] + [p in later for p in PRIMITIVES]
    (workdir / "model.pvl").write_text(model)
    (workdir / "main.pv").write_text(
        "process System(" + ", ".join(str(f).lower() for f in flags) + ")\n"
    )
    start = time.monotonic()
    proc = subprocess.run(
        [proverif, "-lib", "model.pvl", "main.pv"],
        cwd=workdir, capture_output=True, text=True, timeout=TIMEOUT,
    )
    (workdir / "proverif.out").write_text(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        raise RuntimeError(f"ProVerif failed, see {workdir / 'proverif.out'}")
    return parse(proc.stdout), time.monotonic() - start


def find_proverif() -> str:
    for candidate in (
        os.environ.get("PROVERIF"),
        shutil.which("proverif"),
        str(Path.home() / ".opam" / "default" / "bin" / "proverif"),
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    sys.exit("ProVerif not found: put it on PATH or set PROVERIF=/path/to/proverif")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)
    proverif = find_proverif()
    model = MODEL.read_text()
    subsets = [
        frozenset(combo) for n in range(len(PRIMITIVES) + 1)
        for combo in itertools.combinations(PRIMITIVES, n)
    ]
    scenarios = [(now, frozenset()) for now in subsets] + [(frozenset(), l) for l in subsets[1:]]
    outdir = Path(tempfile.mkdtemp(prefix="pbp1-proverif-"))
    print(f"{len(scenarios)} scenarios and {len(MUTANTS)} mutants, {args.jobs} jobs, output in {outdir}\n")

    jobs = [("scenario", now, later, model) for now, later in scenarios]
    jobs += [("mutant", m.now, frozenset(), mutate(model, m.edits)) for m in MUTANTS]
    failures = 0
    with ThreadPoolExecutor(args.jobs) as pool:
        futures = [
            pool.submit(run_proverif, proverif, text, now, later, outdir / f"{kind}-{i:02d}")
            for i, (kind, now, later, text) in enumerate(jobs)
        ]
        print(f"{'broken now':<28}{'broken later':<28}{'time':>6}  result")
        for future, (now, later) in zip(futures, scenarios):
            results, seconds = future.result()
            expected = claims(now, later)
            wrong = [q for q in expected if results.get(q) is not expected[q]]
            failures += bool(wrong)
            verdict = "as claimed" if not wrong else "MISMATCH " + ", ".join(
                f"{q} (expected {expected[q]}, got {results.get(q)})" for q in wrong
            )
            print(f"{label(now):<28}{label(later):<28}{seconds:>5.0f}s  {verdict}")

        width = max(len(f"{m.name} (now: {label(m.now)})") for m in MUTANTS) + 2
        print(f"\n{'mutant':<{width}}{'time':>6}  result")
        for future, mutant in zip(futures[len(scenarios):], MUTANTS):
            results, seconds = future.result()
            reachable = results.get("reachable_initiator") is False and (
                results.get("reachable_responder") is False
            )
            survived = [q for q in mutant.must_fail if results.get(q) is not False]
            failures += bool(survived) or not reachable
            if not reachable:
                verdict = "MODEL BLOCKS: honest run no longer reachable"
            elif survived:
                verdict = "SURVIVED: no attack on " + ", ".join(survived)
            else:
                verdict = "attack found on " + ", ".join(mutant.must_fail)
            name = f"{mutant.name} (now: {label(mutant.now)})"
            print(f"{name:<{width}}{seconds:>5.0f}s  {verdict}")

    if failures:
        print(f"\n{failures} check(s) failed; ProVerif output is in {outdir}")
        return 1
    shutil.rmtree(outdir)
    print("\nAll scenarios match the claims and every mutant was caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
