import json
import os
import stat

import pytest

from hybride_pq.errors import KeystoreDecryptError, KeystoreError
from hybride_pq.keystore import V1, V2, load, load_versioned, save

SECRET = b"\x01" * 101
PASS = "correct horse battery staple"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "wallet.json"
    save(path, SECRET, PASS)
    return path


def _edit(path, change):
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))


def _flip_hex(h: str) -> str:
    return ("1" if h[0] == "0" else "0") + h[1:]


def test_roundtrip(store):
    assert load(store, PASS) == SECRET


def test_wrong_passphrase_fails(store):
    with pytest.raises(KeystoreDecryptError):
        load(store, "wrong passphrase")


def test_file_contains_no_plaintext_secret(store):
    raw = store.read_text()
    assert SECRET.hex() not in raw.lower()
    assert json.loads(raw)["version"] == V1


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(ciphertext=_flip_hex(d["ciphertext"])),
        lambda d: d["kdf"].update(salt=_flip_hex(d["kdf"]["salt"])),
        lambda d: d["cipher"].update(nonce=_flip_hex(d["cipher"]["nonce"])),
        # the version string is authenticated: swapping in the other valid one fails too
        lambda d: d.update(version=V2),
    ],
    ids=["ciphertext", "salt", "nonce", "version"],
)
def test_tampering_detected(store, change):
    _edit(store, change)
    with pytest.raises(KeystoreDecryptError):
        load(store, PASS)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(version="PBP1-keystore-9"),
        lambda d: d["kdf"].update(name="scrypt"),
        lambda d: d["kdf"].update(memory_cost=4 * 1024 * 1024),
        lambda d: d["kdf"].update(time_cost=0),
        lambda d: d["kdf"].update(parallelism="4"),
        lambda d: d["kdf"].update(parallelism=True),
        lambda d: d["kdf"].update(memory_cost=16, parallelism=4),
        lambda d: d["kdf"].update(hash_len=16),
        lambda d: d["kdf"].update(salt="00"),
        lambda d: d["cipher"].update(name="aes-gcm"),
        lambda d: d["cipher"].update(nonce="zz"),
        lambda d: d.update(kdf=[]),
        lambda d: d.pop("ciphertext"),
    ],
    ids=[
        "version", "kdf-name", "huge-memory", "zero-time", "str-param", "bool-param",
        "memory-below-parallelism", "hash-len", "short-salt", "cipher-name", "bad-hex",
        "kdf-not-object", "missing-field",
    ],
)
def test_out_of_spec_file_raises_keystore_error(store, change):
    _edit(store, change)
    with pytest.raises(KeystoreError):
        load(store, PASS)


def test_garbage_file_raises_keystore_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("this is not json {")
    with pytest.raises(KeystoreError):
        load(path, PASS)


def test_deeply_nested_file_raises_keystore_error(tmp_path):
    path = tmp_path / "nested.json"
    path.write_text("[" * 200_000)
    with pytest.raises(KeystoreError):
        load(path, PASS)


def test_unencodable_passphrase_raises_keystore_error(store, tmp_path):
    lone_surrogate = "pass\udcff"
    with pytest.raises(KeystoreError):
        load(store, lone_surrogate)
    with pytest.raises(KeystoreError):
        save(tmp_path / "x.json", SECRET, lone_surrogate)


def test_empty_passphrase_refused(tmp_path):
    with pytest.raises(KeystoreError):
        save(tmp_path / "x.json", SECRET, "")


def test_unwritable_location_raises_keystore_error(tmp_path):
    with pytest.raises(KeystoreError):
        save(tmp_path / "no-such-dir" / "x.json", SECRET, PASS)


def test_missing_file_raises_keystore_error(tmp_path):
    with pytest.raises(KeystoreError):
        load(tmp_path / "nope.json", PASS)


def test_salt_and_nonce_differ_per_save(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    save(a, SECRET, PASS)
    save(b, SECRET, PASS)
    doc_a, doc_b = json.loads(a.read_text()), json.loads(b.read_text())
    assert doc_a["kdf"]["salt"] != doc_b["kdf"]["salt"]
    assert doc_a["cipher"]["nonce"] != doc_b["cipher"]["nonce"]


def test_v2_roundtrip_and_versioned(tmp_path):
    path = tmp_path / "v2.json"
    save(path, SECRET, PASS, version=V2)
    assert load_versioned(path, PASS) == (V2, SECRET)


def test_save_unknown_version_rejected(tmp_path):
    with pytest.raises(KeystoreError):
        save(tmp_path / "x.json", SECRET, PASS, version="PBP1-keystore-9")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_file_is_readable_by_owner_only(store):
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="directory fsync is POSIX only")
def test_failing_directory_sync_does_not_fail_a_completed_save(store, monkeypatch):
    real_fsync = os.fsync

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("fsync not supported on this directory")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    save(store, SECRET, "new passphrase")
    assert load(store, "new passphrase") == SECRET


def test_overwrite_is_atomic_and_leaves_no_temp_files(store):
    save(store, b"\x02" * 101, PASS)
    assert load(store, PASS) == b"\x02" * 101
    assert [p.name for p in store.parent.iterdir()] == [store.name]
