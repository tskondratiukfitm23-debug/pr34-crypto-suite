"""pytest-тести crypto-suite: roundtrip, tamper, keystore, container, CLI."""
import json
import secrets

import pytest

import asym
import cli
import hybrid
import sym
from errors import (BadPassword, IntegrityError, InvalidContainer, InvalidKey,
                    KeyPolicyViolation, SignatureInvalid, WrongRecipient)

DATA = b"Hello, crypto-suite! \xd0\x9f\xd0\xa0 3-4 " * 50
PW = "Test-Pa$$w0rd"


def flip(blob: bytes, pos: int) -> bytes:
    b = bytearray(blob)
    b[pos] ^= 0x01
    return bytes(b)


@pytest.fixture(scope="module")
def rsa_key():
    return asym.gen_rsa(2048)


@pytest.fixture(scope="module")
def ecc_key():
    return asym.gen_ecc("P-256")


# ============================================================ roundtrip
@pytest.mark.parametrize("mode", ["GCM", "CCM", "CBC", "CTR"])
@pytest.mark.parametrize("bits", [128, 256])
def test_aes_roundtrip(mode, bits):
    key = secrets.token_bytes(bits // 8)
    blob = sym.encrypt_bytes(DATA, key, mode)
    assert blob[:4] == b"CSYM" and DATA not in blob
    assert sym.decrypt_bytes(blob, key) == DATA


@pytest.mark.parametrize("mode", ["GCM", "CCM", "CBC", "CTR"])
def test_aes_empty_and_unique_salt_nonce(mode):
    key = secrets.token_bytes(32)
    a, b = sym.encrypt_bytes(b"", key, mode), sym.encrypt_bytes(b"", key, mode)
    assert a != b  # новий salt/nonce щоразу
    assert sym.decrypt_bytes(a, key) == b""


def test_rsa_encrypt_decrypt(rsa_key):
    ct = asym.rsa_encrypt(rsa_key.public_key(), b"short secret")
    assert asym.rsa_decrypt(rsa_key, ct) == b"short secret"


def test_rsa_sign_verify(rsa_key):
    sig = asym.sign_rsa(rsa_key, DATA)
    assert asym.verify_rsa(rsa_key.public_key(), DATA, sig)


@pytest.mark.parametrize("curve", ["P-256", "P-384"])
def test_ecc_encrypt_decrypt(curve):
    k = asym.gen_ecc(curve)
    assert asym.ecc_decrypt(k, asym.ecc_encrypt(k.public_key(), DATA)) == DATA


def test_ecc_sign_verify(ecc_key):
    sig = asym.sign_ecc(ecc_key, DATA)
    assert asym.verify_ecc(ecc_key.public_key(), DATA, sig)


@pytest.mark.parametrize("which", ["rsa", "ecc"])
def test_hybrid_roundtrip(which, rsa_key, ecc_key):
    k = rsa_key if which == "rsa" else ecc_key
    big = secrets.token_bytes(200_000)
    blob = hybrid.encrypt_hybrid(big, k.public_key(), filename="x.bin")
    assert blob[:4] == b"CHYB"
    assert hybrid.decrypt_hybrid(blob, k) == big


def test_pem_roundtrip(tmp_path, rsa_key):
    p = tmp_path / "k.pem"
    asym.save_priv_pem(rsa_key, str(p), PW)
    assert b"ENCRYPTED" in p.read_bytes()
    assert asym.fingerprint(asym.load_priv(str(p), PW)) == asym.fingerprint(rsa_key)


# ============================================================ tamper
@pytest.mark.parametrize("mode", ["GCM", "CCM", "CBC", "CTR"])
@pytest.mark.parametrize("where", ["ciphertext", "tag"])
def test_tamper_ciphertext(mode, where):
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(DATA, key, mode)
    _, prefix, _ = sym.parse_container(blob)
    pos = len(prefix) + 3 if where == "ciphertext" else len(blob) - 1
    with pytest.raises(IntegrityError):
        sym.decrypt_bytes(flip(blob, pos), key)


@pytest.mark.parametrize("mode", ["GCM", "CBC"])
def test_tamper_header_is_authenticated(mode):
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(DATA, key, mode, key_id="abc")
    tampered = blob.replace(b'"key_id":"abc"', b'"key_id":"abd"')
    with pytest.raises(IntegrityError):
        sym.decrypt_bytes(tampered, key)


def test_wrong_key_integrity():
    blob = sym.encrypt_bytes(DATA, secrets.token_bytes(32), "GCM")
    with pytest.raises(IntegrityError):
        sym.decrypt_bytes(blob, secrets.token_bytes(32))


def test_tamper_rsa_signature(rsa_key):
    sig = asym.sign_rsa(rsa_key, DATA)
    with pytest.raises(SignatureInvalid):
        asym.verify_rsa(rsa_key.public_key(), DATA, flip(sig, 10))


def test_tamper_ecc_signature(ecc_key):
    sig = asym.sign_ecc(ecc_key, DATA)
    with pytest.raises(SignatureInvalid):
        asym.verify_ecc(ecc_key.public_key(), DATA, flip(sig, len(sig) - 2))


def test_tamper_signed_data(ecc_key):
    sig = asym.sign_ecc(ecc_key, DATA)
    with pytest.raises(SignatureInvalid):
        asym.verify_ecc(ecc_key.public_key(), DATA + b"!", sig)


def test_tamper_hybrid(rsa_key):
    blob = hybrid.encrypt_hybrid(DATA, rsa_key.public_key())
    with pytest.raises(IntegrityError):
        hybrid.decrypt_hybrid(flip(blob, len(blob) - 5), rsa_key)


def test_hybrid_wrong_recipient(rsa_key):
    blob = hybrid.encrypt_hybrid(DATA, rsa_key.public_key())
    with pytest.raises(WrongRecipient):
        hybrid.decrypt_hybrid(blob, asym.gen_rsa(2048))


def test_bad_pem_password(tmp_path, ecc_key):
    p = tmp_path / "e.pem"
    asym.save_priv_pem(ecc_key, str(p), PW)
    with pytest.raises(BadPassword):
        asym.load_priv(str(p), "wrong-password")


def test_private_key_requires_password(tmp_path, ecc_key):
    with pytest.raises(BadPassword):
        asym.save_priv_pem(ecc_key, str(tmp_path / "x.pem"), "")


@pytest.mark.parametrize("n", [0, 15, 17, 33])
def test_invalid_key_length(n):
    with pytest.raises(InvalidKey):
        sym.encrypt_bytes(DATA, secrets.token_bytes(n), "GCM")


def test_key_size_mismatch_header():
    blob = sym.encrypt_bytes(DATA, secrets.token_bytes(32), "GCM")
    with pytest.raises(InvalidKey):
        sym.decrypt_bytes(blob, secrets.token_bytes(16))


# ============================================================ keystore
@pytest.fixture
def store(tmp_path):
    return sym.SymKeyStore(str(tmp_path / "keystore.json"), PW)


def test_keystore_no_plaintext_keys(store, tmp_path):
    store.new("docs")
    raw = (tmp_path / "keystore.json").read_text()
    assert '"wrapped"' in raw and '"key"' not in raw


def test_keystore_bad_password(store):
    with pytest.raises(BadPassword):
        sym.SymKeyStore(store.path, "nope")


def test_keystore_rotation(store):
    old = store.new("docs")
    blob = sym.encrypt_with_store(store, DATA, "GCM", label="docs")
    new = store.rotate("docs")
    st = {k["key_id"]: k["status"] for k in store.list()}
    assert st[old["key_id"]] == "retired" and st[new["key_id"]] == "active"
    # старі дані розшифровуються retired-ключем, нові шифруються новим
    assert sym.decrypt_with_store(store, blob) == DATA
    assert sym.parse_container(sym.encrypt_with_store(store, DATA, label="docs"))[0]["key_id"] == new["key_id"]
    with pytest.raises(KeyPolicyViolation):
        store.key_for_encrypt(key_id=old["key_id"])


def test_keystore_revoke(store):
    meta = store.new("docs")
    blob = sym.encrypt_with_store(store, DATA, "CTR", label="docs")
    store.revoke(meta["key_id"], "compromised")
    with pytest.raises(KeyPolicyViolation):
        sym.decrypt_with_store(store, blob)


def test_keystore_max_uses(store):
    meta = store.new("docs", max_uses=1)
    sym.encrypt_with_store(store, DATA, label="docs")
    # явний key_id — заборона
    with pytest.raises(KeyPolicyViolation):
        sym.encrypt_with_store(store, DATA, key_id=meta["key_id"])
    # за міткою — авторотація: новий ключ, старий retired
    blob = sym.encrypt_with_store(store, DATA, label="docs")
    kid = sym.parse_container(blob)[0]["key_id"]
    assert kid != meta["key_id"]
    st = {k["key_id"]: k["status"] for k in store.list()}
    assert st[meta["key_id"]] == "retired" and st[kid] == "active"


def test_keystore_persistence(store):
    meta = store.new("docs", bits=128)
    blob = sym.encrypt_with_store(store, DATA, "CCM", label="docs")
    again = sym.SymKeyStore(store.path, PW, create=False)
    assert sym.decrypt_with_store(again, blob) == DATA
    assert again.list()[0]["bits"] == 128 and again.list()[0]["key_id"] == meta["key_id"]


# ============================================================ container
def test_container_bad_magic():
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(DATA, key, "GCM")
    with pytest.raises(InvalidContainer):
        sym.decrypt_bytes(b"XSYM" + blob[4:], key)


def test_container_bad_version():
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(DATA, key, "GCM")
    with pytest.raises(InvalidContainer):
        sym.decrypt_bytes(blob[:4] + b"\x09" + blob[5:], key)


@pytest.mark.parametrize("cut", [3, 10, 40])
def test_container_truncated(cut):
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(DATA, key, "GCM")
    with pytest.raises(InvalidContainer):
        sym.decrypt_bytes(blob[:cut], key)


def test_container_truncated_tag():
    key = secrets.token_bytes(32)
    blob = sym.encrypt_bytes(b"", key, "CBC")  # 16 байт ct + 32 байти тегу
    _, prefix, _ = sym.parse_container(blob)
    with pytest.raises(InvalidContainer):
        sym.decrypt_bytes(blob[:len(prefix) + 10], key)


def test_hybrid_container_bad_magic_and_truncated(rsa_key):
    blob = hybrid.encrypt_hybrid(DATA, rsa_key.public_key())
    with pytest.raises(InvalidContainer):
        hybrid.decrypt_hybrid(b"XHYB" + blob[4:], rsa_key)
    with pytest.raises(InvalidContainer):
        hybrid.decrypt_hybrid(blob[:60], rsa_key)


# ============================================================ CLI (end-to-end)
def run_cli(*argv):
    return cli.main([str(a) for a in argv])


def test_cli_sym_flow(tmp_path, capsys):
    ks, src = tmp_path / "ks.json", tmp_path / "in.txt"
    src.write_bytes(DATA)
    base = ["--keystore", ks]
    assert run_cli(*base, "sym", "new", "--label", "docs", "--ks-password", PW) == 0
    for mode in ("gcm", "ccm", "cbc", "ctr"):
        enc, dec = tmp_path / f"{mode}.bin", tmp_path / f"{mode}.out"
        assert run_cli(*base, "sym", "enc", "--label", "docs", "--ks-password", PW,
                       "--in", src, "--out", enc, "--mode", mode) == 0
        assert run_cli(*base, "sym", "dec", "--ks-password", PW, "--in", enc, "--out", dec) == 0
        assert dec.read_bytes() == DATA
    assert run_cli(*base, "sym", "list", "--ks-password", PW) == 0
    assert "docs" in capsys.readouterr().out
    # пошкоджений контейнер → код IntegrityError
    enc = tmp_path / "gcm.bin"
    enc.write_bytes(flip(enc.read_bytes(), len(enc.read_bytes()) - 1))
    assert run_cli(*base, "sym", "dec", "--ks-password", PW, "--in", enc, "--out", tmp_path / "x") == IntegrityError.code
    assert "integrity_failed" in capsys.readouterr().err


@pytest.mark.parametrize("kind,extra", [("rsa", ["--bits", "2048"]), ("ecc", ["--curve", "p384"])])
def test_cli_asym_and_hybrid(tmp_path, kind, extra):
    priv, pub, src = tmp_path / "k.pem", tmp_path / "k.pub.pem", tmp_path / "m.txt"
    src.write_bytes(b"short message")
    assert run_cli(kind, "gen", "--priv", priv, "--pub", pub, "--password", PW, *extra) == 0
    assert run_cli(kind, "enc", "--pub", pub, "--in", src, "--out", tmp_path / "c") == 0
    assert run_cli(kind, "dec", "--priv", priv, "--password", PW, "--in", tmp_path / "c", "--out", tmp_path / "p") == 0
    assert (tmp_path / "p").read_bytes() == b"short message"
    assert run_cli(kind, "sign", "--priv", priv, "--password", PW, "--in", src, "--sig", tmp_path / "s") == 0
    assert run_cli(kind, "verify", "--pub", pub, "--in", src, "--sig", tmp_path / "s") == 0
    src.write_bytes(b"short messagE")
    assert run_cli(kind, "verify", "--pub", pub, "--in", src, "--sig", tmp_path / "s") == SignatureInvalid.code
    assert run_cli("hybrid", "enc", "--pub", pub, "--in", src, "--out", tmp_path / "h", "--algo", kind) == 0
    assert run_cli("hybrid", "dec", "--priv", priv, "--password", PW, "--in", tmp_path / "h",
                   "--out", tmp_path / "hp") == 0
    assert (tmp_path / "hp").read_bytes() == src.read_bytes()
    assert run_cli(kind, "dec", "--priv", priv, "--password", "bad", "--in", tmp_path / "c",
                   "--out", tmp_path / "p") == BadPassword.code


def test_logs_do_not_contain_secrets(tmp_path, monkeypatch):
    import logging
    import logger as lg
    path = tmp_path / "log.jsonl"
    log = lg.get_logger(str(path))
    lg.log_event("t", logger=log, password=PW, key=b"k" * 32, nonce="00ff", mode="GCM")
    for h in log.handlers:
        h.flush()
    rec = json.loads(path.read_text().splitlines()[-1])
    assert rec["password"] == rec["key"] == rec["nonce"] == "***" and rec["mode"] == "GCM"
    assert PW not in path.read_text()
