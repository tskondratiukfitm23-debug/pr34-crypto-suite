"""Симетричне шифрування: AES-GCM, AES-CCM, AES-CBC+HMAC-SHA256, AES-CTR+HMAC-SHA256.

Контейнер CSYM v1:
    MAGIC 'CSYM' (4B) | VERSION (1B) | HDRLEN (2B, big-endian) | JSON-заголовок | шифртекст [| тег]

* GCM/CCM: AAD = MAGIC|VERSION|HDRLEN|JSON-заголовок, тег (16B) додається в кінці.
* CBC/CTR: encrypt-then-MAC; тег = HMAC-SHA256(mac_key, MAGIC..заголовок||шифртекст) (32B) у кінці.
  При розшифруванні HMAC перевіряється ДО будь-якої дешифрації (verify-then-decrypt).
* Ключ файлу = HKDF-SHA256(master_key, salt=випадковий 16B, info=...) — унікальний для кожного файлу.

SymKeyStore — сховище ключів з паролем: KEK = scrypt(пароль, salt), кожен ключ зберігається
обгорнутим AESGCM(KEK) (AAD = key_id). Політика: uses/max_uses, expires, статус active/retired/revoked.
"""
import hmac as _hmac
import json
import os
import secrets
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from errors import (BadPassword, InputError, IntegrityError, InvalidContainer,
                    InvalidKey, KeyNotFound, KeyPolicyViolation)
from logger import log_event

MAGIC = b"CSYM"
VERSION = 1
PREFIX_LEN = 4 + 1 + 2
MODES = ("GCM", "CCM", "CBC", "CTR")
VALID_BITS = (128, 192, 256)
TAG_LEN = {"GCM": 16, "CCM": 16, "CBC": 32, "CTR": 32}
MAX_HDR = 4096


# --------------------------------------------------------------------------- helpers
def _check_key(key: bytes) -> int:
    if not isinstance(key, (bytes, bytearray)) or len(key) * 8 not in VALID_BITS:
        n = len(key) * 8 if isinstance(key, (bytes, bytearray)) else "?"
        raise InvalidKey(f"Неправильна довжина ключа AES: {n} біт (дозволено 128/192/256)")
    return len(key) * 8


def _norm_mode(mode: str) -> str:
    m = (mode or "").upper().replace("-HMAC", "")
    if m not in MODES:
        raise InputError(f"Невідомий режим '{mode}'. Доступні: gcm, ccm, cbc, ctr")
    return m


def _derive(master: bytes, salt: bytes, mode: str, key_id: str, bits: int):
    """HKDF-SHA256 → (enc_key, mac_key|None)."""
    enc_len = bits // 8
    mac_len = 32 if mode in ("CBC", "CTR") else 0
    okm = HKDF(algorithm=hashes.SHA256(), length=enc_len + mac_len, salt=salt,
               info=f"CSYM-v1|{mode}|{key_id}".encode()).derive(master)
    return okm[:enc_len], (okm[enc_len:] if mac_len else None)


def _pack_prefix(header: dict) -> bytes:
    blob = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return MAGIC + bytes([VERSION]) + struct.pack(">H", len(blob)) + blob


def parse_container(blob: bytes):
    """Повертає (header: dict, prefix: bytes, body: bytes). Кидає InvalidContainer."""
    if len(blob) < PREFIX_LEN or blob[:4] != MAGIC:
        raise InvalidContainer("Не CSYM-контейнер (невірний MAGIC)")
    if blob[4] != VERSION:
        raise InvalidContainer(f"Непідтримувана версія CSYM: {blob[4]}")
    (hl,) = struct.unpack(">H", blob[5:7])
    if hl == 0 or hl > MAX_HDR or len(blob) < PREFIX_LEN + hl:
        raise InvalidContainer("Пошкоджена довжина заголовка CSYM")
    try:
        header = json.loads(blob[PREFIX_LEN:PREFIX_LEN + hl].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidContainer("Заголовок CSYM не є валідним JSON")
    for f in ("v", "alg", "mode", "bits", "salt", "kdf", "key_id"):
        if f not in header:
            raise InvalidContainer(f"У заголовку CSYM бракує поля '{f}'")
    if header["mode"] not in MODES or header["bits"] not in VALID_BITS:
        raise InvalidContainer("Непідтримуваний режим/довжина ключа у заголовку")
    return header, blob[:PREFIX_LEN + hl], blob[PREFIX_LEN + hl:]


# --------------------------------------------------------------------------- core API
def encrypt_bytes(data: bytes, master_key: bytes, mode: str = "GCM", key_id: str = "raw") -> bytes:
    """Шифрує data і повертає CSYM-контейнер."""
    bits = _check_key(master_key)
    mode = _norm_mode(mode)
    salt = secrets.token_bytes(16)
    enc_key, mac_key = _derive(master_key, salt, mode, key_id, bits)
    header = {"v": VERSION, "alg": f"AES-{bits}-{mode}" + ("-HMAC-SHA256" if mac_key else ""),
              "mode": mode, "bits": bits, "salt": salt.hex(), "kdf": "HKDF-SHA256", "key_id": key_id}

    if mode == "GCM":
        nonce = secrets.token_bytes(12)
        header["nonce"] = nonce.hex()
        prefix = _pack_prefix(header)
        return prefix + AESGCM(enc_key).encrypt(nonce, data, prefix)
    if mode == "CCM":
        nonce = secrets.token_bytes(13)
        header["nonce"] = nonce.hex()
        prefix = _pack_prefix(header)
        return prefix + AESCCM(enc_key, tag_length=16).encrypt(nonce, data, prefix)

    if mode == "CBC":
        iv = secrets.token_bytes(16)
        header["iv"] = iv.hex()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
    else:  # CTR
        nonce = secrets.token_bytes(16)
        header["nonce"] = nonce.hex()
        enc = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
        ct = enc.update(data) + enc.finalize()
    prefix = _pack_prefix(header)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(prefix)
    h.update(ct)
    return prefix + ct + h.finalize()  # encrypt-then-MAC


def decrypt_bytes(blob: bytes, master_key: bytes) -> bytes:
    """Розшифровує CSYM-контейнер. IntegrityError, якщо тег/HMAC не збігся."""
    header, prefix, body = parse_container(blob)
    bits = _check_key(master_key)
    if bits != header["bits"]:
        raise InvalidKey(f"Ключ {bits} біт не відповідає заголовку ({header['bits']} біт)")
    mode = header["mode"]
    try:
        salt = bytes.fromhex(header["salt"])
        iv_or_nonce = bytes.fromhex(header.get("nonce") or header.get("iv") or "")
    except ValueError:
        raise InvalidContainer("Невалідний hex у заголовку")
    enc_key, mac_key = _derive(master_key, salt, mode, header["key_id"], bits)
    tlen = TAG_LEN[mode]
    if len(body) < tlen:
        raise InvalidContainer("Контейнер обрізаний: немає тегу")

    if mode in ("GCM", "CCM"):
        try:
            aead = AESGCM(enc_key) if mode == "GCM" else AESCCM(enc_key, tag_length=16)
            return aead.decrypt(iv_or_nonce, body, prefix)
        except (InvalidTag, ValueError):
            raise IntegrityError()

    ct, tag = body[:-tlen], body[-tlen:]
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(prefix)
    h.update(ct)
    if not _hmac.compare_digest(h.finalize(), tag):  # verify-then-decrypt
        raise IntegrityError()
    if mode == "CBC":
        dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv_or_nonce)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise IntegrityError("Невалідний padding після перевірки HMAC")
    dec = Cipher(algorithms.AES(enc_key), modes.CTR(iv_or_nonce)).decryptor()
    return dec.update(ct) + dec.finalize()


# --------------------------------------------------------------------------- key store
class SymKeyStore:
    """Сховище симетричних ключів під паролем (scrypt KEK + AES-GCM key wrapping)."""

    SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
    CHECK = b"crypto-suite keystore v1"

    def __init__(self, path: str, password: str, create: bool = True):
        if not password:
            raise BadPassword("Пароль до сховища ключів не задано")
        self.path = path
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
            except (OSError, json.JSONDecodeError):
                raise InputError(f"Не вдалося прочитати сховище ключів: {path}")
            self.kek = self._kek(password, bytes.fromhex(self.db["kdf"]["salt"]), self.db["kdf"])
            try:
                v = bytes.fromhex(self.db["check"])
                if AESGCM(self.kek).decrypt(v[:12], v[12:], b"check") != self.CHECK:
                    raise InvalidTag
            except InvalidTag:
                log_event("keystore.open", status="fail", reason="bad_password")
                raise BadPassword("Неправильний пароль до сховища ключів")
        elif create:
            salt = secrets.token_bytes(16)
            kdf = {"name": "scrypt", "salt": salt.hex(), "n": self.SCRYPT_N, "r": self.SCRYPT_R, "p": self.SCRYPT_P}
            self.kek = self._kek(password, salt, kdf)
            n = secrets.token_bytes(12)
            self.db = {"version": 1, "kdf": kdf,
                       "check": (n + AESGCM(self.kek).encrypt(n, self.CHECK, b"check")).hex(), "keys": []}
            self.save()
            log_event("keystore.create", path=path)
        else:
            raise KeyNotFound(f"Сховище ключів не знайдено: {path}")

    @staticmethod
    def _kek(password: str, salt: bytes, kdf: dict) -> bytes:
        return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password.encode("utf-8"))

    def save(self):
        tmp = self.path + ".part"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- key lifecycle
    def new(self, label: str = "default", bits: int = 256, max_uses: int = 1000, days: int = 90) -> dict:
        if bits not in VALID_BITS:
            raise InvalidKey(f"Неправильна довжина ключа: {bits} (дозволено 128/192/256)")
        key = secrets.token_bytes(bits // 8)
        key_id = secrets.token_hex(8)
        n = secrets.token_bytes(12)
        now = int(time.time())
        meta = {"key_id": key_id, "label": label, "bits": bits, "created": now,
                "expires": now + int(days * 86400) if days else None, "max_uses": max_uses,
                "uses": 0, "status": "active",
                "wrapped": (n + AESGCM(self.kek).encrypt(n, key, key_id.encode())).hex()}
        self.db["keys"].append(meta)
        self.save()
        log_event("keystore.new", key_id=key_id, label=label, bits=bits, max_uses=max_uses, days=days)
        return self._public(meta)

    def list(self) -> list:
        return [self._public(k) for k in self.db["keys"]]

    def _find(self, key_id: str) -> dict:
        for k in self.db["keys"]:
            if k["key_id"] == key_id:
                return k
        raise KeyNotFound(f"Ключ '{key_id}' не знайдено у сховищі")

    def _unwrap(self, meta: dict) -> bytes:
        w = bytes.fromhex(meta["wrapped"])
        try:
            return AESGCM(self.kek).decrypt(w[:12], w[12:], meta["key_id"].encode())
        except InvalidTag:
            raise IntegrityError(f"Обгорнутий ключ {meta['key_id']} пошкоджено")

    @staticmethod
    def _public(meta: dict) -> dict:
        return {k: v for k, v in meta.items() if k != "wrapped"}

    def rotate(self, label: str = "default", bits: int = None, max_uses: int = None, days: int = None) -> dict:
        """Переводить активні ключі мітки у retired і створює новий активний."""
        old = [k for k in self.db["keys"] if k["label"] == label and k["status"] == "active"]
        for k in old:
            k["status"] = "retired"
        ref = old[-1] if old else {}
        meta = self.new(label, bits or ref.get("bits", 256),
                        max_uses if max_uses is not None else ref.get("max_uses", 1000),
                        days if days is not None else 90)
        log_event("keystore.rotate", label=label, retired=[k["key_id"] for k in old], new=meta["key_id"])
        return meta

    def revoke(self, key_id: str, reason: str = "unspecified") -> dict:
        k = self._find(key_id)
        k["status"] = "revoked"
        k["revoked_reason"] = reason
        self.save()
        log_event("keystore.revoke", key_id=key_id, reason=reason)
        return self._public(k)

    def _expired_or_exhausted(self, k: dict) -> str:
        if k.get("expires") and time.time() >= k["expires"]:
            return "expired"
        if k.get("max_uses") and k["uses"] >= k["max_uses"]:
            return "max_uses"
        return ""

    def key_for_encrypt(self, label: str = "default", key_id: str = None):
        """Повертає (key_id, key) і збільшує лічильник uses. Автоматична ротація за uses/expires."""
        if key_id:
            k = self._find(key_id)
            if k["status"] != "active":
                raise KeyPolicyViolation(f"Ключ {key_id} має статус '{k['status']}' — шифрування заборонено")
            why = self._expired_or_exhausted(k)
            if why:
                raise KeyPolicyViolation(f"Ключ {key_id} недійсний для шифрування ({why}); виконайте rotate")
        else:
            act = [k for k in self.db["keys"] if k["label"] == label and k["status"] == "active"]
            if not act:
                raise KeyNotFound(f"Немає активного ключа з міткою '{label}' (виконайте: sym new)")
            k = act[-1]
            why = self._expired_or_exhausted(k)
            if why:
                log_event("keystore.auto_rotate", key_id=k["key_id"], reason=why)
                k = self._find(self.rotate(label)["key_id"])
        k["uses"] += 1
        self.save()
        return k["key_id"], self._unwrap(k)

    def key_for_decrypt(self, key_id: str) -> bytes:
        k = self._find(key_id)
        if k["status"] == "revoked":
            log_event("keystore.decrypt_denied", status="fail", key_id=key_id, reason="revoked")
            raise KeyPolicyViolation(f"Ключ {key_id} відкликано — розшифрування заборонено")
        return self._unwrap(k)


# --------------------------------------------------------------------------- store-level helpers
def encrypt_with_store(store: SymKeyStore, data: bytes, mode: str = "GCM", label: str = "default",
                       key_id: str = None) -> bytes:
    kid, key = store.key_for_encrypt(label=label, key_id=key_id)
    return encrypt_bytes(data, key, mode, kid)


def decrypt_with_store(store: SymKeyStore, blob: bytes) -> bytes:
    header, _, _ = parse_container(blob)
    return decrypt_bytes(blob, store.key_for_decrypt(header["key_id"]))
