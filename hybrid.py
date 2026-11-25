"""Гібридне шифрування: випадковий AES-256 ключ (GCM) + обгортання ключа публічним ключем отримувача.

Пакет CHYB v1:
    MAGIC 'CHYB' (4B) | VERSION (1B) | ALGID (1B) | HDRLEN (2B) | JSON-заголовок |
    WRAPPED_KEY_LEN (2B) | wrapped_key | AES-256-GCM шифртекст+тег (16B)

ALGID: 1 = RSA-OAEP-SHA256, 2 = ECIES (ECDH + HKDF-SHA256 + AES-GCM).
AAD для AES-GCM = усе від MAGIC до кінця wrapped_key (заголовок і обгорнутий ключ захищені тегом).
"""
import json
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import asym
from errors import IntegrityError, InvalidContainer, InvalidKey, WrongRecipient

MAGIC = b"CHYB"
VERSION = 1
ALG_RSA, ALG_ECC = 1, 2
ALG_NAMES = {ALG_RSA: "RSA-OAEP-SHA256", ALG_ECC: "ECIES-HKDF-SHA256"}


def encrypt_hybrid(data: bytes, recipient_pub, filename: str = None) -> bytes:
    if isinstance(recipient_pub, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        recipient_pub = recipient_pub.public_key()
    if isinstance(recipient_pub, rsa.RSAPublicKey):
        algid = ALG_RSA
    elif isinstance(recipient_pub, ec.EllipticCurvePublicKey):
        algid = ALG_ECC
    else:
        raise InvalidKey("Публічний ключ отримувача має бути RSA або ECC")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    wrapped = asym.rsa_encrypt(recipient_pub, aes_key) if algid == ALG_RSA else asym.ecc_encrypt(recipient_pub, aes_key)
    header = {"v": VERSION, "wrap": ALG_NAMES[algid], "recipient": asym.describe(recipient_pub),
              "fp": asym.fingerprint(recipient_pub), "cipher": "AES-256-GCM", "nonce": nonce.hex()}
    if filename:
        header["name"] = filename
    hblob = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    aad = (MAGIC + bytes([VERSION, algid]) + struct.pack(">H", len(hblob)) + hblob
           + struct.pack(">H", len(wrapped)) + wrapped)
    return aad + AESGCM(aes_key).encrypt(nonce, data, aad)


def parse_hybrid(blob: bytes):
    """Повертає (algid, header, wrapped_key, aad, body)."""
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise InvalidContainer("Не CHYB-пакет (невірний MAGIC)")
    if blob[4] != VERSION:
        raise InvalidContainer(f"Непідтримувана версія CHYB: {blob[4]}")
    algid = blob[5]
    if algid not in ALG_NAMES:
        raise InvalidContainer(f"Невідомий ALGID: {algid}")
    (hl,) = struct.unpack(">H", blob[6:8])
    off = 8 + hl
    if len(blob) < off + 2:
        raise InvalidContainer("CHYB-пакет обрізаний (заголовок)")
    try:
        header = json.loads(blob[8:off].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidContainer("Заголовок CHYB не є валідним JSON")
    (wl,) = struct.unpack(">H", blob[off:off + 2])
    wrapped = blob[off + 2:off + 2 + wl]
    if len(wrapped) != wl or len(blob) < off + 2 + wl + 16:
        raise InvalidContainer("CHYB-пакет обрізаний (обгорнутий ключ/тег)")
    return algid, header, wrapped, blob[:off + 2 + wl], blob[off + 2 + wl:]


def decrypt_hybrid(blob: bytes, recipient_priv) -> bytes:
    algid, header, wrapped, aad, body = parse_hybrid(blob)
    want = rsa.RSAPrivateKey if algid == ALG_RSA else ec.EllipticCurvePrivateKey
    if not isinstance(recipient_priv, want):
        raise InvalidKey(f"Пакет обгорнуто {ALG_NAMES[algid]} — потрібен відповідний приватний ключ")
    if header.get("fp") != asym.fingerprint(recipient_priv):
        raise WrongRecipient(f"Пакет призначено для ключа {header.get('fp')}, а надано {asym.fingerprint(recipient_priv)}")
    aes_key = asym.rsa_decrypt(recipient_priv, wrapped) if algid == ALG_RSA else asym.ecc_decrypt(recipient_priv, wrapped)
    if len(aes_key) != 32:
        raise IntegrityError("Розгорнутий ключ має неправильну довжину")
    try:
        return AESGCM(aes_key).decrypt(bytes.fromhex(header["nonce"]), body, aad)
    except (InvalidTag, ValueError, KeyError):
        raise IntegrityError()
