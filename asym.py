"""Асиметрична криптографія: RSA (OAEP/PSS, SHA-256) та ECC P-256/P-384 (ECIES-HKDF, ECDSA SHA-256).

Приватні ключі зберігаються лише у зашифрованому PKCS#8 PEM (BestAvailableEncryption →
AES-256-CBC + PBKDF2/scrypt у бекенді OpenSSL). Публічні — незашифрований SubjectPublicKeyInfo PEM.
"""
import hashlib
import os
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from errors import BadPassword, InputError, IntegrityError, InvalidKey, SignatureInvalid
from logger import log_event

RSA_BITS = (2048, 3072, 4096)
CURVES = {"P-256": ec.SECP256R1, "P256": ec.SECP256R1, "P-384": ec.SECP384R1, "P384": ec.SECP384R1}
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
ECIES_INFO = b"crypto-suite ECIES-HKDF-SHA256 v1"


# --------------------------------------------------------------------------- keygen / PEM
def gen_rsa(bits: int = 3072) -> rsa.RSAPrivateKey:
    if bits not in RSA_BITS:
        raise InvalidKey(f"Непідтримувана довжина RSA: {bits} (дозволено 2048/3072/4096)")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def gen_ecc(curve: str = "P-256") -> ec.EllipticCurvePrivateKey:
    c = CURVES.get(curve.upper())
    if c is None:
        raise InvalidKey(f"Непідтримувана крива: {curve} (дозволено P-256/P-384)")
    return ec.generate_private_key(c())


def save_priv_pem(key, path: str, password: str):
    if not password:
        raise BadPassword("Приватний ключ дозволено зберігати лише під паролем")
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password.encode("utf-8")))
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def save_pub_pem(key, path: str):
    pub = key.public_key() if hasattr(key, "private_bytes") else key
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise InputError(f"Не вдалося прочитати файл ключа '{path}': {e.strerror}")


def load_priv(path: str, password: str):
    data = _read(path)
    try:
        return serialization.load_pem_private_key(data, password.encode("utf-8") if password else None)
    except TypeError:
        raise BadPassword("Приватний ключ зашифровано — потрібен пароль")
    except ValueError as e:
        if b"ENCRYPTED" in data:
            raise BadPassword("Неправильний пароль до приватного ключа")
        raise InvalidKey(f"Невалідний PEM приватного ключа: {e}")
    except UnsupportedAlgorithm as e:
        raise InvalidKey(f"Непідтримуваний алгоритм ключа: {e}")


def load_pub(path: str):
    try:
        return serialization.load_pem_public_key(_read(path))
    except (ValueError, UnsupportedAlgorithm) as e:
        raise InvalidKey(f"Невалідний PEM публічного ключа: {e}")


def fingerprint(key) -> str:
    """SHA-256 від DER(SubjectPublicKeyInfo), перші 16 байт у hex."""
    pub = key.public_key() if hasattr(key, "private_bytes") else key
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:32]


def _need(key, kind, private: bool):
    if kind == "rsa":
        ok = isinstance(key, rsa.RSAPrivateKey if private else (rsa.RSAPublicKey, rsa.RSAPrivateKey))
    else:
        ok = isinstance(key, ec.EllipticCurvePrivateKey if private else (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey))
    if not ok:
        raise InvalidKey(f"Очікувався {'приватний' if private else 'публічний'} ключ {kind.upper()}")
    if not private and hasattr(key, "private_bytes"):
        return key.public_key()
    return key


# --------------------------------------------------------------------------- RSA
def rsa_encrypt(pub, data: bytes) -> bytes:
    pub = _need(pub, "rsa", False)
    max_len = pub.key_size // 8 - 2 * 32 - 2
    if len(data) > max_len:
        raise InputError(f"RSA-OAEP може зашифрувати максимум {max_len} байт; для більших даних — hybrid")
    return pub.encrypt(data, OAEP)


def rsa_decrypt(priv, ct: bytes) -> bytes:
    priv = _need(priv, "rsa", True)
    try:
        return priv.decrypt(ct, OAEP)
    except ValueError:
        raise IntegrityError("RSA-OAEP: розшифрування не вдалося (пошкоджені дані або чужий ключ)")


def sign_rsa(priv, data: bytes) -> bytes:
    return _need(priv, "rsa", True).sign(data, PSS, hashes.SHA256())


def verify_rsa(pub, data: bytes, sig: bytes) -> bool:
    try:
        _need(pub, "rsa", False).verify(sig, data, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        raise SignatureInvalid()


# --------------------------------------------------------------------------- ECC
def _ecies_key(shared: bytes, eph_bytes: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_bytes, info=ECIES_INFO).derive(shared)


def ecc_encrypt(pub, data: bytes) -> bytes:
    """ECIES: ефемерний ECDH → HKDF-SHA256 → AES-256-GCM. Вихід: EPH_PUB (uncompressed) | NONCE 12 | CT+TAG."""
    pub = _need(pub, "ecc", False)
    eph = ec.generate_private_key(pub.curve)
    eph_bytes = eph.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
    key = _ecies_key(eph.exchange(ec.ECDH(), pub), eph_bytes)
    nonce = secrets.token_bytes(12)
    return eph_bytes + nonce + AESGCM(key).encrypt(nonce, data, eph_bytes)


def ecc_decrypt(priv, blob: bytes) -> bytes:
    priv = _need(priv, "ecc", True)
    plen = 1 + 2 * ((priv.curve.key_size + 7) // 8)
    if len(blob) < plen + 12 + 16:
        raise IntegrityError("ECIES-пакет занадто короткий")
    eph_bytes, nonce, ct = blob[:plen], blob[plen:plen + 12], blob[plen + 12:]
    try:
        eph = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph_bytes)
        key = _ecies_key(priv.exchange(ec.ECDH(), eph), eph_bytes)
        return AESGCM(key).decrypt(nonce, ct, eph_bytes)
    except (InvalidTag, ValueError):
        raise IntegrityError("ECIES: перевірка тегу не пройдена (пошкоджені дані або чужий ключ)")


def sign_ecc(priv, data: bytes) -> bytes:
    return _need(priv, "ecc", True).sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecc(pub, data: bytes, sig: bytes) -> bool:
    try:
        _need(pub, "ecc", False).verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        raise SignatureInvalid()


def describe(key) -> str:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return f"RSA-{key.key_size}"
    return f"ECC-{key.curve.name}"


def log_keygen(kind: str, param, fp: str):
    log_event(f"{kind}.gen", param=str(param), fingerprint=fp)
