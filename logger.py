"""JSON-логер (JSONL) з маскуванням чутливих полів.

Кожен рядок файлу logs/crypto.jsonl — окремий JSON-об'єкт:
{"ts": "...", "level": "INFO", "event": "sym.enc", "status": "ok", ...}
Секрети (ключі, паролі, nonce/IV, теги, відкритий текст) ніколи не записуються.
"""
import json
import logging
import os
import time

SENSITIVE = {"key", "aes_key", "password", "passphrase", "secret", "nonce", "iv",
             "tag", "mac_key", "enc_key", "plaintext", "data", "wrapped_key", "salt"}

DEFAULT_LOG = os.environ.get("CRYPTO_SUITE_LOG", os.path.join("logs", "crypto.jsonl"))


def mask(obj):
    """Рекурсивно замінює значення чутливих полів на '***'."""
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SENSITIVE else mask(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return f"<{len(obj)} bytes>"
    return obj


class JSONFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(mask(fields))
        return json.dumps(payload, ensure_ascii=False)


def get_logger(path: str = None) -> logging.Logger:
    path = path or DEFAULT_LOG
    logger = logging.getLogger("crypto-suite:" + os.path.abspath(path))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
    return logger


def log_event(event: str, status: str = "ok", level: int = logging.INFO, logger=None, **fields):
    """Зручна обгортка: log_event('sym.enc', mode='GCM', sec=0.01)."""
    (logger or get_logger()).log(level, event, extra={"fields": {"status": status, **fields}})
