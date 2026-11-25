#!/usr/bin/env python3
"""Бенчмарк crypto-suite.

* AES (GCM, CBC-HMAC, CTR-HMAC, ключ 256 біт): encrypt+decrypt файлів 1KB/100KB/1MB/10MB
  (тимчасові файли з secrets.token_bytes; час включає читання/запис файлу).
* Генерація ключів: RSA-2048/3072/4096, ECC-P256/P384.
Результат: outputs/bench.csv та outputs/bench.md. Використовується медіана кількох повторів.
"""
import csv
import os
import platform
import secrets
import statistics
import tempfile
import time

import cryptography

import asym
import sym
from logger import log_event

SIZES = {"1KB": 1024, "100KB": 100 * 1024, "1MB": 1024 * 1024, "10MB": 10 * 1024 * 1024}
AES_MODES = [("GCM", "AES-256-GCM"), ("CBC", "AES-256-CBC-HMAC"), ("CTR", "AES-256-CTR-HMAC")]
KEYGEN = [("RSA-2048", lambda: asym.gen_rsa(2048)), ("RSA-3072", lambda: asym.gen_rsa(3072)),
          ("RSA-4096", lambda: asym.gen_rsa(4096)), ("ECC-P256", lambda: asym.gen_ecc("P-256")),
          ("ECC-P384", lambda: asym.gen_ecc("P-384"))]
KEYGEN_REPEATS = {"RSA-2048": 5, "RSA-3072": 5, "RSA-4096": 5, "ECC-P256": 20, "ECC-P384": 20}
HEADER = ["size", "algorithm", "enc_s", "dec_s", "enc_mb_s", "dec_mb_s"]


def parse_sizes(spec: str) -> dict:
    out = {}
    for name in spec.split(","):
        name = name.strip().upper()
        if name not in SIZES:
            raise ValueError(f"Невідомий розмір {name}; доступні: {', '.join(SIZES)}")
        out[name] = SIZES[name]
    return out


def _repeats(n: int) -> int:
    return 7 if n <= 100 * 1024 else (3 if n <= 1024 * 1024 else 2)


def _time_file_op(fn, src, dst) -> float:
    t0 = time.perf_counter()
    with open(src, "rb") as f:
        out = fn(f.read())
    with open(dst, "wb") as f:
        f.write(out)
    return time.perf_counter() - t0


def bench_aes(sizes: dict, tmpdir: str) -> list:
    rows = []
    key = secrets.token_bytes(32)
    for size_name, n in sizes.items():
        plain = os.path.join(tmpdir, f"plain_{size_name}.bin")
        with open(plain, "wb") as f:
            f.write(secrets.token_bytes(n))
        enc_path, dec_path = plain + ".enc", plain + ".dec"
        for mode, title in AES_MODES:
            enc_t, dec_t = [], []
            for _ in range(_repeats(n)):
                enc_t.append(_time_file_op(lambda d: sym.encrypt_bytes(d, key, mode, "bench"), plain, enc_path))
                dec_t.append(_time_file_op(lambda b: sym.decrypt_bytes(b, key), enc_path, dec_path))
            with open(plain, "rb") as a, open(dec_path, "rb") as b:
                assert a.read() == b.read(), f"roundtrip failed: {title} {size_name}"
            e, d = statistics.median(enc_t), statistics.median(dec_t)
            mb = n / (1024 * 1024)
            rows.append([size_name, title, e, d, mb / e, mb / d])
            print(f"  {size_name:>6} {title:<18} enc {e:.5f} с  dec {d:.5f} с")
    return rows


def bench_keygen() -> list:
    rows = []
    for name, fn in KEYGEN:
        times = []
        for _ in range(KEYGEN_REPEATS[name]):
            t0 = time.perf_counter()
            fn()
            times.append(time.perf_counter() - t0)
        t = statistics.median(times)
        rows.append(["N/A", f"{name} keygen", t, None, None, None])
        print(f"  keygen {name:<10} {t:.5f} с")
    return rows


def _f(v, nd=6):
    return "N/A" if v is None else f"{v:.{nd}f}"


def write_outputs(rows: list, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "bench.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for r in rows:
            w.writerow([r[0], r[1]] + ["N/A" if v is None else f"{v:.6f}" for v in r[2:]])
    lines = [
        "# Результати бенчмарку crypto-suite", "",
        f"Середовище: Python {platform.python_version()}, cryptography {cryptography.__version__}, "
        f"{platform.system()} {platform.machine()}, {time.strftime('%Y-%m-%d %H:%M')}.",
        "Час — медіана кількох повторів; для AES включає читання та запис файлу. Ключ AES — 256 біт.", "",
        "| Розмір | Режим/Алгоритм | Enc (с) | Dec (с) | Enc МБ/с | Dec МБ/с |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r[0]} | {r[1]} | {_f(r[2])} | {_f(r[3])} | {_f(r[4], 2)} | {_f(r[5], 2)} |")
    md = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "bench.md"), "w", encoding="utf-8") as f:
        f.write(md)
    return md


def run(sizes: dict = None, out_dir: str = "outputs") -> str:
    sizes = sizes or SIZES
    print("AES encrypt/decrypt:")
    with tempfile.TemporaryDirectory(prefix="csbench_") as tmp:
        rows = bench_aes(sizes, tmp)
    print("Генерація ключів:")
    rows += bench_keygen()
    md = write_outputs(rows, out_dir)
    log_event("bench.run", sizes=list(sizes), rows=len(rows), out_dir=out_dir)
    return md


if __name__ == "__main__":
    print(run())
