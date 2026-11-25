#!/usr/bin/env python3
"""crypto-suite CLI: симетричне (AES), асиметричне (RSA/ECC) та гібридне шифрування.

Приклади:
    python cli.py sym new --label docs --ks-password 'S3cret!'
    python cli.py sym enc --label docs --ks-password 'S3cret!' --in data/sample.txt --out outputs/s.bin
    python cli.py rsa gen --priv keys/rsa.pem --pub keys/rsa.pub.pem --password 'P@ss'
    python cli.py hybrid enc --pub keys/rsa.pub.pem --in data/sample.txt --out outputs/h.bin
    python cli.py --interactive
"""
import argparse
import getpass
import logging
import os
import sys
import time
from datetime import datetime, timezone

import asym
import hybrid
import sym
from errors import CryptoSuiteError, InputError, KeyPolicyViolation
from logger import log_event

DEFAULT_KS = os.environ.get("CRYPTO_SUITE_KEYSTORE", "keystore.json")


# --------------------------------------------------------------------------- I/O helpers
def read_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise InputError(f"Не вдалося прочитати '{path}': {e.strerror}")


def write_file(path: str, data: bytes):
    """Атомарний запис: спочатку *.part, потім os.replace (без напівзаписаних файлів)."""
    d = os.path.dirname(path)
    try:
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".part"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError as e:
        raise InputError(f"Не вдалося записати '{path}': {e.strerror}")


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if ts else "—"


def _store(args, create=True):
    return sym.SymKeyStore(args.keystore, args.ks_password, create=create)


# --------------------------------------------------------------------------- sym
def cmd_sym(args):
    if args.action == "new":
        meta = _store(args).new(args.label, args.bits, args.max_uses, args.days)
        print(f"Створено ключ: key_id={meta['key_id']} label={meta['label']} bits={meta['bits']}")
        return {"key_id": meta["key_id"], "label": args.label, "bits": args.bits}
    if args.action == "list":
        keys = _store(args, create=False).list()
        row = "{:<18} {:<12} {:>4}  {:<8} {:>11}  {:<10}"
        print(row.format("KEY_ID", "LABEL", "BITS", "STATUS", "USES/MAX", "EXPIRES"))
        print("-" * 70)
        for k in keys:
            print(row.format(k["key_id"], k["label"][:12], k["bits"], k["status"],
                             f"{k['uses']}/{k.get('max_uses') or '∞'}", _fmt_ts(k.get("expires"))))
        if not keys:
            print("(сховище порожнє)")
        return {"count": len(keys)}
    if args.action == "rotate":
        meta = _store(args, create=False).rotate(args.label)
        print(f"Ротація виконана: новий активний ключ {meta['key_id']} (попередні → retired)")
        return {"label": args.label, "new": meta["key_id"]}
    if args.action == "revoke":
        meta = _store(args, create=False).revoke(args.key_id, args.reason)
        print(f"Ключ {meta['key_id']} відкликано (reason={args.reason})")
        return {"key_id": args.key_id}
    if args.action == "enc":
        store = _store(args, create=False)
        data = read_file(args.inp)
        t0 = time.perf_counter()
        blob = sym.encrypt_with_store(store, data, args.mode, label=args.label)
        dt = time.perf_counter() - t0
        write_file(args.out, blob)
        hdr, _, _ = sym.parse_container(blob)
        print(f"Зашифровано {len(data)} Б → {args.out} ({hdr['alg']}, key_id={hdr['key_id']}, {dt:.4f} с)")
        return {"mode": hdr["mode"], "key_id": hdr["key_id"], "in": args.inp, "out": args.out,
                "size": len(data), "sec": round(dt, 4)}
    if args.action == "dec":
        store = _store(args, create=False)
        blob = read_file(args.inp)
        hdr, _, _ = sym.parse_container(blob)
        if args.key_id and hdr["key_id"] != args.key_id:
            raise KeyPolicyViolation(f"Контейнер зашифровано ключем {hdr['key_id']}, а вказано {args.key_id}")
        t0 = time.perf_counter()
        data = sym.decrypt_bytes(blob, store.key_for_decrypt(hdr["key_id"]))
        dt = time.perf_counter() - t0
        write_file(args.out, data)
        print(f"Розшифровано → {args.out} ({len(data)} Б, {hdr['alg']}, {dt:.4f} с)")
        return {"mode": hdr["mode"], "key_id": hdr["key_id"], "in": args.inp, "out": args.out,
                "size": len(data), "sec": round(dt, 4)}


# --------------------------------------------------------------------------- rsa / ecc
def _asym_ops(kind):
    if kind == "rsa":
        return asym.rsa_encrypt, asym.rsa_decrypt, asym.sign_rsa, asym.verify_rsa
    return asym.ecc_encrypt, asym.ecc_decrypt, asym.sign_ecc, asym.verify_ecc


def cmd_asym(args):
    kind = args.cmd
    enc, dec, sign, verify = _asym_ops(kind)
    if args.action == "gen":
        t0 = time.perf_counter()
        if kind == "rsa":
            key, param = asym.gen_rsa(args.bits), args.bits
        else:
            param = {"p256": "P-256", "p384": "P-384"}.get(args.curve.lower(), args.curve)
            key = asym.gen_ecc(param)
        dt = time.perf_counter() - t0
        asym.save_priv_pem(key, args.priv, args.password)
        asym.save_pub_pem(key, args.pub)
        fp = asym.fingerprint(key)
        print(f"Згенеровано {asym.describe(key)} за {dt:.3f} с; priv={args.priv} (PEM, зашифровано), "
              f"pub={args.pub}; fingerprint={fp}")
        return {"alg": asym.describe(key), "fingerprint": fp, "sec": round(dt, 4)}
    if args.action == "enc":
        pub = asym.load_pub(args.pub)
        write_file(args.out, enc(pub, read_file(args.inp)))
        print(f"Зашифровано ({asym.describe(pub)}) → {args.out}")
        return {"alg": asym.describe(pub), "in": args.inp, "out": args.out}
    if args.action == "dec":
        priv = asym.load_priv(args.priv, args.password)
        data = dec(priv, read_file(args.inp))
        write_file(args.out, data)
        print(f"Розшифровано ({asym.describe(priv)}) → {args.out} ({len(data)} Б)")
        return {"alg": asym.describe(priv), "in": args.inp, "out": args.out}
    if args.action == "sign":
        priv = asym.load_priv(args.priv, args.password)
        write_file(args.sig, sign(priv, read_file(args.inp)))
        print(f"Підпис ({asym.describe(priv)}) збережено → {args.sig}")
        return {"alg": asym.describe(priv), "in": args.inp, "sig": args.sig}
    if args.action == "verify":
        pub = asym.load_pub(args.pub)
        verify(pub, read_file(args.inp), read_file(args.sig))
        print(f"OK: підпис дійсний ({asym.describe(pub)})")
        return {"alg": asym.describe(pub), "in": args.inp, "valid": True}


# --------------------------------------------------------------------------- hybrid
def cmd_hybrid(args):
    if args.action == "enc":
        pub = asym.load_pub(args.pub)
        is_rsa = asym.describe(pub).startswith("RSA")
        if args.algo and (args.algo == "rsa") != is_rsa:
            raise InputError(f"--algo {args.algo} не відповідає ключу {asym.describe(pub)}")
        data = read_file(args.inp)
        t0 = time.perf_counter()
        blob = hybrid.encrypt_hybrid(data, pub, filename=os.path.basename(args.inp))
        dt = time.perf_counter() - t0
        write_file(args.out, blob)
        print(f"Гібридно зашифровано {len(data)} Б → {args.out} "
              f"({'RSA-OAEP' if is_rsa else 'ECIES'} + AES-256-GCM, {dt:.4f} с)")
        return {"recipient": asym.describe(pub), "in": args.inp, "out": args.out, "sec": round(dt, 4)}
    if args.action == "dec":
        priv = asym.load_priv(args.priv, args.password)
        t0 = time.perf_counter()
        data = hybrid.decrypt_hybrid(read_file(args.inp), priv)
        dt = time.perf_counter() - t0
        write_file(args.out, data)
        print(f"Гібридно розшифровано → {args.out} ({len(data)} Б, {dt:.4f} с)")
        return {"recipient": asym.describe(priv), "in": args.inp, "out": args.out, "sec": round(dt, 4)}


# --------------------------------------------------------------------------- bench
def cmd_bench(args):
    import benchmark
    sizes = benchmark.parse_sizes(args.sizes) if args.sizes else None
    md = benchmark.run(sizes=sizes, out_dir=args.out_dir)
    print(md)
    return {"out_dir": args.out_dir}


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="crypto-suite", description="Криптографічний пакет (ПР №3-4)")
    p.add_argument("--interactive", "-i", action="store_true", help="текстове меню")
    p.add_argument("--keystore", default=DEFAULT_KS, help="шлях до сховища ключів (default: keystore.json)")
    sub = p.add_subparsers(dest="cmd")

    # sym
    ps = sub.add_parser("sym", help="симетричне шифрування AES + сховище ключів")
    ss = ps.add_subparsers(dest="action", required=True)
    s = ss.add_parser("new", help="створити ключ")
    s.add_argument("--label", required=True)
    s.add_argument("--bits", type=int, choices=[128, 192, 256], default=256)
    s.add_argument("--max-uses", type=int, default=1000)
    s.add_argument("--days", type=int, default=90, help="строк дії ключа, днів")
    s = ss.add_parser("list", help="список ключів")
    s = ss.add_parser("rotate", help="ротація ключа мітки")
    s.add_argument("--label", required=True)
    s = ss.add_parser("revoke", help="відкликати ключ")
    s.add_argument("--key-id", required=True)
    s.add_argument("--reason", default="unspecified")
    s = ss.add_parser("enc", help="зашифрувати файл (CSYM v1)")
    s.add_argument("--label", required=True)
    s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--mode", choices=["gcm", "ccm", "cbc", "ctr"], default="gcm")
    s = ss.add_parser("dec", help="розшифрувати файл (CSYM v1)")
    s.add_argument("--key-id", default=None, help="очікуваний key_id (за замовч. — з заголовка)")
    s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out", required=True)
    for a in ss.choices.values():
        a.add_argument("--ks-password", default=None, help="пароль сховища (або env CRYPTO_SUITE_KS_PASSWORD)")
    ps.set_defaults(func=cmd_sym)

    # rsa / ecc
    for kind in ("rsa", "ecc"):
        pk = sub.add_parser(kind, help=f"{kind.upper()}: генерація, шифрування, підпис")
        sk = pk.add_subparsers(dest="action", required=True)
        g = sk.add_parser("gen")
        g.add_argument("--priv", required=True)
        g.add_argument("--pub", required=True)
        g.add_argument("--password", default=None)
        if kind == "rsa":
            g.add_argument("--bits", type=int, choices=[2048, 3072, 4096], default=3072)
        else:
            g.add_argument("--curve", choices=["p256", "p384"], default="p256")
        e = sk.add_parser("enc")
        e.add_argument("--pub", required=True)
        e.add_argument("--in", dest="inp", required=True)
        e.add_argument("--out", required=True)
        d = sk.add_parser("dec")
        d.add_argument("--priv", required=True)
        d.add_argument("--password", default=None)
        d.add_argument("--in", dest="inp", required=True)
        d.add_argument("--out", required=True)
        sg = sk.add_parser("sign")
        sg.add_argument("--priv", required=True)
        sg.add_argument("--password", default=None)
        sg.add_argument("--in", dest="inp", required=True)
        sg.add_argument("--sig", required=True)
        v = sk.add_parser("verify")
        v.add_argument("--pub", required=True)
        v.add_argument("--in", dest="inp", required=True)
        v.add_argument("--sig", required=True)
        pk.set_defaults(func=cmd_asym)

    # hybrid
    ph = sub.add_parser("hybrid", help="гібридне шифрування (CHYB v1)")
    sh = ph.add_subparsers(dest="action", required=True)
    e = sh.add_parser("enc")
    e.add_argument("--pub", required=True)
    e.add_argument("--in", dest="inp", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--algo", choices=["rsa", "ecc"], default=None)
    d = sh.add_parser("dec")
    d.add_argument("--priv", required=True)
    d.add_argument("--password", default=None)
    d.add_argument("--in", dest="inp", required=True)
    d.add_argument("--out", required=True)
    ph.set_defaults(func=cmd_hybrid)

    # bench
    pb = sub.add_parser("bench", help="запустити бенчмарки")
    pb.add_argument("--sizes", default=None, help="напр. 1KB,100KB,1MB,10MB")
    pb.add_argument("--out-dir", default="outputs")
    pb.set_defaults(func=cmd_bench)
    return p


def _fill_secrets(args):
    """Паролі: аргумент → змінна середовища → getpass (не потрапляють у лог)."""
    if hasattr(args, "ks_password") and not args.ks_password:
        args.ks_password = os.environ.get("CRYPTO_SUITE_KS_PASSWORD") or getpass.getpass("Пароль сховища: ")
    needs_pw = args.cmd in ("rsa", "ecc", "hybrid") and args.action in ("gen", "dec", "sign")
    if needs_pw and not getattr(args, "password", None):
        args.password = os.environ.get("CRYPTO_SUITE_KEY_PASSWORD") or getpass.getpass("Пароль приватного ключа: ")


def execute(args) -> int:
    event = ".".join(x for x in (args.cmd, getattr(args, "action", None)) if x)
    try:
        _fill_secrets(args)
        info = args.func(args) or {}
        log_event(event, status="ok", **info)
        return 0
    except CryptoSuiteError as err:
        log_event(event, status="fail", level=logging.WARNING, error=err.kind, code=err.code, message=str(err))
        print(f"ПОМИЛКА [{err.kind}, код {err.code}]: {err}", file=sys.stderr)
        return err.code
    except KeyboardInterrupt:
        print("\nПерервано користувачем", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------- interactive
MENU = [
    ("Симетричний: створити ключ", "sym new --label {label}"),
    ("Симетричний: список ключів", "sym list"),
    ("Симетричний: зашифрувати файл", "sym enc --label {label} --in {inp} --out {out} --mode {mode}"),
    ("Симетричний: розшифрувати файл", "sym dec --in {inp} --out {out}"),
    ("Симетричний: ротація ключа", "sym rotate --label {label}"),
    ("Симетричний: відкликати ключ", "sym revoke --key-id {key_id}"),
    ("RSA: згенерувати пару ключів", "rsa gen --priv {priv} --pub {pub} --bits {bits}"),
    ("ECC: згенерувати пару ключів", "ecc gen --priv {priv} --pub {pub} --curve {curve}"),
    ("RSA/ECC: підписати файл", "{kind} sign --priv {priv} --in {inp} --sig {sig}"),
    ("RSA/ECC: перевірити підпис", "{kind} verify --pub {pub} --in {inp} --sig {sig}"),
    ("Гібрид: зашифрувати файл", "hybrid enc --pub {pub} --in {inp} --out {out}"),
    ("Гібрид: розшифрувати файл", "hybrid dec --priv {priv} --in {inp} --out {out}"),
    ("Бенчмарк", "bench"),
]
PROMPTS = {"label": "Мітка ключа", "inp": "Вхідний файл", "out": "Вихідний файл", "mode": "Режим (gcm/ccm/cbc/ctr)",
           "key_id": "key_id", "priv": "Файл приватного ключа", "pub": "Файл публічного ключа",
           "bits": "Біт RSA (2048/3072/4096)", "curve": "Крива (p256/p384)", "kind": "Алгоритм (rsa/ecc)",
           "sig": "Файл підпису"}
DEFAULTS = {"mode": "gcm", "bits": "3072", "curve": "p256", "kind": "rsa"}


def interactive(parser, keystore):
    import re
    import shlex
    while True:
        print("\n=== crypto-suite: інтерактивне меню ===")
        for i, (title, _) in enumerate(MENU, 1):
            print(f" {i:>2}. {title}")
        print("  0. Вихід")
        choice = input("Ваш вибір: ").strip()
        if choice in ("0", "q", ""):
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(MENU):
            print("Невірний пункт меню")
            continue
        template = MENU[int(choice) - 1][1]
        values = {}
        for name in re.findall(r"{(\w+)}", template):
            d = DEFAULTS.get(name)
            v = input(f"{PROMPTS[name]}{f' [{d}]' if d else ''}: ").strip() or d or ""
            values[name] = shlex.quote(v)
        argv = ["--keystore", keystore] + shlex.split(template.format(**values))
        try:
            args = parser.parse_args(argv)
        except SystemExit:
            continue
        rc = execute(args)
        print(f"(код завершення: {rc})")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.interactive:
        return interactive(parser, args.keystore)
    if not args.cmd:
        parser.print_help()
        return 2
    return execute(args)


if __name__ == "__main__":
    sys.exit(main())
