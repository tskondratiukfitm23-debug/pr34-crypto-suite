# crypto-suite — ПР №3-4

Реалізація симетричного, асиметричного та гібридного шифрування на Python (`cryptography` ≥ 42).

**Виконав:** Кондратюк Т.С., група 22340.

[![CI](https://kodekloud.com/kk-media/image/upload/v1752876750/notes-assets/images/GitHub-Actions-Adding-a-workflow-status-badge/github-status-badge-creation-popup.jpg)](https://github.com/tskondratiukfitm23-debug/pr34-crypto-suite/actions/workflows/ci.yml)

## Можливості

* **AES-128/192/256**: GCM, CCM (AEAD, заголовок = AAD), CBC+HMAC-SHA256 і CTR+HMAC-SHA256 (encrypt-then-MAC, verify-then-decrypt).
* **Сховище ключів** `keystore.json`: scrypt-KEK + AES-GCM обгортання, ротація (лічильник/строк), відкликання.
* **RSA** 2048/3072/4096: OAEP-SHA256 (шифрування), PSS-SHA256 (підпис).
* **ECC** P-256/P-384: ECIES (ECDH + HKDF-SHA256 + AES-GCM), ECDSA-SHA256.
* **Гібрид** CHYB v1: AES-256-GCM + обгортання ключа RSA-OAEP або ECIES, перевірка отримувача за відбитком.
* Приватні ключі — **лише** PEM PKCS#8 під паролем.
* JSON-журнал `logs/crypto.jsonl` з маскуванням секретів; ієрархія винятків з кодами завершення.
* Бенчмарки, 60 pytest-тестів, CI на GitHub Actions.

## Структура проєкту

```
pr34-crypto-suite/
├── cli.py               # argparse CLI: sym / rsa / ecc / hybrid / bench / --interactive
├── sym.py               # AES-режими, формат CSYM v1, SymKeyStore
├── asym.py              # RSA, ECC, PEM, підписи
├── hybrid.py            # формат CHYB v1
├── errors.py            # ієрархія винятків (коди завершення)
├── logger.py            # JSONL-логер з маскуванням
├── benchmark.py         # бенчмарки → outputs/bench.csv, outputs/bench.md
├── tests/test_crypto.py # pytest: roundtrip, tamper, keystore, container, CLI
├── data/sample.txt      # тестовий файл
├── docs/                # formats.md, key-policy.md, exceptions.md
├── keys/  logs/  outputs/
├── requirements.txt
└── .github/workflows/ci.yml
```

## Quick Start

```bash
git clone https://github.com/tskondratiukfitm23-debug/pr34-crypto-suite.git
cd pr34-crypto-suite
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
mkdir -p keys logs outputs

# --- Симетричне шифрування зі сховищем ключів
python cli.py sym new    --label docs --bits 256 --max-uses 100 --ks-password 'S3cret!'
python cli.py sym list   --ks-password 'S3cret!'
python cli.py sym enc    --label docs --ks-password 'S3cret!' --in data/sample.txt --out outputs/sample.csym --mode gcm
python cli.py sym dec    --ks-password 'S3cret!' --in outputs/sample.csym --out outputs/sample.dec.txt
python cli.py sym rotate --label docs --ks-password 'S3cret!'
python cli.py sym revoke --key-id <KEY_ID> --reason compromised --ks-password 'S3cret!'

# --- RSA
python cli.py rsa gen    --priv keys/rsa.pem --pub keys/rsa.pub.pem --password 'P@ss' --bits 3072
python cli.py rsa enc    --pub keys/rsa.pub.pem --in data/sample.txt --out outputs/sample.rsa
python cli.py rsa dec    --priv keys/rsa.pem --password 'P@ss' --in outputs/sample.rsa --out outputs/sample.rsa.txt
python cli.py rsa sign   --priv keys/rsa.pem --password 'P@ss' --in data/sample.txt --sig outputs/sample.rsa.sig
python cli.py rsa verify --pub keys/rsa.pub.pem --in data/sample.txt --sig outputs/sample.rsa.sig

# --- ECC
python cli.py ecc gen    --priv keys/ecc.pem --pub keys/ecc.pub.pem --password 'P@ss' --curve p384
python cli.py ecc sign   --priv keys/ecc.pem --password 'P@ss' --in data/sample.txt --sig outputs/sample.ecc.sig
python cli.py ecc verify --pub keys/ecc.pub.pem --in data/sample.txt --sig outputs/sample.ecc.sig

# --- Гібрид (файли будь-якого розміру)
python cli.py hybrid enc --pub keys/ecc.pub.pem --in data/sample.txt --out outputs/sample.chyb --algo ecc
python cli.py hybrid dec --priv keys/ecc.pem --password 'P@ss' --in outputs/sample.chyb --out outputs/sample.chyb.txt

# --- Бенчмарки, тести, меню
python cli.py bench            # або: python benchmark.py
python -m pytest tests/ -v
python cli.py --interactive
```

Паролі можна не передавати аргументом: CLI візьме їх зі змінних `CRYPTO_SUITE_KS_PASSWORD` /
`CRYPTO_SUITE_KEY_PASSWORD` або запитає через `getpass`.

## CLI-довідка

| Команда | Аргументи | Дія |
|---|---|---|
| `sym new` | `--label` `[--bits 128\|192\|256]` `[--max-uses N]` `[--days D]` `--ks-password` | новий ключ, виводить key_id |
| `sym list` | `--ks-password` | таблиця: key_id, label, bits, status, uses/max, expires |
| `sym rotate` | `--label` `--ks-password` | active → retired, новий active |
| `sym revoke` | `--key-id` `[--reason]` `--ks-password` | статус revoked |
| `sym enc` | `--label` `--in` `--out` `[--mode gcm\|ccm\|cbc\|ctr]` `--ks-password` | шифрування у CSYM v1 |
| `sym dec` | `[--key-id]` `--in` `--out` `--ks-password` | розшифрування (key_id береться з заголовка) |
| `rsa gen` | `--priv` `--pub` `--password` `[--bits 2048\|3072\|4096]` | пара ключів |
| `ecc gen` | `--priv` `--pub` `--password` `[--curve p256\|p384]` | пара ключів |
| `rsa\|ecc enc/dec` | `--pub`/`--priv --password` `--in` `--out` | OAEP / ECIES |
| `rsa\|ecc sign/verify` | `--priv --password`/`--pub` `--in` `--sig` | PSS / ECDSA |
| `hybrid enc` | `--pub` `--in` `--out` `[--algo rsa\|ecc]` | CHYB v1 |
| `hybrid dec` | `--priv` `--password` `--in` `--out` | алгоритм визначається з пакета |
| `bench` | `[--sizes 1KB,1MB]` `[--out-dir outputs]` | бенчмарки |
| `--keystore PATH` | глобальний | шлях до сховища (за замовч. `keystore.json`) |
| `--interactive` | глобальний | нумероване текстове меню |

Коди завершення: `0` — успіх, `10` InvalidContainer, `20` IntegrityError, `21` SignatureInvalid,
`22` BadPassword, `30` InvalidKey, `31` KeyNotFound, `32` KeyPolicyViolation, `33` WrongRecipient,
`40` InputError, `2` — помилка аргументів. Див. [docs/exceptions.md](docs/exceptions.md).

## Формат CSYM v1 (симетричний)

```
+--------+---------+----------+-------------------+-------------+-------------------+
| "CSYM" | VER=1   | HDRLEN   | JSON header       | ciphertext  | TAG               |
| 4 B    | 1 B     | 2 B (BE) | HDRLEN B          | N B         | 16 B GCM/CCM      |
|        |         |          | v,alg,mode,bits,  |             | 32 B HMAC CBC/CTR |
|        |         |          | kdf,salt,key_id,  |             |                   |
|        |         |          | nonce|iv          |             |                   |
+--------+---------+----------+-------------------+-------------+-------------------+
 \______________ PREFIX = AAD (GCM/CCM) / вхід HMAC разом із CT (CBC/CTR) ______/
```

## Формат CHYB v1 (гібридний)

```
+--------+-------+-------+--------+-------------+-------+-------------+------------+--------+
| "CHYB" | VER=1 | ALGID | HDRLEN | JSON header | WKLEN | wrapped key | ciphertext | TAG 16 |
| 4 B    | 1 B   | 1 B   | 2 B    | HDRLEN B    | 2 B   | WKLEN B     | N B        | B      |
+--------+-------+-------+--------+-------------+-------+-------------+------------+--------+
 ALGID: 1 = RSA-OAEP-SHA256, 2 = ECIES-HKDF-SHA256
 \___________________________ AAD для AES-256-GCM _______________________/
```

Детально: [docs/formats.md](docs/formats.md). Політика ключів: [docs/key-policy.md](docs/key-policy.md).

## Бенчмарки

`python benchmark.py` вимірює encrypt+decrypt (AES-256 GCM, CBC-HMAC, CTR-HMAC) для 1KB/100KB/1MB/10MB
та генерацію ключів RSA-2048/3072/4096, ECC-P256/P384. Результати: `outputs/bench.md`, `outputs/bench.csv`.

## Security notes

* Секрети генеруються лише CSPRNG (`secrets`, OpenSSL). Nonce/IV — новий для кожної операції, ззовні не задається.
* Кожен файл шифрується окремим ключем: `HKDF-SHA256(master, salt_16B, info=mode|key_id)`.
* CBC/CTR: **encrypt-then-MAC**, HMAC перевіряється `compare_digest` **до** дешифрації (немає padding-oracle).
* GCM/CCM: увесь заголовок (MAGIC…JSON) — AAD; зміна будь-якого байта → `IntegrityError`.
* Сховище ключів: scrypt (N=2^15, r=8, p=1) → KEK; ключі обгорнуті AES-GCM з AAD=key_id; файл 0600.
* Приватні ключі — тільки зашифрований PEM; `keystore.json`, `keys/*.pem`, `logs/` не комітяться (`.gitignore`).
* Журнал не містить ключів, паролів, nonce/IV, тегів і відкритого тексту (маскування у `logger.py`).
* Вихідні файли пишуться атомарно (`*.part` → `os.replace`); при збої перевірки результат не створюється.
* RSA-OAEP шифрує лише короткі дані (≤ 190 Б для 2048) — для файлів використовуйте `hybrid`.
* Обмеження: файл повністю завантажується в пам'ять (потокова обробка не реалізована); захист від side-channel — на рівні OpenSSL.
