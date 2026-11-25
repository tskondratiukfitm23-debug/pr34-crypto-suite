# Обробка винятків: 5 реальних прикладів

Усі помилки пакета успадковуються від `CryptoSuiteError` (`errors.py`). CLI перехоплює їх у
`cli.execute()`, виводить у stderr повідомлення формату

```
ПОМИЛКА [<kind>, код <code>]: <опис>
```

записує подію зі `status: "fail"` у `logs/crypto.jsonl` (без секретів) і завершується з `sys.exit(err.code)`.

| Клас | kind | Код |
|---|---|---|
| `InvalidContainer` | invalid_container | 10 |
| `IntegrityError` | integrity_failed | 20 |
| `SignatureInvalid` | signature_invalid | 21 |
| `BadPassword` | bad_password | 22 |
| `InvalidKey` | invalid_key | 30 |
| `KeyNotFound` | key_not_found | 31 |
| `KeyPolicyViolation` | key_policy | 32 |
| `WrongRecipient` | wrong_recipient | 33 |
| `InputError` | input_error | 40 |

Підготовка (виконано реально):

```
$ python cli.py sym new --label docs --ks-password 'S3cret!'
Створено ключ: key_id=316e97fdaef3f38f label=docs bits=256
$ python cli.py sym enc --label docs --ks-password 'S3cret!' --in sample.txt --out s.bin --mode gcm
Зашифровано 18 Б → s.bin (AES-256-GCM, key_id=316e97fdaef3f38f, 0.0005 с)
```

## 1. Пошкоджений контейнер (невірний MAGIC)

Перші 4 байти `CSYM` замінено на `XSYM`:

```
$ python cli.py sym dec --ks-password 'S3cret!' --in s_bad.bin --out o.txt
ПОМИЛКА [invalid_container, код 10]: Не CSYM-контейнер (невірний MAGIC)
$ echo $?
10
```

Так само обробляється обрізаний файл ("Пошкоджена довжина заголовка CSYM", "Контейнер обрізаний: немає тегу").

## 2. Неправильний тег (змінено 1 байт)

Інвертовано молодший біт останнього байта (тегу GCM):

```
$ python cli.py sym dec --ks-password 'S3cret!' --in s_tag.bin --out o.txt
ПОМИЛКА [integrity_failed, код 20]: Перевірка цілісності не пройдена: тег/HMAC не збігається (дані або заголовок пошкоджені, або ключ неправильний).
$ echo $?
20
```

Вихідний файл **не створюється** — дані не повертаються до перевірки тегу (для CBC/CTR — HMAC перевіряється до дешифрації).

## 3. Неправильний пароль PEM

```
$ python cli.py rsa gen --priv k.pem --pub k.pub.pem --password 'P@ss' --bits 2048
Згенеровано RSA-2048 за 0.047 с; priv=k.pem (PEM, зашифровано), pub=k.pub.pem; fingerprint=723d7f90816789e029a91565467df1af
$ python cli.py rsa sign --priv k.pem --password 'wrong' --in sample.txt --sig s.sig
ПОМИЛКА [bad_password, код 22]: Неправильний пароль до приватного ключа
$ echo $?
22
```

Аналогічно для сховища: `sym list --ks-password bad` → `ПОМИЛКА [bad_password, код 22]: Неправильний пароль до сховища ключів`.

## 4. Неправильна довжина ключа

Ключ 17 байт (136 біт) переданий у `encrypt_bytes`:

```
$ python -c "import sym; sym.encrypt_bytes(b'x', b'A'*17)"   # виняток InvalidKey, виведений у форматі CLI
ПОМИЛКА [invalid_key, код 30]: Неправильна довжина ключа AES: 136 біт (дозволено 128/192/256)
```

На рівні CLI недопустима довжина відсікається ще argparse:

```
$ python cli.py sym new --label x --bits 100 --ks-password 'S3cret!'
crypto-suite sym new: error: argument --bits: invalid choice: 100 (choose from 128, 192, 256)
$ echo $?
2
```

## 5. Відкликаний ключ

```
$ python cli.py sym revoke --key-id 316e97fdaef3f38f --reason compromised --ks-password 'S3cret!'
Ключ 316e97fdaef3f38f відкликано (reason=compromised)
$ python cli.py sym dec --ks-password 'S3cret!' --in s.bin --out o.txt
ПОМИЛКА [key_policy, код 32]: Ключ 316e97fdaef3f38f відкликано — розшифрування заборонено
$ echo $?
32
```

## Запис у журналі (фрагмент `logs/crypto.jsonl`)

```json
{"ts": "2026-11-25T20:16:10Z", "level": "INFO", "event": "keystore.open", "status": "fail", "reason": "bad_password"}
{"ts": "2026-11-25T20:16:10Z", "level": "WARNING", "event": "sym.list", "status": "fail", "error": "bad_password", "code": 22, "message": "Неправильний пароль до сховища ключів"}
```

Паролі, ключі, nonce/IV, теги і відкритий текст у журнал не потрапляють (перевірено: `grep -c "S3cret\|P@ss" crypto.jsonl` → `0`).
