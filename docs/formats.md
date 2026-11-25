# Формати контейнерів crypto-suite

Усі багатобайтові цілі числа — **big-endian**. JSON-заголовок серіалізується детерміновано
(`sort_keys=True`, без пробілів, UTF-8), максимальна довжина — 4096 байт.

## 1. CSYM v1 — симетричний контейнер (`sym.py`)

```
 зміщення  довжина   поле
 0         4         MAGIC = "CSYM" (0x43 0x53 0x59 0x4D)
 4         1         VERSION = 0x01
 5         2         HDRLEN  (uint16, довжина JSON-заголовка, 1..4096)
 7         HDRLEN    HEADER  (JSON, UTF-8)
 7+HDRLEN  N         CIPHERTEXT
 кінець-T  T         TAG: 16 Б (GCM/CCM — тег AEAD) або 32 Б (CBC/CTR — HMAC-SHA256)
```

`PREFIX = MAGIC | VERSION | HDRLEN | HEADER` — автентифікується в усіх режимах.

### Поля JSON-заголовка

| Поле | Тип | Опис |
|---|---|---|
| `v` | int | версія формату (1) |
| `alg` | str | людинозрозуміла назва, напр. `AES-256-GCM`, `AES-128-CBC-HMAC-SHA256` |
| `mode` | str | `GCM` / `CCM` / `CBC` / `CTR` |
| `bits` | int | 128 / 192 / 256 — довжина AES-ключа |
| `kdf` | str | `HKDF-SHA256` |
| `salt` | hex | 16 випадкових байт — salt для HKDF (унікальний на файл) |
| `key_id` | str | ідентифікатор майстер-ключа у сховищі (`raw` — якщо ключ передано напряму) |
| `nonce` | hex | GCM: 12 Б; CCM: 13 Б; CTR: 16 Б (початковий лічильник) |
| `iv` | hex | CBC: 16 Б |

Nonce/IV/salt не є секретами, тому зберігаються відкрито — але вони захищені від підміни (входять до AAD/HMAC).

### Виведення ключів

```
OKM = HKDF-SHA256(IKM = master_key, salt = salt, info = "CSYM-v1|<MODE>|<key_id>", L)
GCM/CCM:  L = bits/8           enc_key = OKM
CBC/CTR:  L = bits/8 + 32      enc_key = OKM[:bits/8], mac_key = OKM[bits/8:]
```

### Режими

| Режим | Шифрування | Тег | Розшифрування |
|---|---|---|---|
| GCM | `AESGCM(enc_key).encrypt(nonce12, pt, AAD=PREFIX)` | 16 Б в кінці | AEAD перевіряє тег; збій → `IntegrityError` |
| CCM | `AESCCM(enc_key, tag=16).encrypt(nonce13, pt, AAD=PREFIX)` | 16 Б | те саме |
| CBC | PKCS#7 → AES-CBC(iv16) | `HMAC-SHA256(mac_key, PREFIX ‖ CT)` | **спочатку** HMAC (`compare_digest`), потім дешифрація |
| CTR | AES-CTR(nonce16) | `HMAC-SHA256(mac_key, PREFIX ‖ CT)` | **спочатку** HMAC, потім дешифрація |

### Валідація при розборі (`parse_container`) → `InvalidContainer`

* довжина < 7 або MAGIC ≠ `CSYM`;
* VERSION ≠ 1;
* HDRLEN = 0, > 4096 або виходить за межі файлу (обрізаний файл);
* заголовок не JSON / бракує обов'язкових полів / невідомий режим чи довжина ключа;
* тіло коротше за довжину тегу.

## 2. CHYB v1 — гібридний пакет (`hybrid.py`)

```
 зміщення      довжина  поле
 0             4        MAGIC = "CHYB"
 4             1        VERSION = 0x01
 5             1        ALGID: 0x01 = RSA-OAEP-SHA256, 0x02 = ECIES-HKDF-SHA256
 6             2        HDRLEN (uint16)
 8             HDRLEN   HEADER (JSON)
 8+HDRLEN      2        WKLEN  (uint16) — довжина обгорнутого ключа
 10+HDRLEN     WKLEN    WRAPPED_KEY
 10+HDRLEN+WK  N        AES-256-GCM CIPHERTEXT
 кінець-16     16       GCM TAG
```

`AAD = усе від MAGIC до кінця WRAPPED_KEY` — заголовок і обгорнутий ключ захищені тегом GCM.

### Поля заголовка

| Поле | Опис |
|---|---|
| `v` | 1 |
| `wrap` | `RSA-OAEP-SHA256` або `ECIES-HKDF-SHA256` |
| `recipient` | опис ключа отримувача (`RSA-3072`, `ECC-secp256r1`) |
| `fp` | відбиток отримувача: перші 16 Б SHA-256(DER SubjectPublicKeyInfo), hex |
| `cipher` | `AES-256-GCM` |
| `nonce` | 12 Б, hex |
| `name` | (необов'язково) ім'я вихідного файлу |

### Обгортання ключа (WRAPPED_KEY)

* **RSA** (ALGID=1): `RSA-OAEP(MGF1-SHA256, SHA-256)` від 32-байтового AES-ключа; довжина = розмір модуля (256/384/512 Б).
* **ECC** (ALGID=2): ECIES —
  ```
  EPH_PUB (X9.62 uncompressed, 65 Б для P-256 / 97 Б для P-384) | NONCE (12) | AES-GCM(K, aes_key, AAD=EPH_PUB) (32+16)
  K = HKDF-SHA256(ECDH(eph_priv, recipient_pub), salt=EPH_PUB, info="crypto-suite ECIES-HKDF-SHA256 v1")
  ```

### Розшифрування

1. Розбір і перевірка структури → `InvalidContainer` (MAGIC, версія, ALGID, обрізання).
2. Тип приватного ключа має відповідати ALGID → `InvalidKey`.
3. `fp` має збігатися з відбитком наданого ключа → `WrongRecipient`.
4. Розгортання ключа (OAEP / ECIES) → `IntegrityError` при збої.
5. AES-GCM з AAD → `IntegrityError`, якщо змінено будь-який байт заголовка, ключа чи шифртексту.
