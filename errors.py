"""Ієрархія винятків crypto-suite. Кожен виняток має код завершення для CLI."""


class CryptoSuiteError(Exception):
    code = 1
    kind = "error"

    def __init__(self, message: str = ""):
        super().__init__(message or self.__doc__ or self.__class__.__name__)


class InvalidContainer(CryptoSuiteError):
    """Невалідний формат контейнера (magic/версія/заголовок)."""
    code, kind = 10, "invalid_container"


class IntegrityError(CryptoSuiteError):
    """Перевірка цілісності не пройдена: тег/HMAC не збігається (дані або заголовок пошкоджені, або ключ неправильний)."""
    code, kind = 20, "integrity_failed"


class SignatureInvalid(CryptoSuiteError):
    """Цифровий підпис недійсний."""
    code, kind = 21, "signature_invalid"


class BadPassword(CryptoSuiteError):
    """Неправильний пароль до приватного ключа або сховища ключів."""
    code, kind = 22, "bad_password"


class InvalidKey(CryptoSuiteError):
    """Неправильний формат або довжина ключа."""
    code, kind = 30, "invalid_key"


class KeyNotFound(CryptoSuiteError):
    """Ключ не знайдено у сховищі."""
    code, kind = 31, "key_not_found"


class KeyPolicyViolation(CryptoSuiteError):
    """Порушення політики ключів (ключ відкликано / виведено з обігу / вичерпано ліміт)."""
    code, kind = 32, "key_policy"


class WrongRecipient(CryptoSuiteError):
    """Пакет зашифровано для іншого отримувача (відбиток ключа не збігається)."""
    code, kind = 33, "wrong_recipient"


class InputError(CryptoSuiteError):
    """Некоректні вхідні дані (файл, параметр)."""
    code, kind = 40, "input_error"
