import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# логи тестів — в окремий тимчасовий файл, щоб не засмічувати logs/
os.environ.setdefault("CRYPTO_SUITE_LOG", os.path.join(tempfile.gettempdir(), "crypto-suite-tests.jsonl"))
