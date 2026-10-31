"""Environment-driven configuration with secure defaults."""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Config:
    # No hardcoded secret: a random one is generated per process if none is set
    # (sessions then reset on restart, which is safe but inconvenient).
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'shadowlink.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    WTF_CSRF_TIME_LIMIT = 3600 * 8
    MAX_CONTENT_LENGTH = 16 * 1024  # tiny bodies only

    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_ENABLED = True
    LOGIN_RATE_LIMIT = "5 per minute"
    SCAN_RATE_LIMIT = "30 per minute"

    MAX_URL_LENGTH = 2048

    DNS_ANALYSIS_ENABLED = _bool("DNS_ANALYSIS_ENABLED", True)
    RDAP_ENABLED = _bool("RDAP_ENABLED", True)
    TLS_INSPECTION_ENABLED = _bool("TLS_INSPECTION_ENABLED", True)
    LIVE_FETCH_ENABLED = _bool("LIVE_FETCH_ENABLED", False)  # off by default
    MAX_REDIRECTS = _int("MAX_REDIRECTS", 5)
    CONNECT_TIMEOUT = _int("CONNECT_TIMEOUT", 4)
    READ_TIMEOUT = _int("READ_TIMEOUT", 4)
    MAX_RESPONSE_BYTES = _int("MAX_RESPONSE_BYTES", 65536)

    SCAN_RETENTION_DAYS = _int("SCAN_RETENTION_DAYS", 90)

    MODEL_PATH = str(BASE_DIR / "ml" / "models" / "phishing_model.joblib")
    MODEL_META_PATH = str(BASE_DIR / "ml" / "models" / "model_metadata.json")
    THREAT_INTEL_PATH = str(BASE_DIR / "ml" / "datasets" / "local_blocklist.txt")
    REPORT_DIR = str(BASE_DIR / "reports")


class TestConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-not-for-production"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False  # tests that exercise CSRF enable it explicitly
    RATELIMIT_ENABLED = False
    DNS_ANALYSIS_ENABLED = False
    RDAP_ENABLED = False
    TLS_INSPECTION_ENABLED = False
    LIVE_FETCH_ENABLED = False
