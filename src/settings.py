import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker


DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DATABASE = os.getenv("DATABASE")
NVD_API_KEY = os.getenv("NVD_API_KEY")

_REQUIRED = {
    "DB_USERNAME": DB_USERNAME,
    "DB_PASSWORD": DB_PASSWORD,
    "DB_HOST": DB_HOST,
    "DATABASE": DATABASE,
}
_missing = [name for name, value in _REQUIRED.items() if not value]
if _missing:
    raise EnvironmentError(
        f"Missing required environment variables: {', '.join(_missing)}"
    )

_db_port_raw = os.getenv("DB_PORT", "5432")
try:
    DB_PORT = int(_db_port_raw)
except ValueError:
    raise EnvironmentError(f"DB_PORT must be an integer, got: {_db_port_raw!r}")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
JSON_FEED_ROOT_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

FIXTURES_DIR = PROJECT_ROOT / "src/fixtures"
os.makedirs(FIXTURES_DIR, exist_ok=True)
DATABASE_URL = URL.create(
    drivername="postgresql",
    username=DB_USERNAME,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DATABASE,
)
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

LOG_DIR = PROJECT_ROOT / "logs"
os.makedirs(LOG_DIR, exist_ok=True)

CVE_REJECTED = "Rejected"

MAX_DECOMPRESSED_FEED_SIZE = 500 * 1024 * 1024  # 500 MB per yearly NVD feed file
MAX_NVD_TOTAL_RESULTS = 500_000  # sanity cap on API-reported totalResults
MAX_CONCURRENT_API_PAGES = 5  # max simultaneous page fetches against NVD API


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
