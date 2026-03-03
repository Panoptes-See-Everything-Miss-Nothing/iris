import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker


DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DATABASE = os.getenv("DATABASE")
NVD_API_KEY = os.getenv("NVD_API_KEY")

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
