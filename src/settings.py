import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DATABASE = os.getenv("DATABASE")
NVD_API_KEY = os.getenv("NVD_API_KEY")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = PROJECT_ROOT / "src/fixtures"
DEFAULT_FIXTURES_FILE = FIXTURES_DIR / "nvdcve_2.0.json"
FIXTURES_FILE = os.getenv("FIXTURES_FILE", str(DEFAULT_FIXTURES_FILE))
DATABASE_URL = (
    f"postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DATABASE}"
)
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOG_DIR = PROJECT_ROOT / "logs"

os.makedirs(LOG_DIR, exist_ok=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
