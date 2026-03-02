import logging
from datetime import datetime
from typing import Dict

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.models.cve import CVE
from src.utils.nvd_parser import parse_datetime
from src.settings import SessionLocal

logger = logging.getLogger(__name__)


def get_existing_cve_ids() -> dict[str, datetime | None] | None:
    """
    Fetch all existing CVE IDs and last_modified timestamps from DB in one query.
    Returns dict of {cve_id: last_modified} or None on failure.
    """
    logger.info("Fetching Existing CVEs")
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar()

            result = db.execute(select(CVE.cve_id, CVE.last_modified)).all()
            existing = {row[0]: row[1] for row in result}

            logger.info("Found %s existing CVEs in DB", len(existing))
            return existing

    except (IntegrityError, SQLAlchemyError):
        logger.exception("Database error while fetching existing CVEs")
    except Exception:
        logger.exception("Unexpected error during DB check")
    return None


def is_updated(cve_obj: Dict, existing_cves: dict[str, datetime | None]) -> bool:
    """In-memory check — no DB call needed."""
    cve_id = cve_obj.get("id")
    existing_last_modified = existing_cves.get(cve_id)

    new_last_mod = parse_datetime(cve_obj.get("lastModified"))
    if new_last_mod and existing_last_modified:
        # DB stores naive UTC; strip timezone before comparing
        return new_last_mod.replace(tzinfo=None) > existing_last_modified
    return False
