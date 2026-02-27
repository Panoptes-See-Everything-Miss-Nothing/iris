import logging
from typing import Dict

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.models.cve import CVE
from src.utils.nvd_parser import parse_datetime
from src.settings import SessionLocal

logger = logging.getLogger(__name__)


def get_existing_cve_ids() -> set | None:
    """
    Fetch all existing CVE IDs from DB.
    Returns set of IDs or None on failure.
    """
    logger.info("Fetching Existing CVEs")
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar()

            # Fetch IDs
            result = db.execute(select(CVE.cve_id)).all()
            existing_ids = {row[0] for row in result}

            logger.info("Found %s existing CVEs in DB", len(existing_ids))
            return existing_ids

    except (IntegrityError, SQLAlchemyError):
        logger.exception("Database error while fetching existing CVEs")
    except Exception:
        logger.exception("Unexpected error during DB check")
    return None


def is_updated(cve_obj: Dict) -> bool:
    cve_id = cve_obj.get("id")
    try:
        with SessionLocal() as db:
            existing_cve = db.scalar(select(CVE).where(CVE.cve_id == cve_id))

            if existing_cve:
                new_last_mod = parse_datetime(cve_obj.get("lastModified"))
                if new_last_mod and new_last_mod > existing_cve.last_modified:
                    return True
    except TypeError:
        logger.exception(
            "Timezone mismatch comparing last_modified for %s — treating as updated",
            cve_id,
        )
        return True
    except (IntegrityError, SQLAlchemyError):
        logger.exception(
            "Database error checking if CVE is updated", extra={"cve_id": cve_id}
        )
    except Exception:
        logger.exception("Unexpected error in is_updated", extra={"cve_id": cve_id})
    return False
