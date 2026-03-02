import logging
from typing import Dict

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from src.models.cvss import CVSSScore, CVSSv2, CVSSv31

logger = logging.getLogger(__name__)


def _upsert_cvss_score(
    cve_id: str, version: str, data: Dict, db: Session
) -> int | None:
    """Upsert into cvss_scores and return the score ID, or None on failure."""
    stmt = insert(CVSSScore).values(
        cve_id=cve_id,
        version=version,
        base_score=data.get("baseScore"),
        base_severity=data.get("baseSeverity"),
        vector_string=data.get("vectorString"),
        exploitability_score=data.get("exploitabilityScore"),
        impact_score=data.get("impactScore"),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_cvss_cve_version",
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in CVSSScore.__table__.columns
            if col.name not in ("id", "cve_id", "version")
        },
    )
    score_id = db.scalar(stmt.returning(CVSSScore.id))
    return score_id


def upsert_cvss_v2(cve_id: str, v2: Dict, db: Session) -> bool:
    score_id = _upsert_cvss_score(cve_id, "2.0", v2, db)
    if score_id is None:
        return False

    stmt = insert(CVSSv2).values(
        cvss_score_id=score_id,
        access_vector=v2.get("accessVector"),
        access_complexity=v2.get("accessComplexity"),
        authentication=v2.get("authentication"),
        confidentiality_impact=v2.get("confidentialityImpact"),
        integrity_impact=v2.get("integrityImpact"),
        availability_impact=v2.get("availabilityImpact"),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_cvss_v2_details_score",
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in CVSSv2.__table__.columns
            if col.name not in ("id", "cvss_score_id")
        },
    )
    db.execute(stmt)
    logger.info("Saved CVSS v2 for %s", cve_id)
    return True


def upsert_cvss_v31(cve_id: str, v3: Dict, db: Session) -> bool:
    score_id = _upsert_cvss_score(cve_id, "3.1", v3, db)
    if score_id is None:
        return False

    stmt = insert(CVSSv31).values(
        cvss_score_id=score_id,
        attack_vector=v3.get("attackVector"),
        attack_complexity=v3.get("attackComplexity"),
        privileges_required=v3.get("privilegesRequired"),
        user_interaction=v3.get("userInteraction"),
        scope=v3.get("scope"),
        confidentiality_impact=v3.get("confidentialityImpact"),
        integrity_impact=v3.get("integrityImpact"),
        availability_impact=v3.get("availabilityImpact"),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_cvss_v31_details_score",
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in CVSSv31.__table__.columns
            if col.name not in ("id", "cvss_score_id")
        },
    )
    db.execute(stmt)
    logger.info("Saved CVSS v31 for %s", cve_id)
    return True
