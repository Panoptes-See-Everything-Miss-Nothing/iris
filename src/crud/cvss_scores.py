from typing import Dict
import logging

from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from src.models.cvss import CVSSv2, CVSSv31

logger = logging.getLogger(__name__)


def upsert_cvss_v2(cve_id: str, v2: Dict, db: Session) -> bool:
    stmt = insert(CVSSv2).values(
        cve_id=cve_id,
        base_score=v2.get("baseScore"),
        base_severity=v2.get("baseSeverity"),
        access_vector=v2.get("accessVector"),
        access_complexity=v2.get("accessComplexity"),
        authentication=v2.get("authentication"),
        confidentiality_impact=v2.get("confidentialityImpact"),
        integrity_impact=v2.get("integrityImpact"),
        availability_impact=v2.get("availabilityImpact"),
        exploitability_score=v2.get("exploitabilityScore"),
        impact_score=v2.get("impactScore"),
        vector_string=v2.get("vectorString"),
        # Flags
        ac_insuf_info=v2.get("acInsufInfo"),
        obtain_all_privilege=v2.get("obtainAllPrivilege"),
        obtain_user_privilege=v2.get("obtainUserPrivilege"),
        obtain_other_privilege=v2.get("obtainOtherPrivilege"),
        user_interaction_required=v2.get("userInteractionRequired"),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_cvss_v2_cve",
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in CVSSv2.__table__.columns
            if col.name not in ("id", "cve_id")  # avoid overwriting PK
        },
    )
    db.execute(stmt)
    logger.info("Saved CVSS v2 for %s", cve_id)
    return True


def upsert_cvss_v31(cve_id: str, v3: Dict, db: Session) -> bool:
    stmt = insert(CVSSv31).values(
        cve_id=cve_id,
        base_score=v3.get("baseScore"),
        base_severity=v3.get("baseSeverity"),
        attack_vector=v3.get("attackVector"),
        attack_complexity=v3.get("attackComplexity"),
        privileges_required=v3.get("privilegesRequired"),
        user_interaction=v3.get("userInteraction"),
        scope=v3.get("scope"),
        confidentiality_impact=v3.get("confidentialityImpact"),
        integrity_impact=v3.get("integrityImpact"),
        availability_impact=v3.get("availabilityImpact"),
        exploitability_score=v3.get("exploitabilityScore"),
        impact_score=v3.get("impactScore"),
        vector_string=v3.get("vectorString"),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_cvss_v31_cve",
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in CVSSv31.__table__.columns
            if col.name not in ("id", "cve_id")  # avoid overwriting PK
        },
    )
    db.execute(stmt)
    logger.info("Saved CVSS v31 for %s", cve_id)
    return True
