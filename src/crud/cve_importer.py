import logging
from typing import Dict, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.models.cve import CVE
from src.models.vendor import Vendor
from src.models.vulnerable_package import VulnerablePackage
from src.models.vulnerable_version import VulnerableVersion
from .cvss_scores import upsert_cvss_v2, upsert_cvss_v31
from src.settings import SessionLocal

logger = logging.getLogger(__name__)


def get_or_create_vendor(vendor_name: Optional[str], db: Session) -> Optional[Vendor]:
    if not vendor_name:
        return None
    vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()
    if not vendor:
        vendor = Vendor(name=vendor_name)
        db.add(vendor)
        db.flush()  # get ID immediately
    return vendor


def save_or_update_cves(cve_objects: List[Dict]) -> bool:
    success = True
    failed_cves = []
    saved_cves = []
    with SessionLocal() as db:
        for item in cve_objects:
            cve_id = item.get("cve")
            try:
                stmt = insert(CVE).values(
                    cve_id=cve_id,
                    published=item.get("published_date"),
                    last_modified=item.get("modified_date"),
                    description=item.get("description"),
                    vuln_status=item.get("status"),
                    source=item.get("source"),
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[CVE.cve_id],
                    set_={
                        col.name: getattr(stmt.excluded, col.name)
                        for col in CVE.__table__.columns
                        if col.name != "cve_id"  # avoid overwriting PK
                    },
                )
                db.execute(stmt)

                # Get CVE object
                cve = db.scalar(select(CVE).where(CVE.cve_id == cve_id))
                if not cve:
                    logger.error(
                        "Failed to retrieve CVE after upsert", extra={"cve_id": cve_id}
                    )
                    failed_cves.append(cve_id)
                    continue

                # Process package and version info
                if not upsert_vulnerable_package_info(cve_id, item, db):
                    logger.error(
                        "Failed to save package info", extra={"cve_id": cve_id}
                    )
                    failed_cves.append(cve_id)
                    db.rollback()
                    continue

                if v2_data := item.get("cvss_v2", {}):
                    cvss_v2 = upsert_cvss_v2(cve_id, v2_data, db)

                    if not cvss_v2:
                        logger.error("Failed to save CVSS V2", extra={"cve": cve_id})
                        failed_cves.append(cve_id)
                        db.rollback()
                        continue

                if v31_data := item.get("cvss_v31", {}):
                    cvss_v31 = upsert_cvss_v31(cve_id, v31_data, db)

                    if not cvss_v31:
                        logger.error(
                            "Failed to save CVSS V31 for", extra={"cve": cve_id}
                        )
                        failed_cves.append(cve_id)
                        db.rollback()
                        continue

                db.commit()
                saved_cves.append(cve_id)
                logger.info("Successfully saved %s", cve_id)
            except IntegrityError:
                db.rollback()
                logger.exception("Duplicate CVE", extra={"cve_id": cve_id})
                success = False

            except SQLAlchemyError:
                db.rollback()
                logger.exception("Database Connection failed")
                success = False

            except Exception:
                db.rollback()
                logger.exception("Unexpected error occured")
                success = False

        logger.info("Successfully saved %s", len(saved_cves))
        if failed_cves:
            logger.error("Failed CVE count %s", len(failed_cves))
    return success


def upsert_vulnerable_package_info(cve: str, item: dict, db: Session) -> bool:
    for node in item.get("cpe_nodes", []):
        operator_value = node.get("operator")
        negate_value = node.get("negate")
        for pkg_entry in node.get("cpe_list", []):
            vendor_name = pkg_entry.get("vendor")
            vendor_obj = get_or_create_vendor(vendor_name, db)
            pkg_entry["operator"] = operator_value
            pkg_entry["negate"] = negate_value

            stmt = insert(VulnerablePackage).values(
                cve_id=cve,
                category=pkg_entry.get("category"),
                package_name=pkg_entry.get("package"),
                vendor_id=vendor_obj.id if vendor_obj else None,
                cpe_string=pkg_entry.get("criteria"),
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_vulnerable_package_cve_cpe",
                set_={
                    "category": stmt.excluded.category,
                    "package_name": stmt.excluded.package_name,
                    "vendor_id": stmt.excluded.vendor_id,
                    "cpe_string": stmt.excluded.cpe_string,
                },
            )
            db.execute(stmt)

            pkg = db.scalar(
                select(VulnerablePackage).where(
                    VulnerablePackage.cve_id == cve,
                    VulnerablePackage.cpe_string == pkg_entry.get("criteria"),
                )
            )

            if not has_version_info(pkg_entry):
                logger.info("No package version info", extra={"cve": cve})
                continue

            # Add VulnerableVersion
            if not save_package_version_info(pkg_entry, pkg, db):
                logger.error("Failed to save package info", extra={"cve": cve})
                return False
    return True


def has_version_info(pkg_entry):
    return any(
        pkg_entry.get(k) is not None
        for k in [
            "fixed_version",
            "including_version_start",
            "excluding_version_end",
            "including_version_end",
            "operator",
        ]
    )


def save_package_version_info(pkg_entry, pkg, db: Session) -> bool:
    stmt = insert(VulnerableVersion).values(
        package_id=pkg.id,
        fixed_version=pkg_entry.get("fixed_version"),
        including_version_start=pkg_entry.get("including_version_start"),
        excluding_version_end=pkg_entry.get("excluding_version_end"),
        including_version_end=pkg_entry.get("including_version_end"),
        operator=pkg_entry.get("operator"),
        negate=pkg_entry.get("negate", False),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[
            VulnerableVersion.package_id,
            text("COALESCE(fixed_version, '')"),
            text("COALESCE(including_version_start, '')"),
            text("COALESCE(excluding_version_end, '')"),
            text("COALESCE(including_version_end, '')"),
            text("COALESCE(operator, '')"),
        ],
        set_={
            col.name: getattr(stmt.excluded, col.name)
            for col in VulnerableVersion.__table__.columns
            if col.name not in ("id", "package_id")
        },
    )
    db.execute(stmt)
    return True
