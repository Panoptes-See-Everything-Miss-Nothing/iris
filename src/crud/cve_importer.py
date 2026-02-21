import logging
from typing import Dict, List, Optional

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from src.models.cve import CVE
from src.models.vendor import Vendor
from src.models.vulnerable_package import VulnerablePackage
from src.models.vulnerable_version import VulnerableVersion
from .cvss_scores import parse_cvss_v2, parse_cvss_v3
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


def save_cves(cve_objects: List[Dict]) -> bool | None:
    success = True
    failed_cves = []
    saved_cves = []
    with SessionLocal() as db:
        try:
            for item in cve_objects:
                cve_id = item.get("cve")

                # Process CVE model data
                cve_obj = CVE(
                    cve_id=cve_id,
                    published=item.get("published_date"),
                    last_modified=item.get("modified_date"),
                    description=item.get("description"),
                    vuln_status=item.get("status"),
                    source=item.get("source"),
                )
                db.add(cve_obj)
                db.flush()  # Get cve.id immediately

                # Process VulnerablePackage data
                if not save_package_info(cve_id, item, db):
                    logger.error(
                        "Failed to save package info", extra={"cve_id": cve_id}
                    )
                    failed_cves.append(cve_id)
                    continue

                cvss_v2 = save_cvss_v2(cve_id, item.get("cvss_v2", {}))
                if not cvss_v2:
                    logger.error("Failed to save CVSS V2", extra={"cve": cve_id})
                    failed_cves.append(cve_id)
                    continue
                db.add(cvss_v2)
                cvss_v31 = save_cvss_v3(cve_id, item.get("cvss_v3", {}))

                if not cvss_v31:
                    logger.error("Failed to save CVSS V31 for", extra={"cve": cve_id})
                    failed_cves.append(cve_id)
                    continue
                db.add(cvss_v31)

                db.commit()
                saved_cves.append(cve_id)
                logger.info("Successfully saved %s", cve_id)

            logger.info("Successfully saved %s", len(saved_cves))
            if failed_cves:
                logger.error("Failed CVE count %s", len(failed_cves))
            return True

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
    return success


def save_package_info(cve: str | None, item: dict, db: Session) -> bool:
    for node in item.get("cpe_nodes", []):
        for pkg_entry in node.get("cpe", []):
            vendor_name = pkg_entry.get("vendor")
            vendor = get_or_create_vendor(vendor_name, db)

            pkg = VulnerablePackage(
                cve_id=cve,
                category=pkg_entry.get("category"),
                package_name=pkg_entry.get("package"),
                vendor_id=vendor.id if vendor else None,
                cpe_string=pkg_entry.get("cpe"),
            )
            db.add(pkg)
            db.flush()

            if not has_version_info:
                logger.info("No package version info", extra={"cve": cve})
                return False

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
    version_range = VulnerableVersion(
        package_id=pkg.id,
        fixed_version=pkg_entry.get("fixed_version"),
        including_version_start=pkg_entry.get("including_version_start"),
        excluding_version_end=pkg_entry.get("excluding_version_end"),
        including_version_end=pkg_entry.get("including_version_end"),
        operator=pkg_entry.get("operator"),
        negate=pkg_entry.get("negate", False),
    )
    db.add(version_range)
    return True


def save_cvss_v2(cve_id, v2):
    if cvss_v2 := parse_cvss_v2(cve_id, v2):
        return cvss_v2
    logger.error("Failed to save CVSS V2 score for %s", cve_id)


def save_cvss_v3(cve_id, v3):
    if cvss_v3 := parse_cvss_v3(cve_id, v3):
        return cvss_v3
    logger.error("Failed to save CVSS V2 score for %s", cve_id)
