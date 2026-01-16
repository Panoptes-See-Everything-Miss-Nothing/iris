from typing import Dict, List, Optional
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from src.models.cve import CVE
from src.models.vendor import Vendor
from src.models.vulnerable_package import VulnerablePackage
from src.models.vulnerable_version import VulnerableVersion

from .cvss_scores import parse_cvss_v2, parse_cvss_v3
from src.settings import SessionLocal


def get_or_create_vendor(vendor_name: Optional[str], db: Session) -> Optional[Vendor]:
    if not vendor_name:
        return None
    vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()
    if not vendor:
        vendor = Vendor(name=vendor_name)
        db.add(vendor)
        db.flush()  # get ID immediately
    return vendor


def save_cves(cve_objects: List[Dict]) -> bool:
    success = True
    with SessionLocal() as db:
        try:
            for item in cve_objects:
                cve = item.get("cve")
                if (
                    db.query(CVE).filter(CVE.cve_id == cve).first()
                ):  # skip if already exists
                    print(f"CVE {cve} already exists")
                    continue

                # Process CVE model data
                cve_obj = CVE(
                    cve_id=cve,
                    published=item.get("published_date"),
                    last_modified=item.get("modified_date"),
                    description=item.get("description"),
                    vuln_status=item.get("status"),
                    source=item.get("source"),
                )
                db.add(cve_obj)
                db.flush()  # Get cve.id immediately

                # Process VulnerablePackage data
                if not save_package_info(cve, item, db):
                    success = False
                    print("Failed to save package info")

                if not save_cvss_v2(cve, item.get("cvss_v2", {}), db):
                    print(f"Failed to save CVSS V2 score for {cve}")

                if not save_cvss_v3(cve, item.get("cvss_v3", {}), db):
                    print(f"Failed to save CVSS V2 score for {cve}")

                db.commit()
                print(f"Successfully saved {len(cve_objects)} CVEs")

        except IntegrityError as e:
            db.rollback()
            print(f"Integrity error while saving CVEs: {e.orig}")
            success = False

        except SQLAlchemyError as e:
            db.rollback()
            print(f"Database error: {e}")
            success = False

        except Exception as e:
            db.rollback()
            print(f"Unexpected error: {e}")
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
                print(f"{cve} has no package version info")
                return False

            # Add VulnerableVersion
            if not save_package_version_info(pkg_entry, pkg, db):
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


def save_cvss_v2(cve_id, v2, db):
    cvss_v2 = parse_cvss_v2(cve_id, v2)
    if cvss_v2:
        db.add(cvss_v2)
        print(f"Successfully save CVSS V2 score for {cve_id}")
        return True
    print(f"Failed to save CVSS V2 score for {cve_id}")


def save_cvss_v3(cve_id, v3, db):
    cvss_v3 = parse_cvss_v3(cve_id, v3)
    if cvss_v3:
        db.add(cvss_v3)
        print(f"Successfully save CVSS V2 score for {cve_id}")
        return True
    print(f"failed to save CVSS V2 score for {cve_id}")
