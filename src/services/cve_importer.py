from typing import Dict, List, Optional

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from src.models.cve import CVE
from src.models.vendor import Vendor
from src.models.vulnerable_package import VulnerablePackage
from src.models.vulnerable_version import VulnerableVersion
from src.models.cvss import CVSSv2, CVSSv31
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


def save_cves(cve_objects: List[Dict]) -> bool | None:
    """
    Adds new CVE records in DB also updates the existing records

    :param cve_objects: Description
    :type cve_objects: List[Dict]
    :return: Description
    :rtype: bool | None
    """
    if not cve_objects:
        print("No CVEs to save")
        return True

    with SessionLocal() as db:
        try:
            cve_values = []
            for item in cve_objects:
                cve_values.append(
                    {
                        "cve_id": item.get("cve"),
                        "published": item.get("published_date"),
                        "last_modified": item.get("modified_date"),
                        "description": item.get("description"),
                        "vuln_status": item.get("status"),
                        "source": item.get("source"),
                    }
                )

            if cve_values:
                stmt = insert(CVE).values(cve_values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["cve_id"],
                    set_={
                        "published": stmt.excluded.published,
                        "last_modified": stmt.excluded.last_modified,
                        "description": stmt.excluded.description,
                        "vuln_status": stmt.excluded.vuln_status,
                        "source": stmt.excluded.source,
                    },
                )
                db.execute(stmt)

            cvss_v2_values = []
            cvss_v31_values = []

            # CVSS v2 — use your parse function
            for item in cve_objects:
                cve_id = item.get("cve")

                if v2 := item.get("cvss_v2"):
                    cvss_v2_obj = parse_cvss_v2(cve_id, v2)
                    if cvss_v2_obj:
                        cvss_v2_values.append(CVSSv2(**cvss_v2_obj))

                if v3 := item.get("cvss_v3"):
                    cvss_v31_obj = parse_cvss_v3(cve_id, v3)
                    if cvss_v31_obj:
                        cvss_v31_values.append(CVSSv31(**cvss_v31_obj))

            if cvss_v2_values:
                db.bulk_save_objects(cvss_v2_values)

            if cvss_v31_values:
                db.bulk_save_objects(cvss_v31_values)

            vendor_cache = {}  # vendor_name → id

            for item in cve_objects:
                for node in item.get("cpe_nodes", []):
                    for pkg_entry in node.get("cpe", []):
                        vendor_name = pkg_entry.get("vendor")
                        if vendor_name and vendor_name not in vendor_cache:
                            vendor = get_or_create_vendor(vendor_name, db)
                            if vendor:
                                vendor_cache[vendor_name] = vendor.id

            # Delete old package & versions -> delete old->insert new
            cve_ids = [item.get("cve") for item in cve_objects if item.get("cve")]

            if cve_ids:
                # Delete old related data for these CVEs
                db.query(VulnerablePackage).filter(
                    VulnerablePackage.cve_id.in_(cve_ids)
                ).delete()
                db.query(VulnerableVersion).filter(
                    VulnerableVersion.package_id.in_(
                        db.query(VulnerablePackage.id).filter(
                            VulnerablePackage.cve_id.in_(cve_ids)
                        )
                    )
                ).delete(synchronize_session=False)

            package_values = []
            created_packages = []

            for item in cve_objects:
                cve_id = item.get("cve")

                for node in item.get("cpe_nodes", []):
                    for pkg_entry in node.get("cpe", []):
                        vendor_name = pkg_entry.get("vendor")
                        vendor_id = vendor_cache.get(vendor_name)

                        package = VulnerablePackage(
                            cve_id=cve_id,
                            category=pkg_entry.get("category"),
                            package_name=pkg_entry.get("package"),
                            vendor_id=vendor_id,
                            cpe_string=pkg_entry.get("cpe"),
                        )
                        package_values.append(package)
                        created_packages.append((package, pkg_entry))

            if package_values:
                db.bulk_save_objects(package_values)
                db.flush()  # Ensure package IDs are available

            # Create versions using correct package_id
            version_values = []

            for package_obj, pkg_entry in created_packages:
                if has_version_info(pkg_entry):
                    version_range = VulnerableVersion(
                        package_id=package_obj.id,
                        fixed_version=pkg_entry.get("fixed_version"),
                        including_version_start=pkg_entry.get(
                            "including_version_start"
                        ),
                        excluding_version_end=pkg_entry.get("excluding_version_end"),
                        including_version_end=pkg_entry.get("including_version_end"),
                        operator=pkg_entry.get("operator"),
                        negate=pkg_entry.get("negate", False),
                    )
                    version_values.append(version_range)

            if version_values:
                db.bulk_save_objects(version_values)

            db.commit()
            print(f"Successfully upserted {len(cve_objects)} CVEs + related data")
            return True

        except IntegrityError as e:
            db.rollback()
            print(f"Integrity error (constraint violation): {e.orig}")
            return False

        except SQLAlchemyError as e:
            db.rollback()
            print(f"Database error during bulk save: {e}")
            return False

        except Exception as e:
            db.rollback()
            print(f"Unexpected error during save: {e}")
            return False


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


def parse_cvss_v2(cve_id, v2):
    cvss_v2 = {
        "cve_id": cve_id,
        "base_score": v2.get("baseScore"),
        "base_severity": v2.get("baseSeverity"),
        "access_vector": v2.get("accessVector"),
        "access_complexity": v2.get("accessComplexity"),
        "authentication": v2.get("authentication"),
        "confidentiality_impact": v2.get("confidentialityImpact"),
        "integrity_impact": v2.get("integrityImpact"),
        "availability_impact": v2.get("availabilityImpact"),
        "exploitability_score": v2.get("exploitabilityScore"),
        "impact_score": v2.get("impactScore"),
        "vector_string": v2.get("vectorString"),
        # Flags
        "ac_insuf_info": v2.get("acInsufInfo"),
        "obtain_all_privilege": v2.get("obtainAllPrivilege"),
        "obtain_user_privilege": v2.get("obtainUserPrivilege"),
        "obtain_other_privilege": v2.get("obtainOtherPrivilege"),
        "user_interaction_required": v2.get("userInteractionRequired"),
    }
    # print("CVSS2", v2)
    return cvss_v2


def parse_cvss_v3(cve_id, v3):
    cvss_v3 = {
        "cve_id": cve_id,
        "base_score": v3.get("baseScore"),
        "base_severity": v3.get("baseSeverity"),
        "attack_vector": v3.get("attackVector"),
        "attack_complexity": v3.get("attackComplexity"),
        "privileges_required": v3.get("privilegesRequired"),
        "user_interaction": v3.get("userInteraction"),
        "scope": v3.get("scope"),
        "confidentiality_impact": v3.get("confidentialityImpact"),
        "integrity_impact": v3.get("integrityImpact"),
        "availability_impact": v3.get("availabilityImpact"),
        "exploitability_score": v3.get("exploitabilityScore"),
        "impact_score": v3.get("impactScore"),
        "vector_string": v3.get("vectorString"),
    }
    # print("CVSS3", v3)
    return cvss_v3
