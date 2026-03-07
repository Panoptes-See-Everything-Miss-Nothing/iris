import re
import logging
from typing import Dict, List

from src.settings import CVE_REJECTED

from .cve_vectors import (
    BaseSeverity,
    UserInteraction,
    AvailabilityImpact,
    AttackVector,
    PrivilegesRequired,
    AttackComplexity,
    IntegrityImpact,
    ConfidentialityImpact,
    AccessComplexity,
    Authentication,
    Scope,
    AccessVector,
)
from src.crud.cve_lookup import get_existing_cve_ids, is_updated
from src.utils.nvd_parser import parse_datetime

logger = logging.getLogger(__name__)


def create_version_dictionary(cvss_obj_list: List[Dict]) -> Dict:
    cvss_obj = cvss_obj_list[0]
    cvss_data = cvss_obj.get("cvssData")
    result = {}

    if cvss_data:
        result["baseScore"] = cvss_data.get("baseScore")
        result["baseSeverity"] = BaseSeverity.from_raw(
            cvss_data.get("baseSeverity") or cvss_obj.get("baseSeverity")
        )
        result["attackVector"] = AttackVector.from_raw(cvss_data.get("attackVector"))
        result["attackComplexity"] = AttackComplexity.from_raw(
            cvss_data.get("attackComplexity")
        )
        result["privilegesRequired"] = PrivilegesRequired.from_raw(
            cvss_data.get("privilegesRequired") or cvss_obj.get("privilegesRequired")
        )
        result["userInteraction"] = UserInteraction.from_raw(
            cvss_data.get("userInteraction")
        )
        result["scope"] = Scope.from_raw(cvss_data.get("scope"))
        result["confidentialityImpact"] = ConfidentialityImpact.from_raw(
            cvss_data.get("confidentialityImpact")
        )
        result["integrityImpact"] = IntegrityImpact.from_raw(
            cvss_data.get("integrityImpact")
        )
        result["availabilityImpact"] = AvailabilityImpact.from_raw(
            cvss_data.get("availabilityImpact")
        )
        result["authentication"] = Authentication.from_raw(
            cvss_data.get("authentication")
        )
        result["accessVector"] = AccessVector.from_raw(cvss_data.get("accessVector"))
        result["accessComplexity"] = AccessComplexity.from_raw(
            cvss_data.get("accessComplexity")
        )
        result["exploitabilityScore"] = cvss_obj.get("exploitabilityScore")
        result["impactScore"] = cvss_obj.get("impactScore")
        result["vectorString"] = cvss_data.get("vectorString")

    return result


def get_cpe_data(configurations: List[Dict]) -> List:
    node_list = []
    for node in configurations:
        temp_dict = dict()
        for _ in node.get("nodes", []):
            temp_dict["operator"] = _["operator"]
            temp_dict["negate"] = _["negate"]
            cpe_list = []

            for cpe in _.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    criteria = cpe.get("criteria")
                    cpe_dict = {
                        "including_version_start": cpe.get("versionStartIncluding"),
                        "excluding_version_end": cpe.get("versionEndExcluding"),
                        "including_version_end": cpe.get("versionEndIncluding"),
                    }
                    result = parse_fixed_version(criteria)
                    if result:
                        cpe_dict.update(result)
                        cpe_list.append(cpe_dict)

            if cpe_list:
                temp_dict = {
                    "operator": _["operator"],
                    "negate": _["negate"],
                    "cpe_list": cpe_list,
                }
                node_list.append(temp_dict)
    return node_list


def parse_fixed_version(criteria) -> dict | None:
    # if versionStartIncluding, versionEndExcluding, versionEndIncluding are not present,
    # package has fixed version in criteria
    fixed_version = None
    try:
        trimmed_criteria = re.sub("^cpe:\\d+\\.\\d+:|(:\\*)+", "", criteria)

        criteria_list = trimmed_criteria.split(":")
        category = criteria_list[0]
        vendor = criteria_list[1]
        package = criteria_list[2]

        if len(criteria_list) > 3:
            raw_ver = criteria_list[3]
            if raw_ver and raw_ver not in ("*", "-"):
                fixed_version = raw_ver

        return {
            "fixed_version": fixed_version,
            "criteria": criteria,
            "category": category,
            "vendor": vendor,
            "package": package,
        }
    except IndexError:
        logger.exception("Failed to parse criteria", extra={"criteria": criteria})


def parse_data(data: Dict) -> list[Dict] | None:
    """Parse file/API and return CVEs that are either new or need updating."""

    existing_cves = get_existing_cve_ids()

    if existing_cves is None:
        logger.error("Cannot proceed database connection failed")
        return None

    nvd_data = []
    for _ in data.get("vulnerabilities", []):
        cve_obj = _.get("cve")
        cve_id = re.sub(r"[\x00-\x1f\x7f]", "", cve_obj.get("id") or "")
        if not cve_id:
            logger.info("CVE not found. Skipping object")
            continue

        if cve_id in existing_cves:
            if not is_updated(cve_obj, existing_cves):
                logger.info("CVE already exists, skipping %s", cve_id)
                continue

        if cve_object := parse_object(cve_obj):
            nvd_data.append(cve_object)
    return nvd_data


def parse_object(cve_obj: Dict) -> Dict | None:
    cve_id = re.sub(r"[\x00-\x1f\x7f]", "", cve_obj.get("id") or "")
    parsed_cve_object = {"cve": cve_id}

    try:
        vuln_status = cve_obj.get("vulnStatus")
        if vuln_status is not None and vuln_status == CVE_REJECTED:
            logger.warning("%s is Rejected", cve_id)
            return None

        if configurations := cve_obj.get("configurations"):
            cpe_data = get_cpe_data(configurations)
            if not cpe_data:
                logger.error("Failed to fetch CPE data for", extra={"cve_id": cve_id})
                return None

            description = next(
                (
                    obj["value"]
                    for obj in cve_obj.get("descriptions", [])
                    if obj["lang"] == "en"
                ),
                None,
            )
            if description is None:
                logger.warning("No English description found for %s", cve_id)

            parsed_cve_object.update(
                {
                    "cpe_nodes": cpe_data,
                    "source": cve_obj.get("sourceIdentifier"),
                    "published_date": parse_datetime(cve_obj.get("published")),
                    "modified_date": parse_datetime(cve_obj.get("lastModified")),
                    "status": vuln_status,
                    "description": description,
                }
            )
            metrics = cve_obj.get("metrics", {})
            if metrics:
                if cvss_v2 := metrics.get("cvssMetricV2"):
                    parsed_cve_object["cvss_v2"] = create_version_dictionary(cvss_v2)

                if cvss_v31 := metrics.get("cvssMetricV31"):
                    parsed_cve_object["cvss_v31"] = create_version_dictionary(cvss_v31)
            else:
                logger.info("No CVSS metrics for %s", cve_id)

            return parsed_cve_object

        logger.error("Could not find configuration information of %s", cve_id)
    except Exception:
        logger.exception("Could not parse %s", cve_id)
        return None
