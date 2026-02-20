import re
import logging
from typing import Dict, List

from .cve_vectors import (
    BaseSeverity,
    UserInteraction,
    AvailabilityImpact,
    AttackVector,
    PrivilegesRequired,
    AttackComplexity,
    IntegrityImpact,
    ConfedentialityImpact,
    AccessComplexity,
    Authentication,
    Scope,
    AccessVector,
)
from src.utils.nvd_parser import get_existing_cve_ids

logger = logging.getLogger(__name__)


def create_version_dictionary(cvss_obj_list: List[Dict]) -> Dict:
    cvss_obj = cvss_obj_list[0]
    cvss_data = cvss_obj.get("cvssData")
    result = {}

    if cvss_data:
        result["baseScore"] = cvss_data.get("baseScore")
        result["baseSeverity"] = BaseSeverity.from_raw(cvss_obj.get("baseSeverity"))
        result["attackVector"] = AttackVector.from_raw(
            AttackVector.from_raw(cvss_data.get("attackVector"))
        )
        result["attackComplexity"] = AttackComplexity.from_raw(
            cvss_data.get("attackComplexity")
        )
        result["privilegesRequired"] = PrivilegesRequired.from_raw(
            cvss_obj.get("privilegesRequired")
        )
        result["userInteraction"] = UserInteraction.from_raw(
            cvss_data.get("userInteraction")
        )
        result["scope"] = Scope.from_raw(cvss_data.get("scope"))
        result["confidentialityImpact"] = ConfedentialityImpact.from_raw(
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


def get_cpe_data(configurations):
    node_list = []
    for node in configurations:
        temp_dict = dict()
        for _ in node.get("nodes"):
            temp_dict["operator"] = _["operator"]
            temp_dict["negate"] = _["negate"]
            cpe_list = []

            for cpe in _.get("cpeMatch"):
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
                    "cpe": cpe_list,
                }
                node_list.append(temp_dict)
                # return temp_dict
            # pprint.pp(temp_dict)
    return node_list


def parse_fixed_version(criteria) -> dict | None:
    try:
        # if versionStartIncluding, versionEndExcluding, versionEndIncluding are not present,
        # package has fixed version in criteria
        fixed_version = None
        trimmed_criteria = re.sub("^cpe:\\d+.\\d+:|(:\\*)+", "", criteria)
        if version := re.search(r"\d+(?:\.\d+)*(?=:)", criteria):
            fixed_version = version.group()

        criteria_list = trimmed_criteria.split(":")
        category = criteria_list[0]
        vendor = criteria_list[1]
        package = criteria_list[2]

        return {
            "fixed_version": fixed_version,
            "cpe": criteria,
            "category": category,
            "vendor": vendor,
            "package": package,
        }
    except IndexError:
        logger.exception("Failed to parse criteria", extra={"criteria": criteria})


def parse_data(data) -> list | None:
    existing_cves = get_existing_cve_ids()

    if existing_cves is None:
        logger.error("Connot proceed database connection failed")
        return None

    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve_id = cve_obj.get("id")
        if not cve_id:
            logger.info("CVE not found. Skipping object")
            continue

        if cve_id in existing_cves:
            logger.info("CVE already exists, skipping", extra={"cve_id": cve_id})
            continue

        cve_object = {"cve": cve_id}
        if configurations := cve_obj.get("configurations"):
            cpe_data = get_cpe_data(configurations)
            if not cpe_data:
                logger.error("Failed to fetch CPE data for", extra={"cve_id": cve_id})
                continue

            cve_object.update(
                {
                    "source": cve_obj.get("sourceIdentifier"),
                    "published_date": cve_obj.get("published"),
                    "modified_date": cve_obj.get("lastModified"),
                    "status": (
                        cve_obj.get("vulnStatus").lower()
                        if cve_obj.get("vulnStatus")
                        else None
                    ),
                    "description": next(
                        obj["value"]
                        for obj in cve_obj.get("descriptions")
                        if obj["lang"] == "en"
                    ),
                }
            )
            metrics = cve_obj.get("metrics")
            if metrics:
                cvss_v2 = metrics.get("cvssMetricV2")
                if cvss_v2:
                    cve_object["cvss_v2"] = create_version_dictionary(cvss_v2)

                cvss_v3 = metrics.get("cvssMetricV31")
                if cvss_v3:
                    cve_object["cvss_v3"] = create_version_dictionary(cvss_v3)
            nvd_data.append(cve_object)

        else:
            logger.info(f"No CPE data found for {cve_id}")
    return nvd_data
