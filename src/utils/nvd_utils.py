import re
from typing import Dict, List

from .attack_vectors import (
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


def create_version_dictionary(cvss_obj_list: List[Dict]) -> Dict:
    cvss_obj = cvss_obj_list[0]
    cvss_data = cvss_obj.get("cvssData")
    result = {}

    if cvss_data:
        result["base_score"] = cvss_data.get("baseScore")
        result["base_severity"] = BaseSeverity.from_raw(
            cvss_obj.get("baseSeverity")
        )  # this calls from_raw()
        result["attack_vector"] = AttackVector.from_raw(
            AttackVector.from_raw(cvss_data.get("attackVector"))
        )
        result["attack_complexity"] = AttackComplexity.from_raw(
            cvss_data.get("attackComplexity")
        )
        result["privileges_required"] = PrivilegesRequired.from_raw(
            cvss_obj.get("privilegesRequired")
        )
        result["user_interaction"] = UserInteraction.from_raw(
            cvss_data.get("userInteraction")
        )
        result["scope"] = Scope.from_raw(cvss_data.get("scope"))
        result["confidentiality_impact"] = ConfedentialityImpact.from_raw(
            cvss_data.get("confidentialityImpact")
        )
        result["integrity_impact"] = IntegrityImpact.from_raw(
            cvss_data.get("integrityImpact")
        )
        result["availability_impact"] = AvailabilityImpact.from_raw(
            cvss_data.get("availabilityImpact")
        )
        result["authentication"] = Authentication.from_raw(
            cvss_data.get("authentication")
        )
        result["accessVector"] = AccessVector.from_raw(cvss_data.get("accessVector"))
        result["accessComplexity"] = AccessComplexity.from_raw(
            cvss_data.get("accessComplexity")
        )
        result["exploitability_score"] = cvss_obj.get("exploitabilityScore")
        result["impact_score"] = cvss_obj.get("impactScore")
        result["vector_string"] = cvss_data.get("vectorString")

    return result


def get_cpe_data(configurations):
    print("Getting CPE data")
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
                    cpe_dict.update(parse_fixed_version(criteria))
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


def parse_fixed_version(criteria) -> dict:
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
