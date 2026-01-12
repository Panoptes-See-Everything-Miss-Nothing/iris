import re


# def create_version_dictionary(data):
# source = data.get("source")

# cvss_data = data.get("cvssData")
# version = cvss_data.get("version")
# base_score = cvss_data.get("baseScore")
# access_vector = cvss_data.get("accessVector")
# access_complexity = cvss_data.get("accessComplexity")
# authentication = cvss_data.get("authentication")
# confidentiality_impact = cvss_data.get("confidentialityImpact")
# integrity_impact = cvss_data.get("integrityImpact")
# availability_impact = cvss_data.get("availabilityImpact")

# base_severity = data.get("baseSeverity")
# exploitabilityScore = data.get("exploitabilityScore")
# impactScoredata = data.get("impactScore")

# return {
#     "source": source,
#     "version": version,
#     "base_score": base_score,
#     "access_vector": access_vector.lower() if access_vector else None,
#     "access_complexity": access_complexity.lower() if access_complexity else None,
#     "authentication": authentication.lower() if authentication else None,
#     "confidentiality_impact": (
#         confidentiality_impact.lower() if confidentiality_impact else None
#     ),
#     "integrity_impact": integrity_impact.lower() if integrity_impact else None,
#     "availability_impact": (
#         availability_impact.lower() if availability_impact else None
#     ),
#     "base_severity": base_severity.lower() if base_severity else None,
#     "exploitabilityScore": exploitabilityScore,
#     "impactScoredata": impactScoredata,
# }
# return {
#     "source": source,
#     "base_score": base_score,
# }


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
        "cpe": criteria,
        "fixed_version": fixed_version,
        "category": category,
        "vendor": vendor,
        "package": package,
    }
