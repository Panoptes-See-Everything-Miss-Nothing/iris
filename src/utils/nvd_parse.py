import json

from src.utils.nvd_utils import get_cpe_data, create_version_dictionary


def read_from_json(file_path) -> str | None:
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"Please check path correctly: {file_path}")


def write_to_json(nvd_data, file_path) -> str | None:
    try:
        print("Writing to file")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            print(f"Data dumped in {file_path}")
    except FileNotFoundError:
        print(f"Could not write to {file_path}")


def parse_data(data) -> list:
    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve = cve_obj.get("id")
        if not cve:
            print("CVE not found. Skipping object")
            continue

        cve_object = {"cve": cve}
        if configurations := cve_obj.get("configurations"):
            if cve != "CVE-2014-0207":
                continue
            # print("CONFIG", configurations)
            cpe_data = get_cpe_data(configurations)
            if not cpe_data:
                print(f"Failed to fetch CPE data for {cve}")
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
            # import pprint

            # pprint.pp(cve_object)
        # else:
        #     print(f"No CPE data found for {cve}")
    return nvd_data
