import json
from utils.nvd_utils import create_version_dictionary, get_cpe_data


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


def parse_data(data):
    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve = cve_obj.get("id")
        if not cve:
            print("CVE not found. Skipping object")
            continue

        cve_object = {"cve": cve}
        if configurations := cve_obj.get("configurations"):
            get_cpe_data(configurations)
        if cpe_matches := cve_object.get("cpeMatch"):
            for cpe in cpe_matches:
                cpe.append(
                    {
                        "vulnerable": cpe.get("vulnerable"),
                        "criteria": cpe.get("criteria"),
                    }
                )
        cve_object.update(
            {
                "source": cve_obj.get("sourceIdentifier"),
                "published_date": cve_obj.get("published"),
                "modified_date": cve_obj.get("lastModified"),
                "status": cve_obj.get("vulnStatus"),
                "description": next(
                    obj["value"]
                    for obj in cve_obj.get("descriptions")
                    if obj["lang"] == "en"
                ),
            }
        )

        metrics_dict = cve_obj.get("metrics", {})
        version_data = {}
        for version, entries in metrics_dict.items():
            if not entries:
                print("No version data available")

            version_dict = entries[0]
            version_data[version] = create_version_dictionary(version_dict)

        cve_object["version"] = version_data
        nvd_data.append(cve_object)
        return nvd_data


if __name__ == "__main__":
    file_path = "../fixtures/nvdcve_2.0.json"
    data = read_from_json(file_path)

    if data:
        cve_objects = parse_data(data)
        # output_file = "output.json"
        # write_to_json(cve_objects, output_file)
    else:
        print("No data present")
