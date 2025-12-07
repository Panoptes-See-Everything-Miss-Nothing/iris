import json
from utils.nvd_utils import create_version_dictionary


if __name__ == "__main__":
    file_path = "fixtures/nvdcve_2.0.json"
    data = None

    try:
        with open(file_path, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        print("Please check path correctly")

    if data:
        nvd_data = []
        for _ in data["vulnerabilities"]:
            cve_obj = _.get("cve")
            cve = cve_obj.get("id")
            if not cve:
                print("CVE not found. Skipping object")
                continue

            cve_object = {"cve": cve}
            cve_object.update(
                {
                    "source": cve_obj.get("sourceIdentifier"),
                    "published_date": cve_obj.get("published"),
                    "modified_date": cve_obj.get("lastModified"),
                    "status": cve_obj.get("vulnStatus"),
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

        output_file = "output.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            print(f"Data dumped in {output_file}")
    else:
        print("No data present")
