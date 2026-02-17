import sys

from src.utils.nvd_parse import read_from_nvd_api, parse_data
from src.services.cve_importer import save_cves

from src.settings import CVE_URL


if __name__ == "__main__":
    combined_data = dict()

    # json_data = read_from_json(FIXTURES_FILE)
    # if json_data:
    #     combined_data.update(json_data)

    api_data = read_from_nvd_api(CVE_URL)
    if api_data:
        combined_data.update(api_data)

    if not combined_data:
        print("No data to parse")
        sys.exit(1)

    cve_objects = parse_data(combined_data)
    cve_objects = []
    if not cve_objects:
        print("No new CVEs found")
    else:
        result = save_cves(cve_objects)
        if result:
            print("Save successful")
        elif result is None:
            print("No data present")
        else:
            print("Failed to save CVE objects")
