from src.utils.nvd_parse import read_from_json, parse_data
from src.services.cve_importer import save_cves

from src.settings import FIXTURES_FILE


if __name__ == "__main__":
    data = read_from_json(FIXTURES_FILE)

    if data:
        cve_objects = parse_data(data)
        # print(cve_objects)
        if not cve_objects:
            print(f"Could not parse {FIXTURES_FILE}")
        save_cves(cve_objects)
        # if save_cves(cve_objects):
        #     print("Save successful")
        # else:
        #     print("Failed to save CVE objects")
    else:
        print("No data present")
