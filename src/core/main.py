from src.utils.nvd_parse import read_from_json, parse_data
from src.services.cve_importer import save_cves

from src.settings import FIXTURES_FILE


if __name__ == "__main__":
    data = read_from_json(FIXTURES_FILE)

    if not data:
        pass
    cve_objects = parse_data(data)

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
