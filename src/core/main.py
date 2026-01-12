from src.utils.nvd_parse import read_from_json, parse_data
from src.services.cve_importer import save_cves

from src.settings import SessionLocal, FIXTURES_FILE


if __name__ == "__main__":
    data = read_from_json(FIXTURES_FILE)

    if data:
        cve_objects = parse_data(data)
        if not cve_objects:
            print(f"Could not parse {FIXTURES_FILE}")
        with SessionLocal() as db:
            if save_cves(cve_objects, db):
                print("Save successful")
    else:
        print("No data present")
