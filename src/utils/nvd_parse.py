import json
from typing import Dict
from math import ceil
import requests

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.utils.nvd_utils import get_cpe_data, create_version_dictionary
from src.models.cve import CVE
from src.settings import SessionLocal


def read_from_json(file_path) -> Dict | None:
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"Please check path correctly: {file_path}")
    except Exception as e:
        print(f"Could not parse file: {e}")


def deco_time(func):
    from datetime import datetime

    def wrapper(*args, **kwargs):
        start = datetime.now()
        func(*args, **kwargs)
        print(f"Total Time taken: {datetime.now()-start}")

    return wrapper


# Sequential execution:
#   Total Records 273042
#   Total Time taken: 0:47:57.390410
#   With ~30 pages 429 error code


@deco_time
def read_from_nvd_api(base_url: str) -> Dict | None:
    print("Reading from API", base_url)
    start_index = 0
    page_size = 2000
    params = {"resultsPerPage": page_size, "startIndex": start_index}

    with requests.Session() as session:
        try:
            response = session.get(base_url, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Intial API call Failed: {e}")
            return

        data = response.json()
        vulnerabilities = []

        total_results = data.get("totalResults", 0)
        print(f"Total Records reported by API: {total_results}")

        if not total_results:
            return {"vulnerabilities": vulnerabilities}

        vulnerabilities.extend(data.get("vulnerabilities", []))

        page_count = ceil(total_results / page_size)
        print(f"Total pages {page_count}")

        for page in range(1, page_count):
            print(f"Fetching from page {page}/{page_count}")
            params["startIndex"] = page * page_size

            try:
                response = session.get(base_url, params=params)
                response.raise_for_status()
                data = response.json()
                vulnerabilities.extend(data.get("vulnerabilities", []))
            except requests.RequestException as e:
                print(f"Error Occured for page count{page}: {e}")
                continue

    print(f"Total Records {len(vulnerabilities)}")
    return {"vulnerabilities": vulnerabilities}


def write_to_json(nvd_data, file_path) -> str | None:
    try:
        print("Writing to file")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            print(f"Data dumped in {file_path}")
    except FileNotFoundError:
        print(f"Could not write to {file_path}")


def get_existing_cve_ids() -> set | None:
    """
    Fetch all existing CVE IDs from DB.
    Returns set of IDs or None on failure.
    """
    print("Fetching Existing CVEs")
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar()

            # Fetch IDs
            result = db.execute(select(CVE.cve_id)).all()
            existing_ids = {row[0] for row in result}

            print(f"Found {len(existing_ids)} existing CVEs in DB")
            return existing_ids

    except (IntegrityError, SQLAlchemyError) as e:
        print(f"Database error while fetching existing CVEs: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error during DB check: {e}")
        return None


def parse_data(data) -> list | None:
    existing_cves = get_existing_cve_ids()

    if existing_cves is None:
        print("Connot proceed database connection failed")
        return None

    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve_id = cve_obj.get("id")
        if not cve_id:
            print("CVE not found. Skipping object")
            continue

        if cve_id in existing_cves:
            print(f"{cve_id} already exists, skipping")
            continue

        cve_object = {"cve": cve_id}
        if configurations := cve_obj.get("configurations"):
            cpe_data = get_cpe_data(configurations)
            if not cpe_data:
                print(f"Failed to fetch CPE data for {cve_id}")
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
        else:
            print(f"No CPE data found for {cve_id}")
    return nvd_data
