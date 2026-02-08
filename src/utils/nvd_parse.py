import json
from typing import Dict

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.utils.nvd_utils import (
    get_cpe_data,
    create_version_dictionary,
    convert_to_timestamptz,
)
from src.models.cve import CVE
from src.settings import SessionLocal


def read_from_json(file_path) -> str | None:
    print(f"Parsing {file_path}")
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
        print(f"Successfully parsed: {file_path}")
        return data
    except FileNotFoundError:
        print(f"Please check path correctly: {file_path}")
    except Exception as e:
        print(f"Could not parse file: {e}")


def write_to_json(nvd_data, file_path) -> str | None:
    try:
        print("Writing to file")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            print(f"Data dumped in {file_path}")
    except FileNotFoundError:
        print(f"Could not write to {file_path}")


def get_existing_cve_ids() -> Dict | None:
    """
    Fetch all existing CVE IDs from DB.
    Returns set of IDs or None on failure.
    """
    print("Fetching Existing CVEs")
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar()

            # Fetch IDs
            result = db.execute(select(CVE.cve_id, CVE.last_modified)).all()
            # dict: cve_id → last_modified (as string or datetime)
            existing_cves = {row[0]: row[1] for row in result if row[1] is not None}

            print(f"Found {len(existing_cves)} existing CVEs in DB")
            return existing_cves

    except (IntegrityError, SQLAlchemyError) as e:
        print(f"Database error while fetching existing CVEs: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error during DB check: {e}")
        return None


def parse_data(data) -> list | None:
    """
    Parses the data and check if cve exists, is updated and returns list of objects to be created as well as updated

    :param data: Description
    :return: Description
    :rtype: list[Any] | None
    """
    existing_cves = get_existing_cve_ids()

    if existing_cves is None:
        print("Database connection failed")
        return None

    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve_id = cve_obj.get("id")
        if not cve_id:
            print("CVE not found. Skipping object")
            continue

        feed_updated = cve_obj.get("lastModified")
        stored_modified = existing_cves.get(cve_id)
        should_process = False

        if stored_modified is None:
            should_process = True  # New CVE process it
        else:
            if not feed_updated:
                continue
            feed_updated = convert_to_timestamptz(feed_updated)
            if feed_updated > stored_modified:
                should_process = True  # Updated CVE based on data
            else:
                should_process = False  # Exists and updated already

        if not should_process:
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
