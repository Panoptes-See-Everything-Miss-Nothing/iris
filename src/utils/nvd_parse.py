import json
import asyncio
import aiohttp
from math import ceil
import logging
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.utils.nvd_utils import get_cpe_data, create_version_dictionary
from src.models.cve import CVE
from src.settings import SessionLocal, CVE_URL, FIXTURES_FILE, NVD_API_KEY

logger = logging.getLogger(__name__)


def read_from_json() -> Dict | None:
    try:
        with open(FIXTURES_FILE, "r") as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        logger.exception(
            "Please check path correctly", extra={"fixtures_file": FIXTURES_FILE}
        )
    except Exception:
        logger.exception("Could not parse file")


async def fetch_page(session: aiohttp.ClientSession, params: Dict, page: int) -> List:
    retries = 5
    backoff = 2
    for attempt in range(retries):
        try:
            async with session.get(CVE_URL, params=params) as response:
                if response.status == 429:
                    wait = backoff**attempt
                    await asyncio.sleep(wait)
                    continue

                response.raise_for_status()
                data = await response.json()
                logger.info(f"Fetched page {page}")
                return data.get("vulnerabilities", [])

        except aiohttp.ClientError:
            logger.exception("Error occured for page", extra={"page": page})
            return []
    logger.error("Failed after multiple retries", extra={"page": page})
    return []


async def read_from_nvd_api() -> Dict | None:
    logger.info("Reading from API", extra={"cve_url": CVE_URL})
    page_size = 2000

    header = {"apiKey": NVD_API_KEY}

    async with aiohttp.ClientSession(headers=header) as session:
        try:
            async with session.get(
                CVE_URL, params={"resultsPerPage": page_size, "startIndex": 0}
            ) as response:
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError:
            logger.exception("Intial API call Failed")
            return

        vulnerabilities = []
        total_results = data.get("totalResults", 0)
        logger.info("Total Records reported by API %s", total_results)

        if not total_results:
            return {"vulnerabilities": vulnerabilities}

        vulnerabilities.extend(data.get("vulnerabilities", []))

        page_count = ceil(total_results / page_size)
        logger.info("Total pages %s", page_count)

        tasks = []  # prepare concurrent tasks for remaining pages
        for page in range(1, page_count):
            logger.info("Fetching from page %s/%s", page, page_count)
            params = {"resultsPerPage": page_size, "startIndex": page * page_size}

            tasks.append(fetch_page(session, params, page))

        if tasks:
            results = await asyncio.gather(*tasks)
            for page_data in results:
                vulnerabilities.extend(page_data)

    logger.info("Total Records %s", len(vulnerabilities))
    return {"vulnerabilities": vulnerabilities}


def write_to_json(nvd_data, file_path) -> str | None:
    try:
        logger.info("Writing to file")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            logger.info("Data dumped in %s", file_path)
    except FileNotFoundError:
        logger.exception("Could not write to %s", file_path)


def get_existing_cve_ids() -> set | None:
    """
    Fetch all existing CVE IDs from DB.
    Returns set of IDs or None on failure.
    """
    logger.info("Fetching Existing CVEs")
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar()

            # Fetch IDs
            result = db.execute(select(CVE.cve_id)).all()
            existing_ids = {row[0] for row in result}

            logger.info("Found %s existing CVEs in DB", len(existing_ids))
            return existing_ids

    except (IntegrityError, SQLAlchemyError):
        logger.exception("Database error while fetching existing CVEs")
        return None
    except Exception:
        logger.exception("Unexpected error during DB check")
        return None


def parse_data(data) -> list | None:
    existing_cves = get_existing_cve_ids()

    if existing_cves is None:
        logger.error("Connot proceed database connection failed")
        return None

    nvd_data = []
    for _ in data["vulnerabilities"]:
        cve_obj = _.get("cve")
        cve_id = cve_obj.get("id")
        if not cve_id:
            logger.info("CVE not found. Skipping object")
            continue

        if cve_id in existing_cves:
            logger.info("CVE already exists, skipping", extra={"cve_id": cve_id})
            continue

        cve_object = {"cve": cve_id}
        if configurations := cve_obj.get("configurations"):
            cpe_data = get_cpe_data(configurations)
            if not cpe_data:
                logger.error("Failed to fetch CPE data for", extra={"cve_id": cve_id})
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
            logger.info(f"No CPE data found for {cve_id}")
    return nvd_data
