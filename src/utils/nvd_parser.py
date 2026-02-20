import json
import asyncio
import aiohttp
import logging
from math import ceil
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from src.models.cve import CVE
from src.utils.nvd_feed_scraper import get_json_feed_files
from src.settings import SessionLocal, CVE_URL, NVD_API_KEY

logger = logging.getLogger(__name__)


def read_from_json() -> Dict | None:
    file_paths = get_json_feed_files()
    all_data = {}
    if file_paths:
        for file in file_paths:
            try:
                with open(file, "r") as file:
                    data = json.load(file)
                    all_data.update(data)
            except FileNotFoundError:
                logger.exception("Please check path correctly")
            except Exception:
                logger.exception("Could not parse file %s", file)
        return all_data
    logger.error("No files to parse")


def write_to_json(nvd_data, file_path) -> str | None:
    try:
        logger.info("Writing to file")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(nvd_data, f, indent=4, ensure_ascii=False)
            logger.info("Data dumped in %s", file_path)
    except FileNotFoundError:
        logger.exception("Could not write to %s", file_path)


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
