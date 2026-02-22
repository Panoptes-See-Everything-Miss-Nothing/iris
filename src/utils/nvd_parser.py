import json
import asyncio
import aiohttp
import logging
from math import ceil
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.settings import CVE_URL, NVD_API_KEY

logger = logging.getLogger(__name__)


def read_from_json(file_path: str) -> List[Dict] | None:
    try:
        with open(file_path, "r") as fobj:
            data = json.load(fobj)
        return data
    except FileNotFoundError:
        logger.exception("Please check path correctly")
    except Exception:
        logger.exception("Could not parse file %s", file_path)
    return None


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
                return data.get("vulnerabilities", [])

        except aiohttp.ClientError:
            logger.exception("Error occured for page", extra={"page": page})
            return []
    logger.error("Failed after multiple retries", extra={"page": page})
    return []


async def read_from_nvd_api() -> Dict | None:
    logger.info("Reading from API %s", CVE_URL)
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

        total_results = data.get("totalResults", 0)
        logger.info("Total Records reported by API %s", total_results)

        if not total_results:
            return {"vulnerabilities": []}

        vulnerabilities = []
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


def parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse NVD-style datetime string safely and ensure UTC-aware."""
    if not dt_str:
        return None

    dt_str = dt_str.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(dt_str)
    except ValueError:
        return None

    # Ensure timezone-aware (force UTC if missing)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)
