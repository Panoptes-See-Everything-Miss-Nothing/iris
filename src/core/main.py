import asyncio
import logging
import os
from typing import Any

from src.utils.nvd_parser import read_from_json, read_from_nvd_api
from src.utils.nvd_feed_scraper import get_json_feed_files
from src.utils.cve_parser import parse_data
from src.crud.cve_importer import save_or_update_cves
from src.logger_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

_RUN_INTERVAL_HOURS = int(os.getenv("RUN_INTERVAL_HOURS", "2"))


def process_data(cve_objects: list[dict[str, Any]]):
    result = save_or_update_cves(cve_objects)

    if result:
        logger.info("Save successful")
    else:
        logger.error("Failed to save CVE objects")


def run_json_feed() -> None:
    logger.info("Running JSON parsing")

    json_feed_files = get_json_feed_files()
    if not json_feed_files:
        logger.error("No files to parse")
        return
    else:
        for file_path in json_feed_files:
            json_data = read_from_json(file_path)
            if json_data is None:
                logger.warning("Failed to read %s", file_path)
                continue

            cve_objects = parse_data(json_data)
            if cve_objects is None:
                logger.error("Parsing failed for %s", file_path)
            elif not cve_objects:
                logger.info("No new CVEs found in %s", file_path)
            else:
                process_data(cve_objects)
    logger.info("Running JSON Feed Completed")


async def run_api_feed() -> None:
    logger.info("Running API Feed")

    api_data = await read_from_nvd_api()
    if api_data is None:
        logger.error("No data from APIs")
        return
    else:
        cve_objects = parse_data(api_data)
        if cve_objects is None:
            logger.error("Parsing failed for API data")
        elif not cve_objects:
            logger.info("No new CVEs found")
        else:
            process_data(cve_objects)
    logger.info("Running API Feed Completed")


async def main() -> None:
    while True:
        logger.info("Pipeline run starting")
        run_json_feed()
        await run_api_feed()
        logger.info(
            "Pipeline run complete. Next run in %s hour(s)", _RUN_INTERVAL_HOURS
        )
        await asyncio.sleep(_RUN_INTERVAL_HOURS * 3600)


if __name__ == "__main__":
    logger.info("Execution started")
    asyncio.run(main())
