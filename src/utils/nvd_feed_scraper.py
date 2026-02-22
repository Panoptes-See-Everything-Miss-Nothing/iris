from asyncio import as_completed
from concurrent.futures import ThreadPoolExecutor
import logging
import gzip
import os
import shutil
import tempfile

from typing import List
from datetime import datetime
import requests

from src.settings import JSON_FEED_ROOT_URL, FIXTURES_DIR

logger = logging.getLogger(__name__)


def get_json_feed_files() -> List[str]:
    START_YEAR = 2002
    CURRENT_YEAR = datetime.now().year
    API_PREFIX = "nvdcve-2.0"
    API_SUFFIX = ".json.gz"
    file_paths = []
    years = range(START_YEAR, CURRENT_YEAR + 1)

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    download_zip_file,
                    session,
                    f"{JSON_FEED_ROOT_URL}/{API_PREFIX}-{year}{API_SUFFIX}",
                    year,
                ): year
                for year in years
            }

            for future in as_completed(futures):
                year = futures[future]
                try:
                    if file_path := future.result():
                        file_paths.append(file_path)
                except Exception:
                    logger.exception("Could not fetch file for year %s", year)
    return file_paths


def download_zip_file(
    session: requests.Session, file_url: str, year: int
) -> str | None:
    json_file = f"{FIXTURES_DIR}/{year}.json"
    if os.path.exists(json_file):
        logger.info("File already exists, skipping %s", json_file)
        return json_file

    logger.info("Downloading file %s", file_url)
    try:
        with session.get(file_url, stream=True, timeout=60) as response:
            response.raise_for_status()
            response.raw.decode_content = True

            with gzip.GzipFile(fileobj=response.raw) as gz:
                with tempfile.NamedTemporaryFile(dir=FIXTURES_DIR, delete=False) as tmp:
                    shutil.copyfileobj(gz, tmp, length=1024 * 1024)
                    temp_name = tmp.name

        os.replace(temp_name, json_file)
        return json_file
    except Exception:
        logger.exception("Could not fetch file %s", file_url)
        return None
