import logging
import gzip
import shutil

from typing import List
from datetime import datetime

import requests

from src.settings import JSON_FEED_ROOT_URL, FIXTURES_DIR

logger = logging.getLogger(__name__)


def get_json_feed_files() -> List[str] | None:
    START_YEAR = 2002
    CURRENT_YEAR = datetime.now().year
    API_PREFIX = "nvdcve-2.0"
    API_SUFFIX = ".json.gz"
    file_paths = []

    for year in range(START_YEAR, CURRENT_YEAR + 1):
        try:
            download_file_url = f"{JSON_FEED_ROOT_URL}/{API_PREFIX}-{year}{API_SUFFIX}"
            download_zip_file(download_file_url, year)
            file_paths.append(download_file_url)
            break
        except Exception:
            logger.exception("Could not fetch file for year %s", year)
    return file_paths


def download_zip_file(file_url: str, year: int):
    logger.info("Downloading file %s", file_url)
    try:
        with requests.get(file_url, stream=True, timeout=60) as response:
            response.raise_for_status()
            json_file = f"{FIXTURES_DIR}/{year}.json"
            with gzip.GzipFile(fileobj=response.raw) as gz:
                with open(json_file, "wb") as f_out:
                    shutil.copyfileobj(gz, f_out)
    except Exception:
        logger.exception("Could not fetch file %s", file_url)
