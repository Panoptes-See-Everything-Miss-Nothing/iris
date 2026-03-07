from concurrent.futures import ThreadPoolExecutor, as_completed
from gzip import GzipFile
import logging
import os
import tempfile

from typing import List
from datetime import datetime
import requests

from src.settings import JSON_FEED_ROOT_URL, FIXTURES_DIR, MAX_DECOMPRESSED_FEED_SIZE

logger = logging.getLogger(__name__)


def get_json_feed_files() -> List[str]:
    START_YEAR = 2002
    CURRENT_YEAR = datetime.now().year
    API_PREFIX = "nvdcve-2.0"
    API_SUFFIX = ".json.gz"
    file_paths = []
    years = range(START_YEAR, CURRENT_YEAR + 1)

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(
                download_zip_file,
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


def download_zip_file(file_url: str, year: int) -> str | None:
    json_file = f"{FIXTURES_DIR}/{year}.json"
    try:
        open(json_file, "x").close()  # atomic: fails if file already exists
    except FileExistsError:
        logger.info("File already exists, skipping %s", json_file)
        return json_file

    logger.info("Downloading file %s", file_url)
    temp_name = None
    try:
        with requests.Session() as session, session.get(
            file_url, stream=True, timeout=60
        ) as response:
            response.raise_for_status()
            response.raw.decode_content = True

            with GzipFile(fileobj=response.raw) as gz:
                with tempfile.NamedTemporaryFile(dir=FIXTURES_DIR, delete=False) as tmp:
                    temp_name = tmp.name
                    total_written = 0
                    chunk_size = 1024 * 1024
                    while chunk := gz.read(chunk_size):
                        total_written += len(chunk)
                        if total_written > MAX_DECOMPRESSED_FEED_SIZE:
                            raise ValueError(
                                f"Decompressed size for {file_url} exceeded "
                                f"{MAX_DECOMPRESSED_FEED_SIZE} bytes — aborting"
                            )
                        tmp.write(chunk)

        os.replace(temp_name, json_file)
        return json_file
    except Exception:
        logger.exception("Could not fetch file %s", file_url)
        if temp_name and os.path.exists(temp_name):
            os.remove(temp_name)
        if os.path.exists(json_file) and os.path.getsize(json_file) == 0:
            os.remove(json_file)
        return None
