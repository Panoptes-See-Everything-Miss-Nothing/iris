import logging
import logging.config
from datetime import datetime

from .settings import LOG_DIR


LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(message)s",
        },
        "detailed": {
            "format": "%(asctime)s [%(levelname)s] "
            "%(filename)s:%(lineno)d - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{LOG_DIR}/app_{datetime.now().strftime("%d-%m-%Y_%H:%M")}.log",
            "maxBytes": 5 * 1024 * 1024,  # 5MB
            "backupCount": 5,
            "formatter": "detailed",
            "level": "INFO",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "DEBUG",
    },
}


def setup_logging():
    logging.config.dictConfig(LOGGING_CONFIG)
