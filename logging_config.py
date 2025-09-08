import logging
from logging.handlers import RotatingFileHandler
from config import APP_LOG_PATH


def setup_logging():
    logger = logging.getLogger()
    if logger.handlers:
        return logger  # already configured
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    # File handler (rotate at 1MB, keep 3 backups)
    file_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=1_000_000, backupCount=3)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    logger.info("Logging initialized -> %s", APP_LOG_PATH)
    return logger
