
import logging, os, sys

def get_logger(name: str, level: str | None = None) -> logging.Logger:
    lvl = (level or os.getenv("LOG_LEVEL") or "INFO").upper()
    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(lvl)
        return logger
    handler = logging.StreamHandler(stream=sys.stdout)
    fmt = logging.Formatter(fmt="%(asctime)s %(levelname)s %(name)s - %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(lvl)
    return logger
