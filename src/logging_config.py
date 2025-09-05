import logging
from config import get_settings

def configure_logging(level):
    """ Configura logging global para todo o projeto. """
    lvl_name = (level or get_settings().get("LOG_LEVEL", "INFO")).upper()
    lvl = getattr(logging, lvl_name, logging.INFO)

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%d-%m-%Y %H:%M:%S"

    logging.basicConfig(level=lvl, format=fmt, datefmt=datefmt, force=True)
    logging.getLogger("agent").setLevel(lvl)
    logging.getLogger("tools").setLevel(lvl)
    logging.getLogger("api").setLevel(lvl)