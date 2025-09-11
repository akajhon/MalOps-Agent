import logging, time, sys
from functools import wraps
from typing import Callable, Any, Optional
from .config import get_settings

def configure_logging(level: Optional[str] = None, log_file: str = "malops.log"):
    """
    Configure global logging for the whole project.

    Receives `LOG_LEVEL` from settings if `level` is not provided.
    """
    lvl_name = (level or get_settings().get("LOG_LEVEL", "INFO")).upper()
    lvl = getattr(logging, lvl_name, logging.INFO)

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%d-%m-%Y %H:%M:%S"

    formatter = logging.Formatter(fmt, datefmt=datefmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(lvl)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(lvl)

    root_logger = logging.getLogger()
    root_logger.setLevel(lvl)

    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    logging.getLogger("agent").setLevel(lvl)
    logging.getLogger("tools").setLevel(lvl)
    logging.getLogger("api").setLevel(lvl)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)


def log_tool(name: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to add structured logging around tool functions.
    Logs start, args (truncated), duration, and errors under logger `tools.<name>`.
    """

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        log_name = f"tools.{name}" if name else f"tools.{getattr(func, '__name__', 'tool')}"
        log = logging.getLogger(log_name)

        def shorten(v: Any) -> Any:
            try:
                s = str(v)
            except Exception:
                return "<unrepr>"
            return (s if len(s) <= 300 else s[:297] + "...")

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.time()
            try:
                if kwargs:
                    log.debug("start args=%s kwargs=%s", shorten(args), {k: shorten(v) for k, v in kwargs.items()})
                else:
                    log.debug("start args=%s", shorten(args))
                out = func(*args, **kwargs)
                dur = (time.time() - start) * 1000.0
                log.info("done in %.1f ms", dur)
                return out
            except Exception as e:
                dur = (time.time() - start) * 1000.0
                log.exception("failed in %.1f ms: %s", dur, e)
                raise
        return wrapper

    return decorate
