import logging
import time
from functools import wraps
from typing import Callable, Any, Optional
from .config import get_settings

def configure_logging(level: Optional[str] = None) -> None:
    """Configure global logging for the whole project.

    Honors `LOG_LEVEL` from settings if `level` is not provided.
    """
    lvl_name = (level or get_settings().get("LOG_LEVEL", "INFO")).upper()
    lvl = getattr(logging, lvl_name, logging.INFO)

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%d-%m-%Y %H:%M:%S"

    logging.basicConfig(level=lvl, format=fmt, datefmt=datefmt, force=True)
    logging.getLogger("agent").setLevel(lvl)
    logging.getLogger("tools").setLevel(lvl)
    logging.getLogger("api").setLevel(lvl)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)


def log_tool(name: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to add structured logging around tool functions.

    Logs start, args (truncated), duration, and errors under logger `tools.<name>`.
    Works whether applied before or after LangChain's `@tool` wrapping.
    """

    def _decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        log_name = f"tools.{name}" if name else f"tools.{getattr(func, '__name__', 'tool')}"
        log = logging.getLogger(log_name)

        def _shorten(v: Any) -> Any:
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
                    log.debug("start args=%s kwargs=%s", _shorten(args), {k: _shorten(v) for k, v in kwargs.items()})
                else:
                    log.debug("start args=%s", _shorten(args))
                out = func(*args, **kwargs)
                dur = (time.time() - start) * 1000.0
                # Avoid dumping huge payloads
                log.info("done in %.1f ms", dur)
                return out
            except Exception as e:
                dur = (time.time() - start) * 1000.0
                log.exception("failed in %.1f ms: %s", dur, e)
                raise
        return wrapper

    return _decorate
