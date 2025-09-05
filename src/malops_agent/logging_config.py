# src/malops_agent/logging_utils.py
from __future__ import annotations
import os, json, time, base64
from typing import Any, Callable, Dict
from functools import wraps
from .logging_tool import get_logger

LOG = get_logger("malops.logging")

_TRUNC = int(os.getenv("LOG_TRUNC", "4000"))

_REDACT_KEYS = {"api_key", "apikey", "x-apikey", "authorization", "token", "password", "secret", "key"}

def _redact_in_mapping(m: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in m.items():
        if str(k).lower() in _REDACT_KEYS:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out

class _SafeEncoder(json.JSONEncoder):
    def default(self, o: Any):
        if isinstance(o, (bytes, bytearray)):
            # Mostra só tamanho (evita despejar payload binário)
            return f"<bytes:{len(o)}>"
        return str(o)

def safe_dump(obj: Any, limit: int | None = None) -> str:
    """Serializa obj em JSON seguro e truncado."""
    limit = limit or _TRUNC
    try:
        txt = json.dumps(obj, ensure_ascii=False, cls=_SafeEncoder)
    except Exception:
        try:
            txt = json.dumps(str(obj))  # último recurso
        except Exception:
            txt = "<unserializable>"
    if len(txt) > limit:
        return txt[:limit] + f"... (truncated {len(txt)-limit} chars)"
    return txt

def log_tool(name: str) -> Callable:
    """Decorator para Tools: loga saída (e entrada com secrets redigidos)."""
    def deco(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                if kwargs:
                    LOG.debug("[tool:%s] kwargs=%s", name, safe_dump(_redact_in_mapping(kwargs)))
                else:
                    LOG.debug("[tool:%s] args=%s", name, safe_dump(args))
            except Exception:
                pass
            t0 = time.time()
            out = fn(*args, **kwargs)
            dt = (time.time() - t0) * 1000.0
            LOG.info("[tool:%s] done in %.1fms | output=%s", name, dt, safe_dump(out))
            return out
        return wrapper
    return deco

def log_node(name: str) -> Callable:
    """Decorator para nós do LangGraph: loga saída do nó (patch do estado)."""
    def deco(fn: Callable):
        @wraps(fn)
        def wrapper(state: Dict[str, Any], *args, **kwargs):
            LOG.debug("[node:%s] start", name)
            t0 = time.time()
            out = fn(state, *args, **kwargs)
            dt = (time.time() - t0) * 1000.0
            LOG.info("[node:%s] patch=%s | %.1fms", name, safe_dump(out), dt)
            return out
        return wrapper
    return deco
