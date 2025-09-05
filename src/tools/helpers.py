# src/malops_agent/tools/helpers.py
from __future__ import annotations
import os, re, json, logging, requests
from typing import Any, Dict, Optional
from dotenv import load_dotenv
from __future__ import annotations
import logging
from typing import Optional

log = logging.getLogger("tools.helpers")

_CURRENT_FILE: Optional[str] = None

def set_current_file(path: str) -> None:
    global _CURRENT_FILE
    _CURRENT_FILE = path
    log.info("Current file set to: %s", path)

def get_current_file() -> str:
    if not _CURRENT_FILE:
        raise RuntimeError(
            "Arquivo alvo não definido. Chame helpers.set_current_file(path) antes de usar as tools."
        )
    return _CURRENT_FILE

# Carrega .env uma única vez (idempotente)
load_dotenv(override=False)

def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

def env_float(name: str, default: float) -> float:
    try:
        return float(env_str(name, str(default)))
    except Exception:
        return default

def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 12.0, params: Optional[Dict[str, str]] = None):
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout, params=params)
        return r.status_code, r.text, safe_json(r)
    except Exception as e:
        return 599, str(e), {"error": f"GET exception: {e}"}

def http_post(url: str, data: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None, timeout: float = 12.0):
    try:
        r = requests.post(url, data=data, json=json_body, headers=headers or {}, timeout=timeout)
        return r.status_code, r.text, safe_json(r)
    except Exception as e:
        return 599, str(e), {"error": f"POST exception: {e}"}

def safe_json(resp) -> Dict[str, Any]:
    try:
        return resp.json()  # type: ignore[attr-defined]
    except Exception:
        try:
            return json.loads(getattr(resp, "text", "") or "{}")
        except Exception:
            return {}

# Detecção simples de tipo de IOC (suficiente para rotear chamadas)
IOC_HASH_RE = re.compile(r"^[A-Fa-f0-9]{64}$")      # sha256
IOC_MD5_RE  = re.compile(r"^[A-Fa-f0-9]{32}$")
IOC_IP_RE   = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IOC_URL_RE  = re.compile(r"^https?://", re.IGNORECASE)
IOC_DOM_RE  = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if IOC_HASH_RE.match(v):
        return "sha256"
    if IOC_MD5_RE.match(v):
        return "md5"
    if IOC_IP_RE.match(v):
        return "ip"
    if IOC_URL_RE.match(v):
        return "url"
    if IOC_DOM_RE.match(v):
        return "domain"
    return "unknown"
