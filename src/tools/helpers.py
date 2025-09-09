from __future__ import annotations
# src/tools/helpers.py
import os
import re
import json
import logging
import requests
from typing import Any, Dict, Optional
from ..config import load_env

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

# Carrega .env uma única vez (idempotente) a partir da raiz do projeto
load_env()

def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

def env_float(name: str, default: float) -> float:
    try:
        return float(env_str(name, str(default)))
    except Exception:
        return default

def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 12.0, params: Optional[Dict[str, str]] = None):
    log.debug("HTTP GET %s params=%s", url, params)
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout, params=params)
        log.info("HTTP GET %s -> %s", url, r.status_code)
        return r.status_code, r.text, safe_json(r)
    except Exception as e:
        log.exception("HTTP GET %s failed: %s", url, e)
        return 599, str(e), {"error": f"GET exception: {e}"}

def http_post(url: str, data: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None, timeout: float = 12.0):
    log.debug("HTTP POST %s data_keys=%s json_keys=%s", url, list((data or {}).keys()), list((json_body or {}).keys()))
    try:
        r = requests.post(url, data=data, json=json_body, headers=headers or {}, timeout=timeout)
        log.info("HTTP POST %s -> %s", url, r.status_code)
        return r.status_code, r.text, safe_json(r)
    except Exception as e:
        log.exception("HTTP POST %s failed: %s", url, e)
        return 599, str(e), {"error": f"POST exception: {e}"}

def safe_json(resp) -> Dict[str, Any]:
    try:
        return resp.json()  # type: ignore[attr-defined]
    except Exception:
        try:
            txt = getattr(resp, "text", "") or "{}"
            return json.loads(txt)
        except Exception:
            log.debug("safe_json: could not parse JSON; returning empty dict")
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
