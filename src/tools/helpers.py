from __future__ import annotations
import re, json, logging, requests, os, math
from typing import List
from typing import Any, Dict, Optional

log = logging.getLogger("tools.helpers")

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
        return resp.json()
    except Exception:
        try:
            txt = getattr(resp, "text", "") or "{}"
            return json.loads(txt)
        except Exception:
            log.debug("safe_json: could not parse JSON; returning empty dict")
            return {}

# Simple IOC Detection
IOC_HASH_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
IOC_MD5_RE  = re.compile(r"^[A-Fa-f0-9]{32}$")
IOC_IP_RE   = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IOC_DOM_RE  = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
IOC_URL_RE  = re.compile(r"^https?://", re.I)

def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if IOC_URL_RE.match(v):
        return "url"
    if IOC_HASH_RE.match(v):
        return "sha256"
    if IOC_MD5_RE.match(v):
        return "md5"
    if IOC_IP_RE.match(v):
        return "ip"
    if IOC_DOM_RE.match(v):
        return "domain"
    return "unknown"

def file_exists(p: str) -> bool:
    return os.path.isfile(p)

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    ln2 = math.log(2)
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * (math.log(p) / ln2)
    return round(ent, 3)

def get_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    pat = re.compile(rb"[ -~]{%d,}" % min_len)
    return [s.decode("ascii", errors="ignore") for s in pat.findall(data)]

def sniff_header(data: bytes) -> str:
    if len(data) >= 2 and data[:2] == b"MZ":
        return "PE"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "ELF"
    return "Unknown"

def defang_ioc(s: str) -> str:
    """
    Normalize common defanged indicators in a string.
    Examples: hxxp -> http, [.] -> ., (.) -> ., {.} -> .
    """
    try:
        t = s
        t = t.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("hxxp:", "http:")
        t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("(dot)", ".").replace("[dot]", ".")
        return t
    except Exception:
        return s