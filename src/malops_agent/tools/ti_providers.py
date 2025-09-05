# src/malops_agent/tools/ti_providers.py
from __future__ import annotations
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
import os, logging, requests,json
from ..logging_config import log_tool

DEFAULT_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12"))
ABUSEIPDB_MAX_AGE = int(os.getenv("ABUSEIPDB_MAX_AGE", "365"))

# --------------------------
# Providers (retorno FULL)
# --------------------------

def vt_lookup_full(sha256: str) -> Dict[str, Any]:
    """VirusTotal file lookup (full v3 JSON)."""
    key = os.getenv("VT_API_KEY", "").strip()
    if not key:
        return {"error": "VT_API_KEY not set"}
    if not sha256:
        return {"error": "empty sha256"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {"error": f"VT HTTP {r.status_code}", "text": r.text[:400]}
        return r.json()
    except Exception as e:
        return {"error": f"VT exception: {e}"}

def malwarebazaar_lookup_full(sha256: str) -> Dict[str, Any]:
    """MalwareBazaar hash lookup (full JSON)."""
    if not sha256:
        return {"error": "empty sha256"}
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {"error": f"MB HTTP {r.status_code}", "text": r.text[:400]}
        return r.json()
    except Exception as e:
        return {"error": f"MB exception: {e}"}

def threatfox_search_ioc(ioc: str) -> Dict[str, Any]:
    """
    ThreatFox single-IOC search (full JSON).
    ⚠️ Campo correto é 'search_term', não 'ioc'.
    """
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {"error": f"ThreatFox HTTP {r.status_code}", "text": r.text[:400]}
        return r.json()
    except Exception as e:
        return {"error": f"ThreatFox exception: {e}"}

def threatfox_bulk_full(
    urls: List[str] | None = None,
    domains: List[str] | None = None,
    ips: List[str] | None = None,
) -> Dict[str, Any]:
    """
    ThreatFox bulk: retorna um dicionário com listas separadas, preservando o JSON de cada consulta:
      {
        "urls":   [ <resp_json_por_url>   ... ],
        "domains":[ <resp_json_por_dom>   ... ],
        "ips":    [ <resp_json_por_ip>    ... ]
      }
    """
    urls = urls or []
    domains = domains or []
    ips = ips or []
    out: Dict[str, Any] = {"urls": [], "domains": [], "ips": []}
    try:
        for u in urls:
            out["urls"].append(threatfox_search_ioc(u))
        for d in domains:
            out["domains"].append(threatfox_search_ioc(d))
        for ip in ips:
            out["ips"].append(threatfox_search_ioc(ip))
        return out
    except Exception as e:
        return {"error": f"ThreatFox bulk exception: {e}"}

def abuseipdb_bulk_full(ips: List[str] | None) -> Dict[str, Any]:
    """AbuseIPDB bulk check (full JSON por IP)."""
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return {"error": "ABUSEIPDB_API_KEY not set"}
    out: Dict[str, Any] = {}
    try:
        for ip in (ips or []):
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": str(ABUSEIPDB_MAX_AGE)},
                headers={"Key": key, "Accept": "application/json"},
                timeout=DEFAULT_TIMEOUT,
            )
            if r.status_code != 200:
                out[ip] = {"error": f"AbuseIPDB HTTP {r.status_code}", "text": r.text[:400]}
            else:
                out[ip] = r.json()
        return out
    except Exception as e:
        return {"error": f"AbuseIPDB exception: {e}"}

# --------------------------
# LangChain Tools (fios finos)
# --------------------------

@tool
@log_tool("vt_lookup_tool")
def vt_lookup_tool(sha256: str) -> dict:
    """VirusTotal file lookup (full JSON)."""
    return vt_lookup_full(sha256)

@tool
@log_tool("malwarebazaar_lookup_tool")
def malwarebazaar_lookup_tool(sha256: str) -> dict:
    """MalwareBazaar hash lookup (full JSON)."""
    return malwarebazaar_lookup_full(sha256)

@tool
@log_tool("threatfox_bulk_search_tool")
def threatfox_bulk_search_tool(
    urls: list[str] | None = None,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
) -> dict:
    """ThreatFox bulk search (full JSON por IOC)."""
    return threatfox_bulk_full(urls=urls, domains=domains, ips=ips)

@tool
@log_tool("abuseipdb_bulk_check_tool")
def abuseipdb_bulk_check_tool(ips: list[str] | None = None) -> dict:
    """AbuseIPDB bulk check (full JSON por IP)."""
    return abuseipdb_bulk_full(ips or [])

# --------------------------
# Normalização (para o supervisor)
# --------------------------

def _normalize_all(
    vt: Dict[str, Any] | None,
    mb: Dict[str, Any] | None,
    tf: Dict[str, Any] | None,
    abuse: Dict[str, Any] | None,
    sha256: str,
) -> Dict[str, Any]:
    """
    Normaliza sem esconder os retornos completos, com tolerância a valores em string.
    Mantém JSONs integrais em `providers.*`.
    """

    def _as_dict(x: Any) -> Dict[str, Any]:
        if isinstance(x, dict):
            return x
        if isinstance(x, str):
            try:
                return json.loads(x)
            except Exception:
                return {}
        return {}

    def _as_list(x: Any) -> List[Any]:
        return x if isinstance(x, list) else []

    labels: List[str] = []
    refs: List[str] = []
    known_mal = None
    first_seen = None
    last_seen = None
    stats: Dict[str, Any] = {}

    # VT
    vt_d = _as_dict(vt)
    vt_attrs = _as_dict(vt_d.get("data", {})).get("attributes", {}) if isinstance(_as_dict(vt_d.get("data", {})).get("attributes", {}), dict) else _as_dict(vt_d.get("data", {})).get("attributes", {})
    if isinstance(vt_attrs, dict) and vt_attrs:
        las = _as_dict(vt_attrs.get("last_analysis_stats", {}))
        stats["virustotal"] = las
        try:
            mal_count = int(las.get("malicious", 0))
            known_mal = True if mal_count > 0 else (known_mal or False)
        except Exception:
            pass
        if isinstance(vt_attrs.get("tags"), list):
            labels.extend(vt_attrs["tags"])
        if isinstance(vt_attrs.get("names"), list):
            labels.extend(vt_attrs["names"][:5])
        refs.append(f"https://www.virustotal.com/gui/file/{sha256}")
        fs = vt_attrs.get("first_submission_date") or vt_attrs.get("times_submitted")
        if isinstance(fs, int) and not first_seen:
            first_seen = fs
        ls = vt_attrs.get("last_submission_date") or vt_attrs.get("last_analysis_date")
        if isinstance(ls, int):
            last_seen = max(last_seen or 0, ls)

    # MalwareBazaar
    mb_d = _as_dict(mb)
    if mb_d.get("query_status") == "ok":
        data = _as_list(mb_d.get("data"))
        if data:
            item = _as_dict(data[0])
            sig = item.get("signature")
            if sig: labels.append(sig)
            ftype = item.get("file_type")
            if ftype: labels.append(ftype)
            dl = item.get("download_url")
            if dl: refs.append(dl)
            fs = item.get("first_seen")
            if fs and not first_seen:
                first_seen = fs
            ls = item.get("last_seen")
            if ls:
                last_seen = ls

    # ThreatFox (tf = {"urls":[resp,...], "domains":[resp,...], "ips":[resp,...]})
    def _walk_tf_bucket(bucket: Any):
    # ✅ declare nonlocal no topo (antes de ler/escrever as variáveis)
        nonlocal first_seen, last_seen
        for resp in _as_list(bucket):
            rj = _as_dict(resp)
            rows = _as_list(rj.get("data"))
            for row in rows:
                rowd = _as_dict(row)
                tag = rowd.get("malware") or rowd.get("threat")
                if tag:
                    labels.append(tag)
                ref = rowd.get("reference")
                if ref:
                    refs.append(ref)
                fs = rowd.get("first_seen")
                if fs and not first_seen:
                    first_seen = fs  # string em ThreatFox (mantenha como está)
                ls = rowd.get("last_seen")
                if ls:
                    last_seen = ls

    tf_d = _as_dict(tf)
    _walk_tf_bucket(tf_d.get("urls"))
    _walk_tf_bucket(tf_d.get("domains"))
    _walk_tf_bucket(tf_d.get("ips"))

    # AbuseIPDB (abuse = { ip: <resp_json> })
    abuse_d = _as_dict(abuse)
    abuse_bad = False
    for ip, resp in abuse_d.items():
        rj = _as_dict(resp)
        data = _as_dict(rj.get("data"))
        score = data.get("abuseConfidenceScore")
        try:
            if int(score) >= 25:
                abuse_bad = True
                labels.append(f"abuseipdb_score_{score}:{ip}")
        except Exception:
            pass
        cc = data.get("countryCode")
        if cc:
            labels.append(f"country_{cc}:{ip}")
    if abuse_bad:
        known_mal = True if known_mal is None else (known_mal or True)

    labels = sorted({str(x) for x in labels if x})
    refs = sorted({str(x) for x in refs if x})

    return {
        "hash": sha256,
        "providers": {
            "virustotal": vt,
            "malwarebazaar": mb,
            "threatfox": tf,
            "abuseipdb": abuse,
        },
        "summary": {
            "known_malicious": bool(known_mal) if known_mal is not None else None,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "threat_labels": labels[:50],
            "references": refs[:50],
            "stats": stats,
        },
    }

