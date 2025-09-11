from __future__ import annotations
from typing import Dict, Any, List
from ..config import get_settings
from .helpers import http_get, http_post, detect_ioc_type

DEFAULT_TIMEOUT = get_settings().get("DEFAULT_TIMEOUT", 12)
VT_API_KEY  = get_settings().get("VT_API_KEY", "")
OTX_API_KEY = get_settings().get("OTX_API_KEY", "")
HA_API_KEY  = get_settings().get("HA_API_KEY", "")
ABUSE_KEY   = get_settings().get("ABUSE_API_KEY", "")

def vt_lookup(sha256: str) -> Dict[str, Any]:
    """VirusTotal file lookup."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    if not sha256:
        return {"error": "empty sha256"}
    status, txt, js = http_get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY},
        timeout=DEFAULT_TIMEOUT
    )
    if status != 200:
        return {"error": f"VT HTTP {status}", "text": txt[:400]}
    return js

def malwarebazaar_lookup(hash_value: str) -> Dict[str, Any]:
    """MalwareBazaar Hash Lookup (md5/sha1/sha256)."""
    if not ABUSE_KEY:
        return {"error": "ABUSE_API_KEY not set"}
    if not hash_value:
        return {"error": "empty hash"}
    st, txt, js = http_post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": hash_value},
        headers={"Auth-Key": ABUSE_KEY},
        timeout=DEFAULT_TIMEOUT,
    )
    if st != 200:
        return {"error": f"MB HTTP {st}", "text": (txt or "")[:400]}
    return js

def otx_query_ioc(ioc: str) -> Dict[str, Any]:
    """AlienVault OTX Lookup (Hash, Domain and IP)"""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}
    ioc_type = detect_ioc_type(ioc)
    base = "https://otx.alienvault.com/api/v1/indicators"
    if ioc_type in ("sha256", "md5"):
        path = f"/file/{ioc}/general"
    elif ioc_type == "ip":
        path = f"/IPv4/{ioc}/general"
    elif ioc_type == "domain":
        path = f"/domain/{ioc}/general"
    else:
        return {"error": f"unsupported ioc type: {ioc_type}"}

    st, txt, js = http_get(
        base + path,
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        timeout=DEFAULT_TIMEOUT
    )
    if st != 200:
        return {"error": f"OTX HTTP {st}", "text": txt[:400], "type": ioc_type}
    return js

def hybrid_analysis_lookup(sha256: str) -> Dict[str, Any]:
    """Hybrid Analysis Sandbox Lookup (SHA256)"""
    if not HA_API_KEY:
        return {"error": "HA_API_KEY not set"}
    if not sha256:
        return {"error": "empty sha256"}

    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }

    url = f"https://hybrid-analysis.com/api/v2/overview/{sha256}"
    st, txt, js = http_get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if st != 200:
        return {"error": f"HA HTTP {st}", "text": txt[:400]}
    return js

def normalize_hash(vt: Dict[str, Any] | None,
                   mb: Dict[str, Any] | None,
                   ha: Dict[str, Any] | None,
                   otx: Dict[str, Any] | None,
                   sha256: str) -> Dict[str, Any]:
    """Simple JSON Normalization"""
    labels: List[str] = []
    refs: List[str] = []
    known_mal = None

    # VirusTotal tags/basics
    try:
        attrs = (vt or {}).get("data", {}).get("attributes", {})
        tags = attrs.get("tags") or []
        labels.extend([str(t) for t in tags][:20])
        if "last_analysis_stats" in attrs:
            mal = int(attrs["last_analysis_stats"].get("malicious", 0))
            known_mal = (mal > 0)
        refs.append(f"https://www.virustotal.com/gui/file/{sha256}")
    except Exception:
        pass

    # Small fields from MalwareBazaar
    try:
        if (mb or {}).get("query_status") == "ok":
            data = (mb or {}).get("data") or []
            if data:
                sig = data[0].get("signature")
                if sig: labels.append(sig)
                dl = data[0].get("download_url")
                if dl: refs.append(dl)
    except Exception:
        pass

    # OTX Pulses and Tags
    try:
        pulses = (otx or {}).get("pulse_info", {}).get("pulses", []) or []
        for p in pulses[:5]:
            name = p.get("name")
            if name: labels.append(name)
        sci = (otx or {}).get("indicator", {}).get("description")
        if sci: labels.append(str(sci))
        refs.append(f"https://otx.alienvault.com/indicator/file/{sha256}")
    except Exception:
        pass

    # Hybrid Analysis Family extractor
    try:
        if isinstance(ha, list) and ha:
            fam = ha[0].get("vx_family") or ha[0].get("verdict") or ha[0].get("threat_score")
            if fam:
                labels.append(str(fam))
        elif isinstance(ha, dict):
            fam = ha.get("vx_family") or ha.get("verdict") or ha.get("threat_score")
            if fam:
                labels.append(str(fam))
    except Exception:
        pass

    # Dedup
    labels = sorted({x for x in labels if x})
    refs   = sorted({x for x in refs if x})

    return {
        "hash": sha256,
        "providers": {
            "virustotal": vt,
            "malwarebazaar": mb,
            "hybridanalysis": ha,
            "otx": otx,
        },
        "summary": {
            "known_malicious": known_mal,
            "threat_labels": labels[:50],
            "references": refs[:50],
        },
    }