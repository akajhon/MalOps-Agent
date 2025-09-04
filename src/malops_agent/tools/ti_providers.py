
from langchain_core.tools import tool
from typing import Dict, Any, Optional
from .askjoe_threatintel_tool import vt_lookup, malwarebazaar_lookup, threatfox_search_ioc, abuseipdb_check_ip, _normalize
import os

DEFAULT_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12"))

@tool
def vt_lookup_tool(sha256: str) -> Dict[str, Any]:
    """VirusTotal lookup by sha256 (requires VT_API_KEY)."""
    from .askjoe_threatintel_tool import vt_lookup
    api_key = os.getenv("VT_API_KEY","").strip()
    if not api_key:
        return {"warning": "VT_API_KEY not set"}
    if not sha256:
        return {"warning": "empty sha256"}
    return vt_lookup(sha256, api_key)

@tool
def malwarebazaar_lookup_tool(sha256: str) -> Dict[str, Any]:
    """MalwareBazaar lookup by sha256 (no key)."""
    from .askjoe_threatintel_tool import malwarebazaar_lookup
    if not sha256:
        return {"warning": "empty sha256"}
    return malwarebazaar_lookup(sha256)

@tool
def threatfox_bulk_search_tool(urls: list[str] | None = None, domains: list[str] | None = None, ips: list[str] | None = None) -> Dict[str, Any]:
    """ThreatFox search for multiple IOCs (urls/domains/ips)."""
    from .askjoe_threatintel_tool import threatfox_search_ioc
    data = []
    for coll in (urls or []):
        data.append(threatfox_search_ioc(coll))
    for coll in (domains or []):
        data.append(threatfox_search_ioc(coll))
    for coll in (ips or []):
        data.append(threatfox_search_ioc(coll))
    return {"data": data}

@tool
def abuseipdb_bulk_check_tool(ips: list[str] | None = None) -> Dict[str, Any]:
    """AbuseIPDB bulk check (requires ABUSEIPDB_API_KEY)."""
    from .askjoe_threatintel_tool import abuseipdb_check_ip
    api_key = os.getenv("ABUSEIPDB_API_KEY","").strip()
    if not api_key:
        return {"warning": "ABUSEIPDB_API_KEY not set"}
    out = {}
    for ip in (ips or []):
        out[ip] = abuseipdb_check_ip(ip, api_key)
    return out
