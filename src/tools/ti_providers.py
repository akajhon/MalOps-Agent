# src/malops_agent/tools/ti_providers.py
from __future__ import annotations
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
import os, requests

from ..config import load_env
from .helpers import env_str, env_float, http_get, http_post, detect_ioc_type
load_env()  # ensure .env is loaded for API keys
from ..logging_config import log_tool  # mantém seu decorador de log

# --------------------------
# Config de ambiente
# --------------------------
DEFAULT_TIMEOUT = env_float("HTTP_TIMEOUT", 12.0)

VT_API_KEY  = env_str("VT_API_KEY")
OTX_API_KEY = env_str("OTX_API_KEY")
HA_API_KEY  = env_str("HA_API_KEY")
HA_ENV      = env_str("HA_ENV", "public") 
ABUSE_KEY   = env_str("ABUSE_API_KEY")
# "public" ou "enterprise"

# --------------------------
# Provedores (retorno FULL)
# --------------------------

def vt_lookup_full(sha256: str) -> Dict[str, Any]:
    """VirusTotal file lookup (full v3 JSON)."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}
    if not sha256:
        return {"error": "empty sha256"}
    st, txt, js = http_get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY},
        timeout=DEFAULT_TIMEOUT
    )
    if st != 200:
        return {"error": f"VT HTTP {st}", "text": txt[:400]}
    return js

def malwarebazaar_lookup(hash_value: str) -> Dict[str, Any]:
    """
    Consulta direta ao MalwareBazaar (hash md5/sha1/sha256).
    Usa Auth-Key da Abuse.ch (mesma chave do ThreatFox).
    """
    if not ABUSE_KEY:
        return {"error": "ABUSE_API_KEY not set"}
    if not hash_value:
        return {"error": "empty hash"}

    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            headers={"Auth-Key": ABUSE_KEY},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return {"error": f"MB HTTP {r.status_code}", "text": r.text[:400]}
        return r.json()
    except Exception as e:
        return {"error": f"MB exception: {e}"}

def otx_query_ioc(ioc: str) -> Dict[str, Any]:
    """
    AlienVault OTX:
      - Hash:  /api/v1/indicators/file/<hash>/general
      - Domain:/api/v1/indicators/domain/<domain>/general
      - IP:    /api/v1/indicators/IPv4/<ip>/general
      - URL:   /api/v1/indicators/url/<url>/general
    """
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
    elif ioc_type == "url":
        # URLs precisam ser url-encoded; API costuma aceitar cruas em muitos casos,
        # mas ideal é codificar no chamador caso necessário.
        path = f"/url/{ioc}/general"
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

def hybrid_analysis_lookup_hash(sha256: str) -> Dict[str, Any]:
    """
    Hybrid Analysis (CrowdStrike) — overview summary for a given SHA256.
    Endpoint: GET https://hybrid-analysis.com/api/v2/overview/<sha256>/
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """
    if not HA_API_KEY:
        return {"error": "HA_API_KEY not set"}
    if not sha256:
        return {"error": "empty sha256"}

    # Para 'public' usa-se o header "api-key" e "User-Agent"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }
    # Overview summary endpoint by SHA256
    url = f"https://hybrid-analysis.com/api/v2/overview/{sha256}"
    st, txt, js = http_get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if st != 200:
        return {"error": f"HA HTTP {st}", "text": txt[:400]}
    return js

# --------------------------
# LangChain Tools (simples)
# --------------------------

@tool
@log_tool("vt_lookup_tool")
def vt_lookup_tool(sha256: str) -> dict:
    """VirusTotal file lookup (full JSON)."""
    return vt_lookup_full(sha256)

@tool
@log_tool("malwarebazaar_lookup_tool")
def malwarebazaar_lookup_tool(hash_value: str) -> dict:
    """Consulta MalwareBazaar (JSON completo)."""
    return malwarebazaar_lookup(hash_value)

@tool
@log_tool("otx_query_ioc_tool")
def otx_query_ioc_tool(ioc: str) -> dict:
    """AlienVault OTX query (auto-rota por tipo de IOC)."""
    return otx_query_ioc(ioc)

@tool
@log_tool("hybrid_analysis_lookup_tool")
def hybrid_analysis_lookup_tool(sha256: str) -> dict:
    """Hybrid Analysis hash search (full JSON)."""
    return hybrid_analysis_lookup_hash(sha256)

# --------------------------
# Normalização simples (sem esconder JSON original)
# --------------------------

def normalize_hash(vt: Dict[str, Any] | None,
                   mb: Dict[str, Any] | None,
                   ha: Dict[str, Any] | None,
                   otx: Dict[str, Any] | None,
                   sha256: str) -> Dict[str, Any]:
    """
    Normalização minimalista: retorna sumário básico e preserva JSONs integrais.
    Evita regras complexas para manter legibilidade.
    """
    labels: List[str] = []
    refs: List[str] = []
    known_mal = None

    # VT tags/basics
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

    # MB pequenos campos
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

    # OTX — possíveis pulses/tags
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

    # Hybrid Analysis — extrai família/score simples
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

    # Dedup ordenado
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
