# Agente de Threat Intel: consulta provedores e normaliza saída
from typing import Dict, List
from ..tools.ti_providers import (
    vt_lookup_tool, malwarebazaar_lookup_tool, threatfox_bulk_search_tool,
    abuseipdb_bulk_check_tool,   # se preferir, troque por OTX/Hybrid Analysis
    _normalize_all as _normalize
)

def ti_from_hash(sha256: str) -> Dict:
    # consultas baseadas em hash
    return {
        "ti_vt": vt_lookup_tool.func(sha256 or ""),
        "ti_mb": malwarebazaar_lookup_tool.func(sha256 or "")
    }

def ti_from_iocs(urls: List[str], domains: List[str], ips: List[str]) -> Dict:
    # consultas baseadas em IOCs
    return {
        "ti_tf": threatfox_bulk_search_tool.func(urls=urls, domains=domains, ips=ips),
        "ti_abuse": abuseipdb_bulk_check_tool.func(ips=ips)  # ou troque por OTX
    }

def normalize_ti(vt: dict, mb: dict, tf: dict, abuse_or_otx: dict, sha256: str) -> Dict:
    # normalizador único (aproveita seu _normalize_all)
    return _normalize(vt, mb, tf, abuse_or_otx, sha256)
