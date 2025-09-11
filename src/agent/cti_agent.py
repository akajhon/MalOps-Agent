"""Threat Intel agent: wraps provider tools and normalization."""

from typing import Dict
from langchain_core.tools import tool
from ..logging_config import log_tool
from ..tools.cti_analysis import (
    vt_lookup,
    malwarebazaar_lookup,
    otx_query_ioc,
    hybrid_analysis_lookup,
    normalize_hash,
)

# Defining CTI Analysis Tools

@tool
@log_tool("vt_lookup_tool")
def vt_lookup_tool(sha256: str) -> dict:
    """VirusTotal file lookup (full JSON)."""
    return vt_lookup(sha256)

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
    return hybrid_analysis_lookup(sha256)

def cti_from_hash(sha256: str) -> Dict:
    """Query VT, MalwareBazaar, Hybrid-Analysis, and OTX for a hash."""
    hash = sha256 or ""
    return {
        "ti_vt": vt_lookup_tool.invoke(hash),
        "ti_mb": malwarebazaar_lookup_tool.invoke(hash),
        "ti_ha": hybrid_analysis_lookup_tool.invoke(hash),
        "ti_otx": otx_query_ioc_tool.invoke(hash),
    }

def normalize_cti(vt: dict, mb: dict, ha: dict, otx: dict, sha256: str) -> Dict:
    """Normalize providers into a single structure for a hash indicator."""
    return normalize_hash(vt, mb, ha, otx, sha256)