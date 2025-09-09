"""Threat Intel agent: wraps provider tools and normalization."""

from typing import Dict
from ..tools.ti_providers import (
    vt_lookup_tool,
    malwarebazaar_lookup_tool,
    otx_query_ioc_tool,
    hybrid_analysis_lookup_tool,
    normalize_hash as _normalize,
)


def ti_from_hash(sha256: str) -> Dict:
    """Query VT, MalwareBazaar, Hybrid-Analysis, and OTX for a hash."""
    sha = sha256 or ""
    return {
        "ti_vt": vt_lookup_tool.func(sha),
        "ti_mb": malwarebazaar_lookup_tool.func(sha),
        "ti_ha": hybrid_analysis_lookup_tool.func(sha),
        "ti_otx": otx_query_ioc_tool.func(sha),
    }


def normalize_ti(vt: dict, mb: dict, ha: dict, otx: dict, sha256: str) -> Dict:
    """Normalize providers into a single structure for a hash indicator."""
    return _normalize(vt, mb, ha, otx, sha256)
