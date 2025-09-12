"""Static triage agent: wraps pure static-analysis functions as LangChain tools.

This agent does not use an LLM. It collects evidence (hashes, PE, imports,
sections, version, strings, indicators, YARA, CAPA) and returns a dictionary
that the supervisor (LLM) can summarize later.
"""

import logging
from typing import Dict, Any
from langchain_core.tools import tool
from ..logging_config import log_tool
from ..tools.static_analysis import extract_triage_data

log = logging.getLogger("agent.static")

# Defining Static Analysis Tool

@tool
@log_tool("extract_comprehensive_triage_data")
def start_triage(path: str, strings_min_len: int = 4) -> Dict[str, Any]:
    """Run full triage: basic info, imports, sections, version, strings, signatures, indicators, YARA, CAPA."""
    try:
        return extract_triage_data(path, strings_min_len)
    except Exception as e:
        return {"error": str(e)}

def run_static_agent(file_path: str, hint: str = "", model: str = "gemini-2.0-flash") -> dict:
    log.info("static_agent: running local triage file=%s", file_path)
    try:
        triage = start_triage.invoke(file_path)
        log.info("static_agent: triage done (keys=%s)", list(triage.keys()) if isinstance(triage, dict) else type(triage))
        return triage
    except Exception as e:
        log.exception("static_agent: triage failed: %s", e)
        return {"error": str(e)}