"""Agente de triagem estática: executa ferramentas locais e retorna dados estruturados.

Este agente não usa LLM. Ele coleta evidências (hashes, PE, imports, seções,
versão, strings, indicadores, YARA, CAPA) e retorna um dicionário que o
supervisor (LLM) irá resumir depois.
"""

import logging
from ..tools.static_analysis import extract_comprehensive_triage_data

log = logging.getLogger("agent.static")


def run_static_agent(file_path: str, hint: str = "", model: str = "gemini-2.0-flash") -> dict:
    log.info("static_agent: running local triage file=%s", file_path)
    try:
        triage = extract_comprehensive_triage_data.func(file_path)  # type: ignore[attr-defined]
        log.info("static_agent: triage done (keys=%s)", list(triage.keys()) if isinstance(triage, dict) else type(triage))
        return triage
    except Exception as e:
        log.exception("static_agent: triage failed: %s", e)
        return {"error": str(e)}
