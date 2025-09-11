import json, logging
from typing import Any, Dict
from ..state import State
from ...config import get_settings
from ..prompts import static_analysis_prompt
from langchain_google_genai import ChatGoogleGenerativeAI as ChatLLM
from langchain_core.prompts import ChatPromptTemplate

log = logging.getLogger("agent.nodes.supervisor")

def safe_json_parse(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        log.warning("Non-JSON output, wrapping raw content.")
        return {"raw": text}

def supervisor_node(state: State) -> State:
    ss = state.get("static_summary") or {}
    gemini_api_key = get_settings().get("GEMINI_API_KEY", "")
    model = state.get("model", "gemini-2.0-flash")
    llm = ChatLLM(model=model, temperature=0, google_api_key=gemini_api_key)

    ss = state.get("static_summary") or {}
    ti = state.get("threat_intel") or {}
    basic = ss.get("basic_info") or {}
    iocs = ss.get("iocs") or {}

    def _fmt_list(items, sep="\n", limit=None):
        vals = items or []
        if limit is not None:
            vals = vals[:limit]
        return sep.join(str(x) for x in vals)

    sha256 = state.get("sha256") or basic.get("sha256") or "unknown"
    imports = ss.get("imports", {}).get("imports") if isinstance(ss.get("imports"), dict) else ss.get("imports")
    sections = ss.get("sections", {}).get("sections") if isinstance(ss.get("sections"), dict) else ss.get("sections")
    version = ss.get("version_info")
    strings = ss.get("stable_strings") if isinstance(ss.get("stable_strings"), list) else ss.get("stable_strings", [])
    signatures = ss.get("code_signatures") if isinstance(ss.get("code_signatures"), list) else ss.get("code_signatures", [])
    advanced = ss.get("advanced_indicators") or {}
    yara = ss.get("yara") or {}
    capa = ss.get("capa") or {}

    imports_summary = "\n".join(
        f"- {k}: {', '.join(v)}" for k, v in (imports or {}).items()
    ) if isinstance(imports, dict) else str(imports)

    sections_summary = "\n".join(
        f"- {s.get('name')} size={s.get('raw_size')} ent={s.get('entropy')} flags={','.join(s.get('characteristics', []))}"
        for s in (sections or [])
    ) if isinstance(sections, list) else str(sections)

    version_summary = json.dumps(version, ensure_ascii=False) if isinstance(version, dict) else str(version)
    strings_summary = _fmt_list(strings, sep="\n", limit=50)
    iocs_summary = json.dumps({
        "urls": (iocs.get("urls") or [])[:50],
        "domains": (iocs.get("domains") or [])[:50],
        "ipv4s": (iocs.get("ipv4s") or [])[:50],
        "btc_addresses": (iocs.get("btc_addresses") or [])[:50],
        "eth_addresses": (iocs.get("eth_addresses") or [])[:50],
    }, ensure_ascii=False)
    signatures_summary = _fmt_list([f"{s.get('label')} @ {s.get('file_offset')}" for s in (signatures or [])], sep="\n")
    advanced_summary = json.dumps(advanced, ensure_ascii=False)
    yara_summary = json.dumps({
        "match_count": yara.get("match_count"),
        "rules": [m.get("rule") for m in (yara.get("matches") or [])][:20],
    }, ensure_ascii=False)
    capa_summary = json.dumps({
        "namespaces": list((capa.get("CAPABILITY") or {}).keys()),
        "capability_counts": {k: len(v) for k, v in (capa.get("CAPABILITY") or {}).items()},
        "attck_tactics": list((capa.get("ATTCK") or {}).keys()),
    }, ensure_ascii=False)
    ti_summary = json.dumps(ti, ensure_ascii=False)

    file_summary = (
        f"=== BASIC PE FACTS ===\n"
        f"SHA256: {sha256}\n"
        f"File Size: {basic.get('size_bytes', 'unknown')} bytes\n"
        f"Architecture: {basic.get('architecture', 'unknown')}\n"
        f"Compile Timestamp: {basic.get('compile_timestamp', 'unknown')}\n"
        f"Subsystem: {basic.get('subsystem', 'unknown')}\n\n"
        f"=== IMPORTS ANALYSIS ===\n{imports_summary}\n\n"
        f"=== SECTIONS ANALYSIS ===\n{sections_summary}\n\n"
        f"=== VERSION INFORMATION ===\n{version_summary}\n\n"
        f"=== STABLE STRINGS (Relevant for Analysis) ===\n{strings_summary}\n\n"
        f"=== IOCs FOUND (Found in Stable Strings) ===\n{iocs_summary}\n\n"
        f"=== CODE SIGNATURES ===\n{signatures_summary}\n\n"
        f"=== ADVANCED INDICATORS ===\n{advanced_summary}\n\n"
        f"=== YARA SCAN ===\n{yara_summary}\n\n"
        f"=== CAPA SCAN ===\n{capa_summary}\n\n"
        f"=== CTI ANALYSIS (VirusTotal/MalwareBazaar/Hybrid-Analysis/AlienVault) ===\n{ti_summary}\n"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", "{instructions}"),
        ("human", "{file_summary}"),
    ])
    chain = prompt | llm
    out = chain.invoke({
        "instructions": static_analysis_prompt(),
        "file_summary": file_summary,
    })

    content = getattr(out, "content", out)
    parsed = safe_json_parse(content)
    return {"final": parsed}
