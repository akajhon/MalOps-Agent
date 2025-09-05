from typing import Optional
from typing_extensions import TypedDict, Annotated
from operator import or_ as merge_dicts
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import ToolNode
from langchain_google_genai import ChatGoogleGenerativeAI as ChatLLM  # ou ChatOpenAI
import json
import os
from ..tools import (
    compute_hashes, extract_iocs, pe_basic_info, file_head_entropy, yara_scan, capa_scan
)
from ..tools.ti_providers import (
    vt_lookup_tool, malwarebazaar_lookup_tool, threatfox_bulk_search_tool, abuseipdb_bulk_check_tool
)
from ..tools.ti_providers import (
    vt_lookup_tool, malwarebazaar_lookup_tool,
    threatfox_bulk_search_tool, abuseipdb_bulk_check_tool,
    _normalize_all as _normalize,
)

class State(TypedDict, total=False):
    # entradas
    file_path: str
    hint: str
    model: str

    # artefatos
    hashes: Annotated[dict, merge_dicts]
    sha256: str
    iocs: Annotated[dict, merge_dicts]
    static_summary: Annotated[dict, merge_dicts]

    # TI (por provedor)
    ti_vt: Annotated[dict, merge_dicts]
    ti_mb: Annotated[dict, merge_dicts]
    ti_tf: Annotated[dict, merge_dicts]
    ti_abuse: Annotated[dict, merge_dicts]

    # TI normalizada e saída final
    threat_intel: Annotated[dict, merge_dicts]
    final: Annotated[dict, merge_dicts]

def _node_bootstrap(state: State) -> State:
    """
    Normaliza o estado inicial e garante 'file_path'. Aceita aliases ('path', 'temp_path').
    """
    fp = state.get("file_path") or state.get("path") or state.get("temp_path")
    if not fp:
        raise KeyError(
            "file_path missing in state. Use /analyze (JSON com 'file_path') "
            "ou /analyze/upload (multipart)."
        )
    # Não escreva de novo se já existe no estado inicial (evita conflito com input).
    if "file_path" in state:
        return {}  # nenhum write neste passo
    return {"file_path": fp}

def _node_hashes(state: State) -> State:
    p = state.get("file_path")
    if not p:
        raise KeyError("file_path not set; expected bootstrap to enforce this")
    h = compute_hashes.func(p)
    return {
        "hashes": h,
        "sha256": (h or {}).get("sha256"),
    }

def _node_iocs(state: State) -> State:
    p = state.get("file_path")
    if not p:
        raise KeyError("file_path not set; expected bootstrap to enforce this")
    i = extract_iocs.func(p)
    return {"iocs": i}

STATIC_TOOLS = [
    compute_hashes, pe_basic_info, file_head_entropy, extract_iocs,
    yara_scan, capa_scan
]

def _static_prompt():
    return (
        "StaticAnalysisAgent: use as ferramentas estáticas (hashes, PE, entropia, IOCs, YARA, CAPA, triage). "
        "Produza um resumo técnico curto e estruturado em JSON com chaves: "
        "imports_suspeitos, entropias_relevantes, iocs_resumidos, yara_scan, capa_scan. "
        "Não gere veredito final."
    )

def _node_static_agent(state: State) -> State:
    llm = ChatLLM(
        model=state.get("model", "gemini-2.0-flash"),
        temperature=0,
        google_api_key=os.getenv("GEMINI_API_KEY")  # <- chave explícita
    )
    tool_node = ToolNode(STATIC_TOOLS)
    llm_tools = llm.bind_tools(STATIC_TOOLS)
    messages = [
        SystemMessage(content=_static_prompt()),
        HumanMessage(content=f"Target: {state.get('file_path')}\nHint: {state.get('hint','')}")
    ]
    ai = llm_tools.invoke(messages)
    messages.append(ai)
    if isinstance(ai, AIMessage) and ai.tool_calls:
        tool_out = tool_node.invoke({"messages": messages})
        messages = tool_out["messages"]
        ai2 = llm_tools.invoke(messages)
        content = ai2.content
    else:
        content = ai.content
    try:
        out = json.loads(content)
    except Exception:
        out = {"raw": content}
    return {"static_summary": out}

def _node_ti_vt(state: State) -> State:
    sha = state.get("sha256") or ""
    return {"ti_vt": vt_lookup_tool.func(sha)}

def _node_ti_mb(state: State) -> State:
    sha = state.get("sha256") or ""
    return {"ti_mb": malwarebazaar_lookup_tool.func(sha)}


def _node_ti_tf(state: State) -> State:
    iocs = state.get("iocs") or {}
    urls = iocs.get("urls") or []
    domains = iocs.get("domains") or []
    ips = iocs.get("ipv4s") or []
    return {"ti_tf": threatfox_bulk_search_tool.func(urls=urls, domains=domains, ips=ips)}


def _node_ti_abuse(state: State) -> State:
    iocs = state.get("iocs") or {}
    ips = iocs.get("ipv4s") or []
    return {"ti_abuse": abuseipdb_bulk_check_tool.func(ips=ips)}


def _node_ti_normalize(state: State) -> State:
    sha = state.get("sha256") or ""
    vt = state.get("ti_vt")
    mb = state.get("ti_mb")
    tf = state.get("ti_tf")
    abuse = state.get("ti_abuse")
    return {"threat_intel": _normalize(vt, mb, tf, abuse, sha)}


def _supervisor_prompt() -> str:
    return (
        "Supervisor: com base no resumo estático e na inteligência de ameaças normalizada, "
        "gere APENAS um JSON com: "
        "verdict (malicious|suspicious|benign), veredict (alias), confidence (0..1), motives (lista), "
        "probable_family, indicators (hashes, imports, urls, domains, ipv4s, wallets, strings), recommended_actions. "
        "Se evidências forem ambíguas, use 'suspicious'. Seja conciso e técnico."
    )

def _node_supervisor(state: State) -> State:
    llm = ChatLLM(
        model=state.get("model", "gemini-2.0-flash"),
        temperature=0,
        google_api_key=os.getenv("GEMINI_API_KEY")  # <- chave explícita
    )
    sys = SystemMessage(content=_supervisor_prompt())
    payload = {
        "static_summary": state.get("static_summary"),
        "threat_intel": state.get("threat_intel"),
        "hashes": state.get("hashes"),
        "iocs": state.get("iocs"),
        "hint": state.get("hint", ""),
        "path": state.get("file_path", ""),
    }
    human = HumanMessage(content="Evidências:\n"+json.dumps(payload, ensure_ascii=False))
    out = llm.invoke([sys, human]).content
    try:
        final = json.loads(out)
    except Exception:
        final = {"raw": out}
    return {"final": final}


def build_hybrid_graph():
    g = StateGraph(State)

    # ENTRY: bootstrap primeiro
    g.add_node("bootstrap", RunnableLambda(_node_bootstrap))

    # Demais nós
    g.add_node("hashes", RunnableLambda(_node_hashes))
    g.add_node("iocs", RunnableLambda(_node_iocs))
    g.add_node("static_agent", RunnableLambda(_node_static_agent))
    g.add_node("ti_vt", RunnableLambda(_node_ti_vt))
    g.add_node("ti_mb", RunnableLambda(_node_ti_mb))
    g.add_node("ti_tf", RunnableLambda(_node_ti_tf))
    g.add_node("ti_abuse", RunnableLambda(_node_ti_abuse))
    g.add_node("ti_normalize", RunnableLambda(_node_ti_normalize))
    g.add_node("supervisor", RunnableLambda(_node_supervisor))

    # Entrada -> bootstrap
    g.set_entry_point("bootstrap")

    # Do bootstrap, dispare hashes e iocs
    g.add_edge("bootstrap", "hashes")
    g.add_edge("bootstrap", "iocs")

    # Paralelo após artefatos básicos
    g.add_edge("iocs", "static_agent")
    g.add_edge("iocs", "ti_tf")
    g.add_edge("iocs", "ti_abuse")
    g.add_edge("hashes", "ti_vt")
    g.add_edge("hashes", "ti_mb")

    # Normalização de TI
    g.add_edge("ti_vt", "ti_normalize")
    g.add_edge("ti_mb", "ti_normalize")
    g.add_edge("ti_tf", "ti_normalize")
    g.add_edge("ti_abuse", "ti_normalize")

    # Supervisor consome estático + TI normalizada
    g.add_edge("static_agent", "supervisor")
    g.add_edge("ti_normalize", "supervisor")
    g.add_edge("supervisor", END)

    return g.compile()

def run_hybrid(file_path: str, hint: Optional[str]=None, model: str="gemini-2.0-flash") -> dict:
    app = build_hybrid_graph()
    init: State = {"file_path": file_path, "hint": hint or "", "model": model}
    print("[run_hybrid] init:", {k: (v if k!="file_path" else str(v)) for k,v in init.items()})
    out = app.invoke(init)
    return out.get("final", {})
