
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import ToolNode
import json

# Tools
from ..tools import (
    compute_hashes, extract_iocs, pe_basic_info, file_head_entropy, yara_scan, capa_scan,
    askjoe_ai_triage, askjoe_capa_summary
)
from ..tools.ti_providers import (
    vt_lookup_tool, malwarebazaar_lookup_tool, threatfox_bulk_search_tool, abuseipdb_bulk_check_tool
)
from ..tools.askjoe_threatintel_tool import _normalize

class State(dict): pass

# ---------------- Basic nodes ----------------

def _node_hashes(state: State) -> State:
    p = state["file_path"]
    state["hashes"] = compute_hashes.func(p)
    # convenience sha256
    sha256 = (state["hashes"] or {}).get("sha256")
    state["sha256"] = sha256
    return state

def _node_iocs(state: State) -> State:
    p = state["file_path"]
    state["iocs"] = extract_iocs.func(p)
    return state

# ---------------- Static Agent (LLM + ToolNode) ----------------

STATIC_TOOLS = [compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan, askjoe_ai_triage, askjoe_capa_summary]

def _static_prompt():
    return (
        "StaticAnalysisAgent: use as ferramentas estáticas (hashes, PE, entropia, IOCs, YARA, CAPA, askjoe_ai_triage). "
        "Produza um resumo técnico curto e estruturado em JSON com chaves:\n"
        "  imports_suspeitos, entropias_relevantes, iocs_resumidos, yara_familias, capa_categorias.\n"
        "Não gere veredito final."
    )

def _node_static_agent(state: State) -> State:
    llm = ChatOpenAI(model=state.get("model", "gpt-4o-mini"), temperature=0)
    tool_node = ToolNode(STATIC_TOOLS)
    llm_tools = llm.bind_tools(STATIC_TOOLS)
    messages = [
        SystemMessage(content=_static_prompt()),
        HumanMessage(content=f"Target: {state.get('file_path')}\nHint: {state.get('hint','')}")
    ]
    # very small loop: one pass of tool calling
    ai = llm_tools.invoke(messages)
    messages.append(ai)
    if isinstance(ai, AIMessage) and ai.tool_calls:
        tool_out = tool_node.invoke({"messages": messages})
        messages = tool_out["messages"]
        # model sees tool outputs once:
        ai2 = llm_tools.invoke(messages)
        messages.append(ai2)
        content = ai2.content
    else:
        content = ai.content
    try:
        state["static_summary"] = json.loads(content)
    except Exception:
        state["static_summary"] = {"raw": content}
    return state

# ---------------- TI provider nodes (parallel) ----------------

def _node_ti_vt(state: State) -> State:
    sha = state.get("sha256") or ""
    state["ti_vt"] = vt_lookup_tool.func(sha)
    return state

def _node_ti_mb(state: State) -> State:
    sha = state.get("sha256") or ""
    state["ti_mb"] = malwarebazaar_lookup_tool.func(sha)
    return state

def _node_ti_tf(state: State) -> State:
    iocs = state.get("iocs") or {}
    urls = iocs.get("urls") or []
    domains = iocs.get("domains") or []
    ips = iocs.get("ipv4s") or []
    state["ti_tf"] = threatfox_bulk_search_tool.func(urls=urls, domains=domains, ips=ips)
    return state

def _node_ti_abuse(state: State) -> State:
    iocs = state.get("iocs") or {}
    ips = iocs.get("ipv4s") or []
    state["ti_abuse"] = abuseipdb_bulk_check_tool.func(ips=ips)
    return state

def _node_ti_normalize(state: State) -> State:
    sha = state.get("sha256") or ""
    vt = state.get("ti_vt")
    mb = state.get("ti_mb")
    tf = state.get("ti_tf")
    abuse = state.get("ti_abuse")
    state["threat_intel"] = _normalize(vt, mb, tf, abuse, sha)
    return state

# ---------------- Summarizer ----------------

def _supervisor_prompt() -> str:
    return (
        "Supervisor: com base no resumo estático e na inteligência de ameaças normalizada, "
        "gere APENAS um JSON com:\n"
        "  verdict (malicious|suspicious|benign), veredict (alias), confidence (0..1), motives (lista),\n"
        "  probable_family, indicators (hashes, imports, urls, domains, ipv4s, wallets, strings), recommended_actions.\n"
        "Se evidências forem ambíguas, use 'suspicious'. Seja conciso e técnico."
    )

def _node_supervisor(state: State) -> State:
    llm = ChatOpenAI(model=state.get("model", "gpt-4o-mini"), temperature=0)
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
        state["final"] = json.loads(out)
    except Exception:
        state["final"] = {"raw": out}
    return state

# ---------------- Build hybrid graph ----------------

def build_hybrid_graph():
    g = StateGraph(State)
    # nodes
    from langchain_core.runnables import RunnableLambda
    g.add_node("hashes", RunnableLambda(_node_hashes))
    g.add_node("iocs", RunnableLambda(_node_iocs))
    g.add_node("static_agent", RunnableLambda(_node_static_agent))
    g.add_node("ti_vt", RunnableLambda(_node_ti_vt))
    g.add_node("ti_mb", RunnableLambda(_node_ti_mb))
    g.add_node("ti_tf", RunnableLambda(_node_ti_tf))
    g.add_node("ti_abuse", RunnableLambda(_node_ti_abuse))
    g.add_node("ti_normalize", RunnableLambda(_node_ti_normalize))
    g.add_node("supervisor", RunnableLambda(_node_supervisor))

    # entry: run hashes and iocs in parallel
    g.set_entry_point("hashes")
    g.add_edge("hashes", "iocs")
    # after basic artifacts, run static agent and TI providers in parallel
    g.add_edge("iocs", "static_agent")
    g.add_edge("iocs", "ti_tf")
    g.add_edge("iocs", "ti_abuse")
    g.add_edge("hashes", "ti_vt")
    g.add_edge("hashes", "ti_mb")
    # normalize TI when all TI providers finished
    g.add_edge("ti_vt", "ti_normalize")
    g.add_edge("ti_mb", "ti_normalize")
    g.add_edge("ti_tf", "ti_normalize")
    g.add_edge("ti_abuse", "ti_normalize")
    # supervisor needs static + TI normalized
    g.add_edge("static_agent", "supervisor")
    g.add_edge("ti_normalize", "supervisor")
    g.add_edge("supervisor", END)
    return g.compile()

def run_hybrid(file_path: str, hint: Optional[str]=None, model: str="gpt-4o-mini") -> Dict[str, Any]:
    app = build_hybrid_graph()
    init = State({"file_path": file_path, "hint": hint or "", "model": model})
    out = app.invoke(init)
    return out.get("final", {})
