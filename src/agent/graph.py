from typing import Optional, TypedDict
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda

# tools locais simples
from ..tools import compute_hashes, extract_iocs

# agentes separados
from .static_agent import run_static_agent
from .cti_agent import ti_from_hash, ti_from_iocs, normalize_ti

# --------- STATE (simples) ---------
class State(TypedDict, total=False):
    file_path: str
    hint: str
    model: str
    hashes: dict
    sha256: str
    iocs: dict
    static_summary: dict
    ti_vt: dict
    ti_mb: dict
    ti_tf: dict
    ti_abuse: dict  # ou ti_otx
    threat_intel: dict
    final: dict

# --------- NODES BÁSICOS ---------
def _bootstrap(state: State) -> State:
    # garante file_path de aliases simples
    fp = state.get("file_path") or state.get("path") or state.get("temp_path")
    if not fp:
        raise KeyError("file_path não informado.")
    return {"file_path": fp}

def _hashes(state: State) -> State:
    h = compute_hashes.func(state["file_path"])
    return {"hashes": h, "sha256": h.get("sha256")}

def _iocs(state: State) -> State:
    return {"iocs": extract_iocs.func(state["file_path"])}

# --------- NODES: AGENTES ---------
def _static_agent(state: State) -> State:
    out = run_static_agent(
        file_path=state["file_path"],
        hint=state.get("hint", ""),
        model=state.get("model", "gemini-2.0-flash"),
    )
    return {"static_summary": out}

def _ti_hash(state: State) -> State:
    out = ti_from_hash(state.get("sha256", ""))
    return {"ti_vt": out["ti_vt"], "ti_mb": out["ti_mb"]}

def _ti_iocs(state: State) -> State:
    i = state.get("iocs") or {}
    out = ti_from_iocs(
        urls=i.get("urls", []),
        domains=i.get("domains", []),
        ips=i.get("ipv4s", []),
    )
    return {"ti_tf": out["ti_tf"], "ti_abuse": out["ti_abuse"]}

def _ti_normalize(state: State) -> State:
    return {
        "threat_intel": normalize_ti(
            state.get("ti_vt"), state.get("ti_mb"),
            state.get("ti_tf"), state.get("ti_abuse"),
            state.get("sha256", "")
        )
    }

# --------- SUPERVISOR (LLM resumidor) ---------
import os, json
from langchain_google_genai import ChatGoogleGenerativeAI as ChatLLM
from langchain_core.messages import SystemMessage, HumanMessage

def _supervisor(state: State) -> State:
    # prompt curto e assertivo
    sys = "Responda APENAS JSON com: verdict, confidence, probable_family, indicators, recommended_actions."
    payload = {
        "static_summary": state.get("static_summary"),
        "threat_intel": state.get("threat_intel"),
        "hashes": state.get("hashes"),
        "iocs": state.get("iocs"),
        "hint": state.get("hint", ""),
        "path": state.get("file_path", "")
    }
    llm = ChatLLM(model=state.get("model", "gemini-2.0-flash"),
                  temperature=0,
                  google_api_key=os.getenv("GEMINI_API_KEY"))
    out = llm.invoke([SystemMessage(content=sys),
                      HumanMessage(content=json.dumps(payload, ensure_ascii=False))]).content
    try:
        return {"final": json.loads(out)}
    except Exception:
        return {"final": {"raw": out}}

# --------- BUILD/RUN ---------
def build_graph():
    g = StateGraph(State)

    # nós
    g.add_node("bootstrap", RunnableLambda(_bootstrap))
    g.add_node("hashes", RunnableLambda(_hashes))
    g.add_node("iocs", RunnableLambda(_iocs))
    g.add_node("static_agent", RunnableLambda(_static_agent))
    g.add_node("ti_hash", RunnableLambda(_ti_hash))
    g.add_node("ti_iocs", RunnableLambda(_ti_iocs))
    g.add_node("ti_normalize", RunnableLambda(_ti_normalize))
    g.add_node("supervisor", RunnableLambda(_supervisor))

    # entrada
    g.set_entry_point("bootstrap")

    # edges principais
    g.add_edge("bootstrap", "hashes")
    g.add_edge("bootstrap", "iocs")
    g.add_edge("iocs", "static_agent")
    g.add_edge("hashes", "ti_hash")
    g.add_edge("iocs", "ti_iocs")
    g.add_edge("ti_hash", "ti_normalize")
    g.add_edge("ti_iocs", "ti_normalize")
    g.add_edge("static_agent", "supervisor")
    g.add_edge("ti_normalize", "supervisor")
    g.add_edge("supervisor", END)

    return g.compile()

def run_hybrid(file_path: str, hint: Optional[str] = None, model: str = "gemini-2.0-flash") -> dict:
    app = build_graph()
    init: State = {"file_path": file_path, "hint": hint or "", "model": model}
    print("[run_hybrid] init:", {**init, "file_path": str(init["file_path"])})
    return app.invoke(init).get("final", {})
