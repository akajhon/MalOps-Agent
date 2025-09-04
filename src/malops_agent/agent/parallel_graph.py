
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
import json

from ..tools import (compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan, askjoe_threat_intel)

class MalwareState(dict): pass

def _node_compute_hashes(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["hashes"]=compute_hashes.func(p); return state
def _node_pe_info(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["pe_info"]=pe_basic_info.func(p); return state
def _node_entropy(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["entropy"]=file_head_entropy.func(p); return state
def _node_iocs(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["iocs"]=extract_iocs.func(p); return state
def _node_yara(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["yara"]=yara_scan.func(p); return state
def _node_capa(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["capa"]=capa_scan.func(p); return state
def _node_ti(state: MalwareState)->MalwareState:
    p=state["file_path"]; state["threat_intel"]=askjoe_threat_intel.func(p, iocs=state.get("iocs")); return state

def _sys_prompt()->str:
    return ("Gere exclusivamente um JSON com: verdict, veredict, confidence, motives, probable_family, "
            "indicators (hashes/imports/urls/domains/ipv4s/wallets/strings), recommended_actions. "
            "Use as evidências agregadas (hashes, PE, entropia, IOCs, YARA, CAPA, TI). Se ambíguo, 'suspicious'.")

def _node_summarize(state: MalwareState)->MalwareState:
    llm = ChatOpenAI(model=state.get("model","gpt-4o-mini"), temperature=0)
    sys = SystemMessage(content=_sys_prompt())
    payload = {k: state.get(k) for k in ["hashes","pe_info","entropy","iocs","yara","capa","threat_intel","hint","file_path"]}
    human = HumanMessage(content="Resultados:\n"+json.dumps(payload, ensure_ascii=False))
    out = llm.invoke([sys, human]).content
    try: state["summary"]=json.loads(out)
    except: state["summary"]={"raw": out}
    return state

def build_parallel_graph():
    g=StateGraph(MalwareState)
    g.add_node("compute_hashes", RunnableLambda(_node_compute_hashes))
    g.add_node("extract_pe_info", RunnableLambda(_node_pe_info))
    g.add_node("calculate_entropy", RunnableLambda(_node_entropy))
    g.add_node("extract_iocs", RunnableLambda(_node_iocs))
    g.add_node("scan_yara", RunnableLambda(_node_yara))
    g.add_node("scan_capa", RunnableLambda(_node_capa))
    g.add_node("threat_intel", RunnableLambda(_node_ti))
    g.add_node("summarize", RunnableLambda(_node_summarize))

    g.set_entry_point("compute_hashes")
    for n in ["extract_pe_info","calculate_entropy","extract_iocs","scan_yara","scan_capa"]:
        g.add_edge("compute_hashes", n)
        g.add_edge(n, "summarize")
    g.add_edge("extract_iocs", "threat_intel")
    g.add_edge("threat_intel", "summarize")
    g.add_edge("summarize", END)
    return g.compile()

def run_parallel(file_path: str, hint: Optional[str]=None, model: str="gpt-4o-mini")->Dict[str, Any]:
    app=build_parallel_graph()
    st=MalwareState({"file_path": file_path, "hint": hint or "", "model": model})
    out=app.invoke(st)
    return out.get("summary", {})
