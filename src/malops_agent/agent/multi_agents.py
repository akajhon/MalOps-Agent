
from typing import Dict, Any, Optional
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from ..tools import (compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan,
                     askjoe_ai_triage, askjoe_capa_summary, askjoe_threat_intel)

STATIC_TOOLS = [compute_hashes, pe_basic_info, file_head_entropy, extract_iocs, yara_scan, capa_scan, askjoe_ai_triage, askjoe_capa_summary]
TI_TOOLS = [askjoe_threat_intel]

def static_prompt():
    return "StaticAnalysisAgent: use ferramentas estáticas e produza um resumo técnico (sem veredito)."

def ti_prompt():
    return "ThreatIntelAgent: use askjoe_threat_intel e produza um resumo de TI (sem veredito)."

def final_prompt():
    return ("Supervisor: gere um único JSON com keys: verdict, veredict, confidence, motives, probable_family, "
            "indicators (hashes/imports/urls/domains/ipv4s/wallets/strings), recommended_actions.")

def _build_simple_node(llm: ChatOpenAI, tools):
    llm_tools = llm.bind_tools(tools); tool_node = ToolNode(tools)
    def call_model(state: Dict[str, Any]) -> Dict[str, Any]:
        ai = llm_tools.invoke(state["messages"]); return {"messages": state["messages"] + [ai]}
    def should_continue(state: Dict[str, Any]):
        last = state["messages"][-1]; 
        if isinstance(last, AIMessage) and last.tool_calls: return "tools"
        return END
    g = StateGraph(dict)
    g.add_node("call_model", call_model); g.add_node("tools", tool_node); g.set_entry_point("call_model")
    g.add_conditional_edges("call_model", should_continue, {"tools":"tools", END: END}); g.add_edge("tools","call_model")
    return g.compile()

def build_multi_agent(llm_static: ChatOpenAI, llm_ti: ChatOpenAI, llm_supervisor: ChatOpenAI):
    static = _build_simple_node(llm_static, STATIC_TOOLS)
    ti = _build_simple_node(llm_ti, TI_TOOLS)
    def supervisor(state: Dict[str, Any]) -> Dict[str, Any]:
        ai = llm_supervisor.invoke(state["messages"]); return {"messages": state["messages"] + [ai]}
    graph = StateGraph(dict)
    graph.add_node("static_agent", static); graph.add_node("ti_agent", ti); graph.add_node("supervisor", supervisor)
    graph.set_entry_point("static_agent"); graph.add_edge("static_agent","ti_agent"); graph.add_edge("ti_agent","supervisor")
    return graph.compile()

def run_pipeline(file_path: str, hint: Optional[str]=None, model: str="gpt-4o-mini")->Dict[str, Any]:
    llm_s=ChatOpenAI(model=model, temperature=0); llm_ti=ChatOpenAI(model=model, temperature=0); llm_sup=ChatOpenAI(model=model, temperature=0)
    app = build_multi_agent(llm_s, llm_ti, llm_sup)
    msgs=[SystemMessage(content=static_prompt()), HumanMessage(content=f"Target: {file_path}\nHint: {hint or ''}"),
          SystemMessage(content=ti_prompt()), SystemMessage(content=final_prompt())]
    state={"messages": msgs}; final=app.invoke(state)
    last_ai = next((m for m in reversed(final["messages"]) if isinstance(m, AIMessage)), None)
    if not last_ai: return {"error":"no supervisor output"}
    import json
    try: return json.loads(last_ai.content)
    except: return {"raw": last_ai.content}
