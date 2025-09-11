import logging
from typing import Optional
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableLambda
from .state import State
from .nodes import (
    init_file_path_node,
    static_agent_node,
    cti_analysis_node,
    supervisor_node,
)

log = logging.getLogger("agent.graph")

def build_graph():
    g = StateGraph(State)

    # Nodes
    g.add_node("init_file_path", RunnableLambda(init_file_path_node))
    g.add_node("static_agent", RunnableLambda(static_agent_node))
    g.add_node("cti_analysis", RunnableLambda(cti_analysis_node))
    g.add_node("supervisor", RunnableLambda(supervisor_node))

    # Entry
    g.set_entry_point("init_file_path")

    # Edges
    g.add_edge("init_file_path", "static_agent")
    g.add_edge("init_file_path", "cti_analysis")
    g.add_edge("static_agent", "supervisor")
    g.add_edge("cti_analysis", "supervisor")
    g.add_edge("supervisor", END)

    return g.compile()


def run_graph(file_path: str, hint: Optional[str] = None, model: str = "gemini-2.0-flash") -> dict:
    app = build_graph()
    init: State = {"file_path": file_path, "hint": hint or "", "model": model}
    log.info("run_graph init: file_path=%s model=%s", init["file_path"], model)
    return app.invoke(init).get("final", {})
