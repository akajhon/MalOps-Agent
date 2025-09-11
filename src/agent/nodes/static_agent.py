import logging
from ..state import State
from ..static_agent import run_static_agent

log = logging.getLogger("agent.nodes.static_agent")


def static_agent_node(state: State) -> State:
    out = run_static_agent(
        file_path=state["file_path"],
        hint=state.get("hint", ""),
        model=state.get("model", "gemini-2.0-flash"),
    )
    log.info("static_agent completed")
    return {"static_summary": out}

