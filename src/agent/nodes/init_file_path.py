import logging
from ..state import State

log = logging.getLogger("agent.nodes.init_file_path")

def init_file_path_node(state: State) -> State:
    fp = state.get("file_path") or state.get("path") or state.get("temp_path")
    if not fp:
        raise KeyError("file_path não informado.")
    log.info("init_file_path: file_path=%s", fp)
    return {"file_path": fp}