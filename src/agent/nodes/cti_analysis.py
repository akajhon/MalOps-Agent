import logging, hashlib
from ..state import State
from ..cti_agent import cti_from_hash, normalize_cti

log = logging.getLogger("agent.nodes.cti_analysis")

def get_sha256(state: State) -> str:
    if state.get("sha256"):
        return state["sha256"]
    ss = state.get("static_summary") or {}
    basic = ss.get("basic_info") or {}
    sha = basic.get("sha256") or ""
    if sha:
        return sha
    try:
        path = state.get("file_path")
        if path:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        pass
    return ""

def cti_analysis_node(state: State) -> State:
    sha = get_sha256(state)
    if not sha:
        log.warning("cti_analysis: no sha256 available; skipping CTI lookup")
        return {"threat_intel": {"note": "sha256 not available"}}

    out = cti_from_hash(sha)
    ti = normalize_cti(out.get("ti_vt"), out.get("ti_mb"), out.get("ti_ha"), out.get("ti_otx"), sha)
    log.info("cti_analysis completed for sha256=%s", sha[:12])
    return {"sha256": sha, "threat_intel": ti, }
