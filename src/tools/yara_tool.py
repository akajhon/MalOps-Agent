
import os, logging, yara
from langchain_core.tools import tool
from ..config import get_settings
from ..logging_config import log_tool

log = logging.getLogger("tools.yara")

YARA_RULES_DIR = get_settings().get("YARA_RULES_DIR", "")
DEFAULT_TIMEOUT = get_settings().get("DEFAULT_TIMEOUT ", "")

def exists(p:str)->bool: return os.path.isfile(p)

@tool
@log_tool("yara_scan")
def yara_scan(path:str)->dict:
    """
    Run YARA scan against a file and summarize matches.

    Args:
        path: file path.
        rules_dir: directory with .yar/.yara rules (default: env YARA_RULES_DIR).
        timeout: match timeout in seconds.

    Returns:
        dict with match_count, matches (rule/meta/tags/strings preview) and family_candidates.
    """
    if not exists(path):
        return {"error": f"file not found: {path}"}
    rules_dir = YARA_RULES_DIR
    if not rules_dir:
        return {"error": "YARA_RULES_DIR not set and rules_dir not provided"}
    rule_files={}
    for root,_,files in os.walk(rules_dir):
        for fn in files:
            if fn.lower().endswith((".yar",".yara")):
                key = os.path.relpath(os.path.join(root, fn), rules_dir)
                rule_files[key] = os.path.join(root, fn)
    if not rule_files:
        return {"warning": f"No YARA rules found in {os.path.abspath(rules_dir)}"}
    try:
        log.debug("Compiling YARA rules from %s files", len(rule_files))
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(filepath=path, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        log.exception("YARA compile/match error: %s", e)
        return {"error": f"YARA compile/match error: {e}"}
    res = []
    fam = []

    for m in matches:
        meta = dict(getattr(m, "meta", {}) or {})
        description = meta.get("description", "")
        res.append({
            "rule": m.rule,
            "description": description
        })

    result = {
        "match_count": len(res), 
        "matches": res
    }

    log.info("YARA matches: %s", result["match_count"])
    return result