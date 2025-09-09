
from langchain_core.tools import tool
import os
import logging
from .helpers import env_str
from ..logging_config import log_tool
log = logging.getLogger("tools.yara")
def _exists(p:str)->bool: return os.path.isfile(p)

@tool
@log_tool("yara_scan")
def yara_scan(path:str, rules_dir:str=None, max_matches_per_rule:int=5, timeout:int=15)->dict:
    """
    Run YARA scan against a file and summarize matches.

    Args:
        path: file path.
        rules_dir: directory with .yar/.yara rules (default: env YARA_RULES_DIR).
        max_matches_per_rule: cap number of string hits returned per rule.
        timeout: match timeout in seconds.

    Returns:
        dict with match_count, matches (rule/meta/tags/strings preview) and family_candidates.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    rules_dir = rules_dir or env_str("YARA_RULES_DIR", "")
    if not rules_dir:
        return {"error": "YARA_RULES_DIR not set and rules_dir not provided"}
    try:
        import yara
    except Exception as e:
        log.error("yara import failed: %s", e)
        return {"error": f"'yara-python' not installed: {e}"}
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
        matches = rules.match(filepath=path, timeout=timeout)
    except Exception as e:
        log.exception("YARA compile/match error: %s", e)
        return {"error": f"YARA compile/match error: {e}"}
    res = []
    fam = []

    for m in matches:
        meta = dict(getattr(m, "meta", {}) or {})
        description = meta.get("description", "")

        # guarda só nome e descrição
        res.append({
            "rule": m.rule,
            "description": description
        })
    def _uniq(seq):
        out=[]
        seen=set()
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    result = {
        "path": os.path.abspath(path), 
        "match_count": len(res), 
        "matches": res
    }
    log.info("YARA matches: %s", result["match_count"])
    return result
