
import os, logging, yara, hashlib
from langchain_core.tools import tool
from ..config import get_settings
from ..logging_config import log_tool

log = logging.getLogger("tools.yara")

YARA_RULES_DIR = get_settings().get("YARA_RULES_DIR", "")
DEFAULT_TIMEOUT = get_settings().get("DEFAULT_TIMEOUT", 30)

def exists(p:str)->bool: return os.path.isfile(p)

@tool
@log_tool("yara_scan")
def yara_scan(path:str)->dict:
    """Run YARA scan against a file and summarize matches."""
    if not exists(path):
        return {"error": f"file not found: {path}"}
    rules_dir = YARA_RULES_DIR
    if not rules_dir:
        return {"error": "YARA_RULES_DIR not set and rules_dir not provided"}
    
    rule_files={}
    if os.path.isfile(rules_dir) and rules_dir.lower().endswith((".yar",".yara")):
        single_path = os.path.abspath(rules_dir)
        try:
            log.debug("Compiling YARA rules (single file): %s", single_path)
            rules = yara.compile(filepath=single_path)
        except Exception as e:
            log.exception("YARA compile error (single file): %s", e)
            return {"error": f"YARA compile error: {e}"}
    else:
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
        except Exception as e:
            log.exception("YARA compile error (directory): %s", e)
            return {"error": f"YARA compile error: {e}"}
    try:
        basename = os.path.basename(path)
        ext = os.path.splitext(basename)[1].lstrip(".").lower()
        filesize = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read()
        externals = {
            "filename": basename,
            "filepath": os.path.abspath(path),
            "extension": ext,
            "filesize": filesize,
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }
    except Exception:
        externals = {}

    try:
        matches = rules.match(filepath=path, timeout=DEFAULT_TIMEOUT, externals=externals)
    except Exception as e:
        log.exception("YARA match error: %s", e)
        return {"error": f"YARA match error: {e}"}
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
