
from langchain_core.tools import tool
import os
from ..config import settings
from ..logging_config import log_tool
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
    if not _exists(path): return {"error": f"file not found: {path}"}
    rules_dir = rules_dir or settings.YARA_RULES_DIR
    try:
        import yara
    except Exception as e:
        return {"error": f"'yara-python' not installed: {e}"}
    rule_files={}
    for root,_,files in os.walk(rules_dir):
        for fn in files:
            if fn.lower().endswith((".yar",".yara")):
                key = os.path.relpath(os.path.join(root, fn), rules_dir)
                rule_files[key] = os.path.join(root, fn)
    if not rule_files: return {"warning": f"No YARA rules found in {os.path.abspath(rules_dir)}"}
    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(filepath=path, timeout=timeout)
    except Exception as e:
        return {"error": f"YARA compile/match error: {e}"}
    res=[]; fam=[]
    for m in matches:
        meta = dict(getattr(m,"meta",{}) or {}); tags=list(getattr(m,"tags",[]) or [])
        s_hits=[]
        for off, ident, data in list(getattr(m,"strings",[]) or [])[:max_matches_per_rule]:
            preview = repr(data[:32] if isinstance(data,(bytes,bytearray)) else str(data)[:32])
            s_hits.append({"offset": int(off), "id": ident, "preview": preview})
        res.append({"rule": m.rule, "tags": tags, "meta": meta, "strings": s_hits})
        fam_name = meta.get("family") or meta.get("malware_family") or None
        if fam_name: fam.append(str(fam_name))
        for t in tags:
            if any(k in t.lower() for k in ["emotet","qakbot","lokibot","agenttesla","redline","ransom","trojan","worm","bot","packer","upx"]):
                fam.append(t)
        if any(x in m.rule.lower() for x in ["emotet","qakbot","lokibot","agenttesla","redline","trickbot","upx","packer"]):
            fam.append(m.rule)
    def _uniq(seq):
        out=[]; seen=set()
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out
    return {"path": os.path.abspath(path), "match_count": len(res), "matches": res, "family_candidates": _uniq(fam)[:5]}
