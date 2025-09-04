
from langchain_core.tools import tool
import os, json, subprocess
from ..config import settings
def _exists(p:str)->bool: return os.path.isfile(p)

@tool
def capa_scan(path:str, rules_dir:str=None, signatures_dir:str=None, extra_args:str="")->dict:
    if not _exists(path): return {"error": f"file not found: {path}"}
    rules_dir = rules_dir or settings.CAPA_RULES_DIR
    signatures_dir = signatures_dir or (settings.CAPA_SIGNATURES_DIR or "")
    cmd = ["capa","-j"]
    if extra_args: cmd.extend(extra_args.split())
    if rules_dir: cmd.extend(["-r", os.path.abspath(rules_dir)])
    if signatures_dir: cmd.extend(["-s", os.path.abspath(signatures_dir)])
    cmd.append(os.path.abspath(path))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return {"error":"capa not found in PATH"}
    except subprocess.TimeoutExpired:
        return {"error":"capa timed out"}
    if p.returncode!=0:
        return {"error": f"capa failed: {p.stderr[:200]}"}
    try:
        data=json.loads(p.stdout)
    except Exception as e:
        return {"error": f"invalid capa json: {e}", "stdout_head": p.stdout[:200]}
    rules=data.get("rules",{}); cat_counts={}
    for _,r in rules.items():
        cat=r.get("meta",{}).get("category","unknown")
        cat_counts[cat]=cat_counts.get(cat,0)+1
    return {"path": os.path.abspath(path), "summary":{"categories":cat_counts,"rule_count":len(rules)}, "raw": data}
