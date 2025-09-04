
from langchain_core.tools import tool
from typing import Dict, Any, List
from .file_hashes import compute_hashes as _h
from .entropy import file_head_entropy as _e
from .pe_info import pe_basic_info as _pe
from .iocs import extract_iocs as _iocs
from .yara_tool import yara_scan as _y
from .capa_tool import capa_scan as _c

def _imports(pe: dict)->List[str]:
    return pe.get("suspicious_imports") or []

@tool
def askjoe_ai_triage(path: str, hint: str = "", model: str = "gpt-4o-mini") -> Dict[str, Any]:
    out={"path": path, "hint": hint}
    out["hashes"]=_h.func(path); out["entropy"]=_e.func(path)
    pe=_pe.func(path); out["pe_info"]=pe
    out["imports_suspicious"]=_imports(pe)
    out["iocs"]=_iocs.func(path); out["yara"]=_y.func(path); out["capa"]=_c.func(path)
    return out
