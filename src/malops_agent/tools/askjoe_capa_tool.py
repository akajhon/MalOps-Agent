
from langchain_core.tools import tool
from .capa_tool import capa_scan as _capa

@tool
def askjoe_capa_summary(path: str) -> dict:
    r=_capa.func(path); s=r.get("summary",{})
    return {"path": r.get("path"), "rule_count": s.get("rule_count"), "categories": s.get("categories")}
