
from langchain_core.tools import tool
import os, re
def _exists(p:str)->bool: return os.path.isfile(p)
def _ascii_strings(b:bytes, min_len:int=4):
    pat = re.compile(rb"[ -~]{%d,}" % min_len)
    return [s.decode("ascii", errors="ignore") for s in pat.findall(b)]

@tool
def extract_strings(path: str, min_length:int=4, max_strings:int=300) -> dict:
    if not _exists(path): return {"error": f"file not found: {path}"}
    with open(path,"rb") as f: data=f.read()
    s = _ascii_strings(data, min_len=min_length)
    return {"path": os.path.abspath(path), "total_strings": len(s), "strings_sample": s[:max_strings]}
