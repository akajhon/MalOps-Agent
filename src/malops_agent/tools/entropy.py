
from langchain_core.tools import tool
from ..logging_config import log_tool
import os
def _exists(p:str)->bool: return os.path.isfile(p)
def _entropy(b:bytes)->float:
    if not b: return 0.0
    freq=[0]*256
    for x in b: freq[x]+=1
    import math
    ent=0.0; ln2=math.log(2)
    for c in freq:
        if c:
            p=c/len(b)
            ent -= p*(math.log(p)/ln2)
    return round(ent,3)

@tool
@log_tool("file_head_entropy")
def file_head_entropy(path:str, head_bytes:int=2048)->dict:
    """
    Entropy extraction
    """
    if not _exists(path): return {"error": f"file not found: {path}"}
    with open(path,"rb") as f: data=f.read(head_bytes)
    return {"path": os.path.abspath(path), "head_bytes": head_bytes, "entropy": _entropy(data)}
