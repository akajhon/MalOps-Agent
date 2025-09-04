
from langchain_core.tools import tool
import os, hashlib
def _exists(p:str)->bool: return os.path.isfile(p)

@tool
def compute_hashes(path: str) -> dict:
    """Compute MD5/SHA1/SHA256 and size. Args: path"""
    if not _exists(path): return {"error": f"file not found: {path}"}
    md5=hashlib.md5(); sha1=hashlib.sha1(); sha256=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"path": os.path.abspath(path),"md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),"sha256": sha256.hexdigest(),
            "size_bytes": os.path.getsize(path)}
