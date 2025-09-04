
from langchain_core.tools import tool
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

def _sniff(b:bytes)->str:
    if len(b)>=2 and b[:2]==b"MZ": return "PE"
    if len(b)>=4 and b[:4]==b"\x7fELF": return "ELF"
    return "Unknown"

@tool
def pe_basic_info(path:str)->dict:
    if not _exists(path): return {"error": f"file not found: {path}"}
    with open(path,"rb") as f: data=f.read()
    t=_sniff(data)
    info={"path": os.path.abspath(path), "type": t}
    if t!="PE":
        info["note"]="Not a PE file (or undetected)."
        return info
    try:
        import pefile
    except Exception as e:
        return {"path": os.path.abspath(path), "type":"PE", "error": f"'pefile' not available: {e}"}
    try:
        pe = pefile.PE(path, fast_load=True)
        ts = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        sections=[]
        for s in pe.sections:
            raw = s.get_data() or b""
            sections.append({"name": s.Name.rstrip(b"\x00").decode(errors="ignore"),
                             "virtual_size": int(getattr(s,"Misc_VirtualSize",0)),
                             "raw_size": int(s.SizeOfRawData),
                             "entropy": _entropy(raw)})
        suspicious={"CreateRemoteThread","VirtualAlloc","VirtualAllocEx","WriteProcessMemory",
                    "WinExec","ShellExecute","URLDownloadToFile","InternetOpen","InternetConnect",
                    "HttpOpenRequest","HttpSendRequest","GetProcAddress","LoadLibraryA","ControlService"}
        sus=set(); count=0
        if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
            for entry in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
                for imp in entry.imports:
                    count+=1
                    if imp.name:
                        n=imp.name.decode(errors="ignore")
                        if n in suspicious: sus.add(n)
        packer_hint = any((sec["name"].lower().startswith(".upx") or "pack" in sec["name"].lower()) for sec in sections)
        return {"path": os.path.abspath(path), "type":"PE", "compile_timestamp": int(ts) if ts else None,
                "sections": sections, "import_count": count, "suspicious_imports": sorted(list(sus)), "packer_hint": packer_hint}
    except Exception as e:
        return {"path": os.path.abspath(path), "type":"PE", "error": f"pefile parse error: {e}"}
