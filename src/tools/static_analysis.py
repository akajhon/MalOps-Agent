from langchain_core.tools import tool
from typing import List, Dict, Any, Optional, Tuple
from ..logging_config import log_tool
import os, re, math, hashlib, time

# =========================
# Helpers básicos e comuns
# =========================

def _exists(p: str) -> bool:
    return os.path.isfile(p)

def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    ln2 = math.log(2)
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * (math.log(p) / ln2)
    return round(ent, 3)

# =========================
# Small tools used by agents
# =========================

@tool
@log_tool("compute_hashes")
def compute_hashes(path: str) -> Dict[str, Any]:
    """Compute MD5/SHA1/SHA256 and size for a file."""
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    data = _read_file(path)
    return {
        "path": os.path.abspath(path),
        "size_bytes": os.path.getsize(path),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

@tool
@log_tool("pe_basic_info")
def pe_basic_info(path: str) -> Dict[str, Any]:
    """Wrapper for extract_basic_pe_info."""
    try:
        return extract_basic_pe_info.func(path)  # type: ignore[attr-defined]
    except Exception as e:
        return {"error": str(e)}

@tool
@log_tool("file_head_entropy")
def file_head_entropy(path: str, head_bytes: Optional[int] = 2048) -> Dict[str, Any]:
    """Wrapper for calculate_entropy with head_bytes sample."""
    try:
        return calculate_entropy.func(path=path, head_bytes=head_bytes)  # type: ignore[attr-defined]
    except Exception as e:
        return {"error": str(e)}

@tool
@log_tool("extract_iocs")
def extract_iocs(path: str, min_length: int = 4, max_strings: int = 300, max_iocs: int = 100) -> Dict[str, Any]:
    """Wrapper for extract_iocs_from_strings."""
    try:
        return extract_iocs_from_strings(path=path, min_length=min_length, max_strings=max_strings, max_iocs=max_iocs)
    except Exception as e:
        return {"error": str(e)}

def _ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    pat = re.compile(rb"[ -~]{%d,}" % min_len)
    return [s.decode("ascii", errors="ignore") for s in pat.findall(data)]

def _sniff_header(data: bytes) -> str:
    if len(data) >= 2 and data[:2] == b"MZ":
        return "PE"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "ELF"
    return "Unknown"

def _try_import_pefile():
    try:
        import pefile  # type: ignore
        return pefile
    except Exception as e:
        return None
    
def _defang(s: str) -> str:
    """Normalize common defanged indicators in a string.

    Examples: hxxp -> http, [.] -> ., (.) -> ., {.} -> .
    """
    try:
        t = s
        t = t.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("hxxp:", "http:")
        t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("(dot)", ".").replace("[dot]", ".")
        return t
    except Exception:
        return s


def extract_iocs_from_strings(path: str, min_length: int = 4, max_strings: int = 5000, max_iocs: int = 100) -> Dict[str, Any]:
    """
    Extrai IOCs (URLs, domínios, IPv4s, carteiras) a partir das strings já obtidas do executável.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    
    data = _read_file(path)
    strings_all = _ascii_strings(data, min_len=min_length)
    strings = strings_all[:max_strings]

    url_re = re.compile(r"\bhttps?://[^\s'\"<>]+", re.I)
    urls_set = set()
    for s in strings:
        for look in (s, _defang(s)):
            for m in url_re.finditer(look):
                urls_set.add(m.group(0).rstrip(").,]"))
    urls = list(urls_set)

    domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I)
    domains_set = set()
    for s in strings:
        for look in (s, _defang(s)):
            for m in domain_re.finditer(look):
                dom = m.group(0).lower().rstrip(").,]")
                domains_set.add(dom)
    domains_all = list(domains_set)

    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ipv4s_all = [m.group(0) for s in strings for m in ipv4_re.finditer(s)]
    ipv4s = [ip for ip in ipv4s_all if all(0 <= int(p) <= 255 for p in ip.split("."))]

    btc_re = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{25,39})\b")
    eth_re = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    btc = list({m.group(0) for s in strings for m in btc_re.finditer(s)})
    eth = list({m.group(0) for s in strings for m in eth_re.finditer(s)})

    return {
        "path": os.path.abspath(path),
        "counts": {"urls": len(urls), "domains": len(domains_all), "ipv4s": len(ipv4s),
                   "btc_addresses": len(btc), "eth_addresses": len(eth)},
        "urls": urls[:max_iocs],
        "domains": domains_all[:max_iocs],
        "ipv4s": ipv4s[:max_iocs],
        "btc_addresses": btc[:max_iocs],
        "eth_addresses": eth[:max_iocs]
    }

# =========================
# 1) TRIAGEM COMPREENSIVA
# =========================

@tool
@log_tool("extract_comprehensive_triage_data")
def extract_comprehensive_triage_data(path: str, strings_min_len: int = 4) -> Dict[str, Any]:
    """
    Executa a triagem consolidada: info básica, imports, seções, versão,
    strings estáveis, assinaturas de código e indicadores avançados.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    basic = extract_basic_pe_info.invoke({"path": path})
    imports = extract_imports_analysis.invoke({"path": path})
    sections = extract_sections_analysis.invoke({"path": path})
    version = extract_version_info.invoke({"path": path})
    stable = extract_stable_strings.invoke({"path": path, "min_length": strings_min_len})
    signatures = extract_code_signatures.invoke({"path": path})
    advanced = extract_advanced_indicators.invoke({"path": path})
    # Lazy-import heavy integrations to avoid import errors in doc builds/CI
    try:
        from .yara_tool import yara_scan  # local import to delay dependency
        yara = yara_scan.func(path)  # type: ignore[attr-defined]
    except Exception as e:
        yara = {"error": str(e)}
    try:
        from .capa_tool import capa_scan  # local import to delay dependency
        capa = capa_scan.func(path)  # type: ignore[attr-defined]
    except Exception as e:
        capa = {"error": str(e)}
    iocs = extract_iocs_from_strings(path, min_length=strings_min_len)

    return {
        "path": os.path.abspath(path),
        "basic_info": basic,
        "imports": imports,
        "sections": sections,
        "version_info": version,
        "stable_strings": stable.get("strings", []) if isinstance(stable, dict) else stable,
        "code_signatures": signatures.get("signatures", []) if isinstance(signatures, dict) else signatures,
        "advanced_indicators": advanced,
        "yara": yara,
        "capa": capa,
        "iocs": iocs
    }

# =========================
# 2) INFO BÁSICA DO ARQUIVO
# =========================

@tool
@log_tool("extract_basic_pe_info")
def extract_basic_pe_info(path: str) -> Dict[str, Any]:
    """
    Hashes, tamanho, tipo, timestamp de compilação, dica de packer, contagem de imports.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    t = _sniff_header(data)
    info = {
        "path": os.path.abspath(path),
        "type": t,
        "size_bytes": os.path.getsize(path),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    if t != "PE":
        info["note"] = "Non-PE or undetected"
        return info

    pefile = _try_import_pefile()
    if not pefile:
        info["error"] = "'pefile' not available"
        return info

    try:
        pe = pefile.PE(path, fast_load=True)
        ts = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        info["compile_timestamp"] = int(ts) if ts else None

        # Heurística simples de packer
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore")
            raw = s.get_data() or b""
            sections.append({"name": name, "entropy": _entropy(raw)})
        info["packer_hint"] = any(
            (sec["name"].lower().startswith(".upx") or "pack" in sec["name"].lower() or sec["entropy"] >= 7.2)
            for sec in sections
        )

        # Contagem de imports
        count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                count += len(entry.imports or [])
        info["import_count"] = count

    except Exception as e:
        info["error"] = f"pefile parse error: {e}"

    return info

# =========================
# 3) ANÁLISE DE IMPORTS
# =========================

@tool
@log_tool("extract_imports_analysis")
def extract_imports_analysis(path: str) -> Dict[str, Any]:
    """
    Categoriza imports por áreas (network, crypto, system, etc.)
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    if _sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

    pefile = _try_import_pefile()
    if not pefile:
        return {"error": "'pefile' not available"}

    categories = {
        "network": ["wininet", "winhttp", "ws2_32", "iphlpapi", "wsock32"],
        "crypto": ["crypt32", "bcrypt", "advapi32", "ncrypt"],
        "system": ["kernel32", "ntdll", "user32", "gdi32", "shell32", "ole32", "oleaut32"],
        "registry": ["advapi32", "shlwapi"],
        "file": ["kernel32", "ntdll", "msvcrt"],
        "process": ["kernel32", "psapi", "tlhelp32", "ntdll"],
        "wmi": ["wbem", "ole32", "oleaut32", "wbemcli"],
        "com": ["ole32", "oleaut32", "comctl32", "comdlg32"],
        "scheduling": ["taskschd", "advapi32", "kernel32"],
        "memory": ["kernel32", "ntdll", "msvcrt"],
        "other": [],
    }

    categorized = {k: [] for k in categories.keys()}
    try:
        pe = pefile.PE(path, fast_load=True)
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return {"imports": {}, "note": "No import table"}

        for entry in pe.DIRECTORY_ENTRY_IMPORT or []:
            lib = (entry.dll or b"").decode(errors="ignore").lower()
            for imp in entry.imports or []:
                name = (imp.name or b"").decode(errors="ignore")
                cat_found = False
                for cat, libs in categories.items():
                    if any(lib.startswith(x) for x in libs):
                        categorized[cat].append(f"{lib}!{name}")
                        cat_found = True
                        break
                if not cat_found:
                    categorized["other"].append(f"{lib}!{name}")

        # Limitar um pouco o volume
        categorized = {k: v[:20] for k, v in categorized.items() if v}
        return {"imports": categorized}

    except Exception as e:
        return {"error": f"imports parse error: {e}"}

# =========================
# 4) ANÁLISE DE SEÇÕES
# =========================

@tool
@log_tool("extract_sections_analysis")
def extract_sections_analysis(path: str) -> Dict[str, Any]:
    """
    Retorna nome, tamanhos, entropia e flags básicas por seção.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    if _sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

    pefile = _try_import_pefile()
    if not pefile:
        return {"error": "'pefile' not available"}

    try:
        pe = pefile.PE(path, fast_load=True)
        out = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore")
            raw = s.get_data() or b""
            ch = int(getattr(s, "Characteristics", 0))
            flags = []
            # IMAGE_SCN_MEM_*
            if ch & 0x20000000:  # EXECUTE
                flags.append("exec")
            if ch & 0x80000000:  # WRITE
                flags.append("write")
            if ch & 0x40000000:  # READ
                flags.append("read")
            out.append({
                "name": name,
                "virtual_size": int(getattr(s, "Misc_VirtualSize", 0)),
                "raw_size": int(s.SizeOfRawData),
                "entropy": _entropy(raw),
                "characteristics": flags
            })
        return {"sections": out}
    except Exception as e:
        return {"error": f"sections parse error: {e}"}

# =========================
# 5) ENTROPIA (Shannon)
# =========================

@tool
@log_tool("calculate_entropy")
def calculate_entropy(path: str, head_bytes: Optional[int] = None) -> Dict[str, Any]:
    """
    Entropia do arquivo (inteiro) ou apenas do cabeçalho (head_bytes).
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    data = _read_file(path)
    if head_bytes and head_bytes > 0:
        data = data[:head_bytes]
    return {"path": os.path.abspath(path), "entropy": _entropy(data), "sampled_bytes": len(data)}

# =========================
# 6) VERSION INFO (PE)
# =========================

@tool
@log_tool("extract_version_info")
def extract_version_info(path: str) -> Dict[str, Any]:
    """
    Extrai VS_VERSION_INFO (StringFileInfo) quando disponível.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    if _sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

    pefile = _try_import_pefile()
    if not pefile:
        return {"error": "'pefile' not available"}

    info = {
        "CompanyName": "Not found",
        "FileDescription": "Not found",
        "ProductName": "Not found",
        "OriginalFilename": "Not found",
        "LegalCopyright": "Not found",
        "FileVersion": "Not found",
        "ProductVersion": "Not found",
        "InternalName": "Not found",
    }
    try:
        pe = pefile.PE(path, fast_load=False)
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for fileinfo in pe.FileInfo:
                if fileinfo and hasattr(fileinfo, "StringTable"):
                    for st in fileinfo.StringTable or []:
                        for k, v in st.entries.items():
                            key = k.decode(errors="ignore")
                            val = v.decode(errors="ignore")
                            if key in info:
                                info[key] = val
        return info
    except Exception as e:
        return {"error": f"version parse error: {e}"}

# =========================
# 7) STRINGS "ESTÁVEIS"
# =========================

def _is_stable_string_impl(s: str) -> bool:
    # Evitar caminhos e itens voláteis
    volatile = [
        r"C:\\Users\\", r"C:\\Program Files\\", r"C:\\Windows\\",
        r"\\AppData\\", r"\\Temp\\", r"\\tmp\\",
        "username", "user", "admin", "administrator"
    ]
    for p in volatile:
        if p.lower() in s.lower():
            return False

    relevant = [
        "http://", "https://", "ftp://", "smtp://",
        "mutex", "pipe", "registry", "reg",
        "config", "setting", "key=", "value=",
        "user-agent", "useragent", "mozilla",
        "error", "exception", "failed", "success",
        "download", "upload", "connect", "send", "receive",
        "encrypt", "decrypt", "hash", "md5", "sha",
        "inject", "hook", "bypass", "evade",
    ]
    for p in relevant:
        if p.lower() in s.lower():
            return True

    # Heurística: strings "técnicas" com sinais de config
    if any(ch in s for ch in "{}[]()<>:;,.="):
        return True

    return False

@tool
@log_tool("is_stable_string")
def is_stable_string(s: str) -> Dict[str, Any]:
    """Retorna se a string é candidata 'estável' e relevante."""
    try:
        return {"string": s, "stable": bool(_is_stable_string_impl(s))}
    except Exception as e:
        return {"error": str(e)}

@tool
@log_tool("extract_stable_strings")
def extract_stable_strings(path: str, min_length: int = 4, max_items: int = 50) -> Dict[str, Any]:
    """
    Extrai strings ASCII e filtra por relevância/estabilidade.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    data = _read_file(path)
    strs = _ascii_strings(data, min_len=min_length)
    stables = [s for s in strs if _is_stable_string_impl(s)]
    return {"path": os.path.abspath(path), "strings": stables[:max_items], "total_candidates": len(stables)}

# =========================
# 8) ASSINATURAS DE CÓDIGO
# =========================

def _rva_to_file_offset(pe, rva: int) -> Optional[int]:
    """
    Converte RVA -> offset de arquivo usando pefile.
    """
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None

@tool
@log_tool("extract_hex_signature")
def extract_hex_signature(path: str, file_offset: int, length: int = 16) -> Dict[str, Any]:
    """
    Retorna bytes hex a partir de um offset em arquivo.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    data = _read_file(path)
    if file_offset < 0 or file_offset >= len(data):
        return {"error": f"invalid offset: {file_offset}"}
    end = min(len(data), file_offset + max(0, length))
    sig = " ".join(f"{b:02x}" for b in data[file_offset:end])
    return {"offset": file_offset, "length": end - file_offset, "hex": sig}

@tool
@log_tool("extract_code_signatures")
def extract_code_signatures(path: str, max_sigs: int = 3, window: int = 32) -> Dict[str, Any]:
    """
    Heurística simples: extrai assinaturas hex em torno de EntryPoint (e outras heurísticas).
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    if _sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

    pefile = _try_import_pefile()
    if not pefile:
        return {"error": "'pefile' not available"}

    sigs = []
    try:
        pe = pefile.PE(path, fast_load=True)
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_off = _rva_to_file_offset(pe, entry_rva)
        if entry_off is not None:
            start = max(0, entry_off)
            end = min(len(data), start + max(16, window))
            sigs.append({
                "label": "EntryPoint",
                "file_offset": start,
                "hex": " ".join(f"{b:02x}" for b in data[start:end])
            })

        # Heurística extra: primeira seção executável
        for s in pe.sections:
            ch = int(getattr(s, "Characteristics", 0))
            if ch & 0x20000000:  # EXECUTE
                off = int(s.PointerToRawData or 0)
                size = int(s.SizeOfRawData or 0)
                if size > 0:
                    end = min(len(data), off + min(size, window))
                    sigs.append({
                        "label": f"ExecSection:{s.Name.rstrip(b'\\x00').decode(errors='ignore')}",
                        "file_offset": off,
                        "hex": " ".join(f"{b:02x}" for b in data[off:end])
                    })
                break

        return {"signatures": sigs[:max_sigs]}

    except Exception as e:
        return {"error": f"signature parse error: {e}"}

# =========================
# 9) INDICADORES AVANÇADOS
# =========================

@tool
@log_tool("detect_packers")
def detect_packers(path: str) -> Dict[str, Any]:
    """
    Heurísticas de packers via nomes/strings de seção e palavras-chave em strings.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    candidates = set()

    # Strings
    s = [x.lower() for x in _ascii_strings(data, min_len=4)][:5000]
    def any_in(strings, subs):
        for sub in subs:
            if any(sub in x for x in strings):
                return True
        return False

    # Sinais clássicos
    known = {
        "UPX": ["upx", "upx0", "upx1", "upx!"],
        "Themida": ["themida", "themida!"],
        "VMProtect": ["vmprotect", "vmp"],
        "ASPack": ["aspack", "aspack!"],
        "PECompact": ["pecompact", "pec1", "pec2"],
        "Armadillo": ["armadillo", "armadillo!"],
        "Obsidium": ["obsidium", "obsidium!"],
        "Enigma": ["enigma", "enig"],
        "MoleBox": ["molebox", "molebox!"],
        "Petite": ["petite", "petite!"],
    }
    for name, sigs in known.items():
        if any_in(s, sigs):
            candidates.add(name)

    # Seções e entropia
    if _sniff_header(data) == "PE":
        pefile = _try_import_pefile()
        if pefile:
            try:
                pe = pefile.PE(path, fast_load=True)
                for sec in pe.sections:
                    n = sec.Name.rstrip(b"\x00").decode(errors="ignore").lower()
                    raw = sec.get_data() or b""
                    ent = _entropy(raw)
                    if n.startswith(".upx"):
                        candidates.add("UPX")
                    if ent >= 7.2:
                        candidates.add("HighEntropy")
            except:
                pass

    return {"packers": sorted(candidates)}

@tool
@log_tool("detect_suspicious_characteristics")
def detect_suspicious_characteristics(path: str) -> Dict[str, Any]:
    """
    Heurísticas gerais: seções RWX, poucos imports, entrypoint 'estranho', etc.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    suspicious = []

    if _sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected", "suspicious": suspicious}

    pefile = _try_import_pefile()
    if not pefile:
        return {"error": "'pefile' not available"}

    try:
        pe = pefile.PE(path, fast_load=True)
        # RWX
        for s in pe.sections:
            ch = int(getattr(s, "Characteristics", 0))
            if (ch & 0x20000000) and (ch & 0x80000000):  # EXEC & WRITE
                suspicious.append(f"RWX section: {s.Name.rstrip(b'\\x00').decode(errors='ignore')}")

        # Few imports
        imp_cnt = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                imp_cnt += len(entry.imports or [])
        if imp_cnt <= 5:
            suspicious.append(f"Very few imports ({imp_cnt}) - possible packing")

        # Entry point muito deslocado
        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep and ep > 0x100000:  # limiar conservador
                suspicious.append(f"Unusual entry point RVA: 0x{ep:x}")
        except:
            pass

    except Exception as e:
        return {"error": f"suspicious characteristics error: {e}"}

    return {"suspicious": suspicious}

@tool
@log_tool("detect_anti_analysis")
def detect_anti_analysis(path: str) -> Dict[str, Any]:
    """
    Anti-debug/Anti-VM/Anti-sandbox via palavras-chave em strings.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    data = _read_file(path)
    s = [x.lower() for x in _ascii_strings(data, min_len=4)][:5000]

    patterns = {
        "Anti-Debug": ["isdebuggerpresent", "checkremotedebuggerpresent", "debugger", "ollydbg", "x64dbg", "ida", "windbg", "ghidra"],
        "Anti-VM": ["vmware", "vbox", "virtualbox", "qemu", "xen", "hyperv"],
        "Anti-Sandbox": ["sandbox", "cuckoo", "joesandbox", "anyrun"],
        "Timing Checks": ["sleep", "gettickcount", "rdtsc", "timegettime"],
        "Process Checks": ["tasklist", "taskmgr", "procmon", "procexp"],
    }

    hits = []
    for cat, keys in patterns.items():
        for k in keys:
            if any(k in x for x in s):
                hits.append(f"{cat}: {k}")
                break

    return {"anti_analysis": hits}

@tool
@log_tool("detect_obfuscation")
def detect_obfuscation(path: str) -> Dict[str, Any]:
    """
    Heurísticas de ofuscação: muitas seções de alta entropia, XOR patterns simples,
    e strings “ruidosas”.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}

    data = _read_file(path)
    indicators = []

    # Muitas regiões de alta entropia
    high_entropy_chunks = 0
    chunk = 4096
    for i in range(0, len(data), chunk):
        if _entropy(data[i:i+chunk]) >= 7.2:
            high_entropy_chunks += 1
    if high_entropy_chunks >= 8:
        indicators.append(f"Many high-entropy blocks: {high_entropy_chunks}")

    # Padrões XOR simples (procura sequências 0x33/0x35 em streams)
    xor_like = len(re.findall(rb"[\x30-\x3f]{3,}", data[:1_000_000]))  # limite 1MB
    if xor_like > 50:
        indicators.append(f"Possible XOR/obfuscation byte streams: {xor_like}")

    # Strings “ruidosas” (muitas com mix de símbolos)
    strings_all = _ascii_strings(data, min_len=8)[:5000]
    noisy = 0
    for s in strings_all:
        # muito símbolo fora de alfanumérico
        sym = sum(1 for c in s if not c.isalnum() and c not in " .:/_-")
        if len(s) > 16 and sym / max(1, len(s)) > 0.35:
            noisy += 1
    if noisy > 50:
        indicators.append(f"Many noisy strings: {noisy}")

    return {"obfuscation": indicators}

@tool
@log_tool("extract_advanced_indicators")
def extract_advanced_indicators(path: str) -> Dict[str, Any]:
    """
    Consolida packers, características suspeitas, anti-análise e ofuscação.
    """
    if not _exists(path):
        return {"error": f"file not found: {path}"}
    pack = detect_packers.invoke({"path": path})
    sus = detect_suspicious_characteristics.invoke({"path": path})
    anti = detect_anti_analysis.invoke({"path": path})
    obf = detect_obfuscation.invoke({"path": path})
    return {
        "packer_indicators": pack.get("packers", []),
        "suspicious_characteristics": sus.get("suspicious", []) if isinstance(sus, dict) else [],
        "anti_analysis": anti.get("anti_analysis", []) if isinstance(anti, dict) else [],
        "obfuscation": obf.get("obfuscation", []) if isinstance(obf, dict) else [],
    }
