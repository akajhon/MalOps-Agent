import os, re, hashlib, pefile
from typing import Dict, Any, Optional
from .yara_tool import yara_scan
from .capa_tool import capa_scan
from .helpers import (
    file_exists,
    read_file,
    entropy,
    get_ascii_strings,
    sniff_header,
    defang_ioc,
)

def extract_iocs_from_strings(path: str, min_length: int = 4, max_strings: int = 10000, max_iocs: int = 10000) -> Dict[str, Any]:
    """
    Extract IOCs (URLs, domains, IPv4s, and cryptocurrency wallets) from ASCII strings in a file.
    Accepts optional limits for number of strings scanned and IOCs returned.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}
    
    data = read_file(path)
    strings = get_ascii_strings(data, min_len=min_length)[: max(0, int(max_strings))]

    url_re = re.compile(r"\bhttps?://[^\s'\"<>]+", re.I)
    urls_set = set()
    for s in strings:
        for look in (s, defang_ioc(s)):
            for m in url_re.finditer(look):
                urls_set.add(m.group(0).rstrip(").,]"))
    urls = list(urls_set)[: max(0, int(max_iocs))]

    domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I)
    domains_set = set()
    for s in strings:
        for look in (s, defang_ioc(s)):
            for m in domain_re.finditer(look):
                dom = m.group(0).lower().rstrip(").,]")
                domains_set.add(dom)
    domains_all = list(domains_set)[: max(0, int(max_iocs))]

    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ipv4s_all = [m.group(0) for s in strings for m in ipv4_re.finditer(s)]
    ipv4s = [ip for ip in ipv4s_all if all(0 <= int(p) <= 255 for p in ip.split("."))][: max(0, int(max_iocs))]

    btc_re = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{25,39})\b")
    eth_re = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    btc = list({m.group(0) for s in strings for m in btc_re.finditer(s)})[: max(0, int(max_iocs))]
    eth = list({m.group(0) for s in strings for m in eth_re.finditer(s)})[: max(0, int(max_iocs))]

    return {
        "path": os.path.abspath(path),
        "counts": {"urls": len(urls), "domains": len(domains_all), "ipv4s": len(ipv4s),
                "btc_addresses": len(btc), "eth_addresses": len(eth)},
        "urls": urls,
        "domains": domains_all,
        "ipv4s": ipv4s,
        "btc_addresses": btc,
        "eth_addresses": eth
    }

# 1) COMPREHENSIVE TRIAGE

def extract_comprehensive_triage_data(path: str, strings_min_len: int = 4) -> Dict[str, Any]:
    """
    Run consolidated triage: basic info, imports, sections, version,
    stable strings, code signatures, advanced indicators, and local YARA/CAPA.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    basic = extract_basic_pe_info(path)
    imports = extract_imports_analysis(path)
    sections = extract_sections_analysis(path)
    version = extract_version_info(path)
    stable = extract_stable_strings(path, min_length=strings_min_len)
    signatures = extract_code_signatures(path)
    advanced = extract_advanced_indicators(path)
    sh_entropy = calculateentropy(path)
    try:
        yara = yara_scan.func(path) 
    except Exception as e:
        yara = {"error": str(e)}
    try:
        capa = capa_scan.func(path)
    except Exception as e:
        capa = {"error": str(e)}
    iocs = extract_iocs_from_strings(path, min_length=strings_min_len)

    return {
        "path": os.path.abspath(path),
        "basic_info": basic,
        "shannon_entropy": sh_entropy,
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

# 2) BASIC FILE INFO

def extract_basic_pe_info(path: str) -> Dict[str, Any]:
    """
    Hashes, size, type, compile timestamp, packer hint, and import count.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    t = sniff_header(data)
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

    if not pefile:
        info["error"] = "'pefile' not available"
        return info

    try:
        pe = pefile.PE(path, fast_load=True)
        ts = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        info["compile_timestamp"] = int(ts) if ts else None

        # Simple packer heuristic
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore")
            raw = s.get_data() or b""
            sections.append({"name": name, "entropy": entropy(raw)})
        info["packer_hint"] = any(
            (sec["name"].lower().startswith(".upx") or "pack" in sec["name"].lower() or sec["entropy"] >= 7.2)
            for sec in sections
        )

        count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                count += len(entry.imports or [])
        info["import_count"] = count

    except Exception as e:
        info["error"] = f"pefile parse error: {e}"

    return info

# 3) IMPORT ANALYSIS

def extract_imports_analysis(path: str) -> Dict[str, Any]:
    """ Categorize imports by area (network, crypto, system, etc.). """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    if sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

    if not pefile:
        return {"error": "'pefile' not available"}

    categories = {
        "network":   ["wininet", "winhttp", "ws2_32", "iphlpapi", "wsock32", "urlmon"],
        "crypto":    ["crypt32", "bcrypt", "advapi32", "ncrypt", "secur32", "wintrust"],
        "system":    ["kernel32", "ntdll", "user32", "gdi32", "shell32", "ole32", "oleaut32", "rpcrt4"],
        "registry":  ["advapi32", "shlwapi"],
        "file":      ["kernel32", "ntdll", "msvcrt"],
        "process":   ["kernel32", "psapi", "tlhelp32", "ntdll"],
        "wmi":       ["wbem", "wbemcli", "wbemprox", "wmi"],
        "com":       ["ole32", "oleaut32", "comctl32", "comdlg32"],
        "scheduling":["taskschd", "advapi32", "kernel32"],
        "memory":    ["kernel32", "ntdll", "msvcrt"],
        "other":     [],
    }

    categorized: Dict[str, list] = {k: [] for k in categories.keys()}

    try:
        pe = pefile.PE(path, fast_load=True)
        try:
            dirs = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            delay_dir = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT')
            if delay_dir is not None:
                dirs.append(delay_dir)
            pe.parse_data_directories(directories=dirs)
        except Exception:
            try:
                pe.parse_data_directories()
            except Exception as e:
                return {"error": f"data directories parse error: {e}"}

        def process_entries(entries):
            for entry in entries or []:
                dll_bytes = entry.dll or b""
                lib = dll_bytes.decode(errors="ignore").lower()
                for imp in (entry.imports or []):
                    if getattr(imp, "name", None):
                        name = imp.name.decode(errors="ignore")
                    else:
                        name = f"ord#{getattr(imp, 'ordinal', '?')}"
                    placed = False
                    for cat, prefixes in categories.items():
                        if any(lib.startswith(pfx) for pfx in prefixes):
                            categorized[cat].append(f"{lib}!{name}")
                            placed = True
                            break
                    if not placed:
                        categorized["other"].append(f"{lib}!{name}")

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            process_entries(pe.DIRECTORY_ENTRY_IMPORT)
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            process_entries(pe.DIRECTORY_ENTRY_DELAY_IMPORT)

        trimmed = {k: v[:50] for k, v in categorized.items() if v}

        if not trimmed:
            return {
                "imports": {},
                "note": "No imports found after parsing (packed sample? API hashing/dynamic resolution? delay-load ausente?)."
            }

        return {"imports": trimmed}

    except Exception as e:
        return {"error": f"imports parse error: {e}"}

# 4) SECTION ANALYSIS

def extract_sections_analysis(path: str) -> Dict[str, Any]:
    """
    Return name, sizes, entropy, and basic flags for each section.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    if sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

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
            # IMAGE_SCN_MEM_* flags
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
                "entropy": entropy(raw),
                "characteristics": flags
            })
        return {"sections": out}
    except Exception as e:
        return {"error": f"sections parse error: {e}"}

# 5) SHANNON ENTROPY

def calculateentropy(path: str, head_bytes: Optional[int] = None) -> Dict[str, Any]:
    """
    File entropy (entire file) or only header bytes (head_bytes).
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}
    data = read_file(path)
    if head_bytes and head_bytes > 0:
        data = data[:head_bytes]
    return {"path": os.path.abspath(path), "entropy": entropy(data), "sampled_bytes": len(data)}

# 6) VERSION INFO (PE)

def extract_version_info(path: str) -> Dict[str, Any]:
    """
    Extract VS_VERSION_INFO (StringFileInfo) when available.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    if sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}

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

# 7) "STABLE" STRINGS

def is_stable_string_impl(s: str) -> bool:
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

    # Heuristic: "technical" strings with config-like characters
    if any(ch in s for ch in "{}[]()<>:;,.="):
        return True

    return False

def is_stable_string(s: str) -> Dict[str, Any]:
    """Return whether a string is a 'stable' and relevant candidate."""
    try:
        return {"string": s, "stable": bool(is_stable_string_impl(s))}
    except Exception as e:
        return {"error": str(e)}

def extract_stable_strings(path: str, min_length: int = 4, max_items: int = 50) -> Dict[str, Any]:
    """
    Extract ASCII strings and filter by relevance/stability.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}
    data = read_file(path)
    strs = get_ascii_strings(data, min_len=min_length)
    stables = [s for s in strs if is_stable_string_impl(s)]
    return {"path": os.path.abspath(path), "strings": stables[:max_items], "total_candidates": len(stables)}

# 8) CODE SIGNATURES

def _rva_to_file_offset(pe, rva: int) -> Optional[int]:
    """
    Convert RVA -> file offset using pefile.
    """
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None

def extract_code_signatures(path: str, max_sigs: int = 3, window: int = 32) -> Dict[str, Any]:
    """
    Simple heuristic: extract hex signatures around the EntryPoint (and other heuristics).
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    if sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected"}
    
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

        # Extra heuristic: first executable section
        for s in pe.sections:
            ch = int(getattr(s, "Characteristics", 0))
            if ch & 0x20000000:  # EXECUTE
                off = int(s.PointerToRawData or 0)
                size = int(s.SizeOfRawData or 0)
                if size > 0:
                    end = min(len(data), off + min(size, window))
                    sec_name = s.Name.rstrip(b"\x00").decode(errors="ignore")
                    sigs.append({
                        "label": "ExecSection:" + sec_name,
                        "file_offset": off,
                        "hex": " ".join(f"{b:02x}" for b in data[off:end])
                    })
                break

        return {"signatures": sigs[:max_sigs]}

    except Exception as e:
        return {"error": f"signature parse error: {e}"}

# 9) ADVANCED INDICATORS

def detect_packers(path: str) -> Dict[str, Any]:
    """
    Packer heuristics via section names/strings and string keywords.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    candidates = set()

    # Strings
    s = [x.lower() for x in get_ascii_strings(data, min_len=4)][:5000]
    def any_in(strings, subs):
        for sub in subs:
            if any(sub in x for x in strings):
                return True
        return False

    # Classic signals
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

    # Sections and entropy
    if sniff_header(data) == "PE":
        if pefile:
            try:
                pe = pefile.PE(path, fast_load=True)
                for sec in pe.sections:
                    n = sec.Name.rstrip(b"\x00").decode(errors="ignore").lower()
                    raw = sec.get_data() or b""
                    ent = entropy(raw)
                    if n.startswith(".upx"):
                        candidates.add("UPX")
                    if ent >= 7.2:
                        candidates.add("HighEntropy")
            except:
                pass

    return {"packers": sorted(candidates)}

def detect_suspicious_characteristics(path: str) -> Dict[str, Any]:
    """
    General heuristics: RWX sections, very few imports, unusual entry point, etc.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    suspicious = []

    if sniff_header(data) != "PE":
        return {"note": "Non-PE or undetected", "suspicious": suspicious}

    if not pefile:
        return {"error": "'pefile' not available"}

    try:
        pe = pefile.PE(path, fast_load=True)
        # RWX
        for s in pe.sections:
            ch = int(getattr(s, "Characteristics", 0))
            if (ch & 0x20000000) and (ch & 0x80000000):  # EXEC & WRITE
                sec_name = s.Name.rstrip(b"\x00").decode(errors="ignore")
                suspicious.append("RWX section: " + sec_name)

        imp_cnt = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                imp_cnt += len(entry.imports or [])
        if imp_cnt <= 5:
            suspicious.append(f"Very few imports ({imp_cnt}) - possible packing")

        # Entry point far from start (conservative threshold)
        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep and ep > 0x100000:  # conservative threshold
                suspicious.append(f"Unusual entry point RVA: 0x{ep:x}")
        except:
            pass

    except Exception as e:
        return {"error": f"suspicious characteristics error: {e}"}

    return {"suspicious": suspicious}

def detect_anti_analysis(path: str) -> Dict[str, Any]:
    """
    Anti-debug/Anti-VM/Anti-sandbox via keywords in strings.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}
    data = read_file(path)
    s = [x.lower() for x in get_ascii_strings(data, min_len=4)][:5000]

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

def detect_obfuscation(path: str) -> Dict[str, Any]:
    """
    Obfuscation heuristics: many high-entropy regions, simple XOR-like patterns,
    and "noisy" strings.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}

    data = read_file(path)
    indicators = []

    # Many high-entropy regions
    highentropy_chunks = 0
    chunk = 4096
    for i in range(0, len(data), chunk):
        if entropy(data[i:i+chunk]) >= 7.2:
            highentropy_chunks += 1
    if highentropy_chunks >= 8:
        indicators.append(f"Many high-entropy blocks: {highentropy_chunks}")

    # Simple XOR-like patterns (look for 0x30-0x3f sequences in streams)
    xor_like = len(re.findall(rb"[\x30-\x3f]{3,}", data[:1_000_000]))  # limite 1MB
    if xor_like > 50:
        indicators.append(f"Possible XOR/obfuscation byte streams: {xor_like}")

    # "Noisy" strings (many mixed symbols)
    strings_all = get_ascii_strings(data, min_len=8)[:5000]
    noisy = 0
    for s in strings_all:
        # many non-alphanumeric symbols
        sym = sum(1 for c in s if not c.isalnum() and c not in " .:/_-")
        if len(s) > 16 and sym / max(1, len(s)) > 0.35:
            noisy += 1
    if noisy > 50:
        indicators.append(f"Many noisy strings: {noisy}")

    return {"obfuscation": indicators}

def extract_advanced_indicators(path: str) -> Dict[str, Any]:
    """
    Consolidate packers, suspicious characteristics, anti-analysis, and obfuscation.
    """
    if not file_exists(path):
        return {"error": f"file not found: {path}"}
    pack = detect_packers(path)
    sus = detect_suspicious_characteristics(path)
    anti = detect_anti_analysis(path)
    obf = detect_obfuscation(path)
    return {
        "packer_indicators": pack.get("packers", []),
        "suspicious_characteristics": sus.get("suspicious", []) if isinstance(sus, dict) else [],
        "anti_analysis": anti.get("anti_analysis", []) if isinstance(anti, dict) else [],
        "obfuscation": obf.get("obfuscation", []) if isinstance(obf, dict) else [],
    }