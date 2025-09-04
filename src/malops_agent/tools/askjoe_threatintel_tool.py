
from langchain_core.tools import tool
from typing import Optional, Dict, Any, List
import os, hashlib, requests, time

DEFAULT_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12"))

def _sha256(path:str)->Optional[str]:
    try:
        h=hashlib.sha256()
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except: return None

def vt_lookup(sha256: str, api_key: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"VT HTTP {r.status_code}", "text": r.text[:200]}
        return r.json()
    except Exception as e:
        return {"error": f"VT exception: {e}"}

def malwarebazaar_lookup(sha256: str) -> Dict[str, Any]:
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        r = requests.post(url, data={"query": "get_info", "hash": sha256}, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"MB HTTP {r.status_code}", "text": r.text[:200]}
        return r.json()
    except Exception as e:
        return {"error": f"MB exception: {e}"}

def threatfox_search_ioc(ioc: str) -> Dict[str, Any]:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "search_ioc", "ioc": ioc}
    try:
        r = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"ThreatFox HTTP {r.status_code}", "text": r.text[:200]}
        return r.json()
    except Exception as e:
        return {"error": f"ThreatFox exception: {e}"}

def abuseipdb_check_ip(ip: str, api_key: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"error": f"AbuseIPDB HTTP {r.status_code}", "text": r.text[:200]}
        return r.json()
    except Exception as e:
        return {"error": f"AbuseIPDB exception: {e}"}

def _normalize(vt: Dict[str, Any], mb: Dict[str, Any], tf_data: Dict[str, Any], abuse: Dict[str, Dict[str, Any]], sha256: str) -> Dict[str, Any]:
    labels: List[str] = []
    refs: List[str] = []
    known_mal = None
    first_seen = None
    last_seen = None
    stats = {}

    # VT normalize
    vt_attrs = None
    try:
        vt_attrs = (vt or {}).get("data", {}).get("attributes", {})
    except Exception:
        vt_attrs = None
    if vt_attrs:
        las = vt_attrs.get("last_analysis_stats", {})
        stats["virustotal"] = las
        mal_count = int(las.get("malicious", 0)) if isinstance(las, dict) else 0
        known_mal = (known_mal or mal_count > 0)
        tags = vt_attrs.get("tags") or []
        if isinstance(tags, list): labels.extend(tags)
        # gather meaningful names
        names = vt_attrs.get("names") or []
        if isinstance(names, list): labels.extend(names[:5])
        # refs (VT GUI)
        refs.append(f"https://www.virustotal.com/gui/file/{sha256}")
        # times
        fs = vt_attrs.get("first_submission_date") or vt_attrs.get("times_submitted")
        if isinstance(fs, int):
            first_seen = first_seen or fs
        ls = vt_attrs.get("last_submission_date") or vt_attrs.get("last_analysis_date")
        if isinstance(ls, int):
            last_seen = max(last_seen or 0, ls)

    # MalwareBazaar normalize
    if mb and mb.get("query_status") == "ok":
        data = mb.get("data") or []
        if data:
            item = data[0]
            # tags / family
            if item.get("signature"):
                labels.append(item.get("signature"))
            if item.get("file_type"):
                labels.append(item.get("file_type"))
            # refs
            dl = item.get("download_url")
            if dl: refs.append(dl)
            fs = item.get("first_seen")
            if fs and not first_seen: first_seen = fs
            ls = item.get("last_seen")
            if ls: last_seen = ls

    # ThreatFox normalize (merge for each IOC searched)
    tf_list = []
    if tf_data:
        if isinstance(tf_data, list):
            tf_list = tf_data
        elif isinstance(tf_data, dict) and tf_data.get("data"):
            tf_list = tf_data["data"]
    tf_labels=set()
    tf_refs=set()
    for row in tf_list or []:
        tag = row.get("malware") or row.get("threat")
        if tag: tf_labels.add(tag)
        ref = row.get("reference")
        if ref: tf_refs.add(ref)
        # times
        fs=row.get("first_seen")
        ls=row.get("last_seen")
        if fs and not first_seen: first_seen = fs
        if ls: last_seen = ls
    if tf_labels: labels.extend(sorted(tf_labels))
    if tf_refs: refs.extend(sorted(tf_refs))

    # AbuseIPDB normalize
    abuse_bad = False
    for ip, resp in (abuse or {}).items():
        data = (resp or {}).get("data") or {}
        score = data.get("abuseConfidenceScore")
        if isinstance(score, int) and score >= 25:
            abuse_bad = True
            labels.append(f"abuseipdb_score_{score}:{ip}")
        if data.get("countryCode"):
            labels.append(f"country_{data['countryCode']}:{ip}")
    if abuse_bad:
        known_mal = True if known_mal is None else known_mal or True

    # final
    labels = sorted(list({str(x) for x in labels if x}))
    refs = sorted(list({str(x) for x in refs if x}))
    return {
        "hash": sha256,
        "providers": {
            "virustotal": vt,
            "malwarebazaar": mb,
            "threatfox": tf_data,
            "abuseipdb": abuse
        },
        "summary": {
            "known_malicious": known_mal,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "threat_labels": labels[:25],
            "references": refs[:25],
            "stats": stats
        }
    }

def _extract_ips_from_iocs(iocs: Optional[Dict[str, Any]]) -> List[str]:
    if not iocs: return []
    ips = iocs.get("ipv4s") or []
    return list({ip for ip in ips if isinstance(ip, str)})

@tool
def askjoe_threat_intel(path: str, sha256: Optional[str]=None, iocs: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    """
    Threat intelligence lookup real: VirusTotal (hash), MalwareBazaar (hash), ThreatFox (IOCs), AbuseIPDB (IPs).
    - VT_API_KEY env required for VT.
    - ABUSEIPDB_API_KEY env optional for AbuseIPDB checks.
    - ThreatFox/MalwareBazaar não exigem chave para consultas básicas.
    """
    sha256 = sha256 or _sha256(path) or ""
    vt_key = os.getenv("VT_API_KEY","").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY","").strip()

    vt = vt_lookup(sha256, vt_key) if (vt_key and sha256) else {"warning": "VT key missing or hash empty"}
    mb = malwarebazaar_lookup(sha256) if sha256 else {"warning": "empty hash"}

    # Para ThreatFox e AbuseIPDB, usamos IOCs se fornecidos; caso contrário, nenhum.
    tf_results: Dict[str, Any] = {}
    if iocs:
        tf_collected = []
        for url in (iocs.get("urls") or []):
            tf_collected.append(threatfox_search_ioc(url))
        for dom in (iocs.get("domains") or []):
            tf_collected.append(threatfox_search_ioc(dom))
        tf_results = {"data": tf_collected}

    abuse = {}
    if abuse_key and iocs:
        for ip in _extract_ips_from_iocs(iocs):
            abuse[ip] = abuseipdb_check_ip(ip, abuse_key)

    normalized = _normalize(vt, mb, tf_results, abuse, sha256)
    return normalized
