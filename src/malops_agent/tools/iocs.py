
from langchain_core.tools import tool
import os, re
from urllib.parse import urlparse
def _exists(p:str)->bool: return os.path.isfile(p)
def _uniq(seq):
    out=[]; seen=set()
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out
def _ascii_strings(b:bytes, min_len:int=4):
    pat = re.compile(rb"[ -~]{%d,}" % min_len)
    return [s.decode("ascii", errors="ignore") for s in pat.findall(b)]

@tool
def extract_iocs(path: str, min_length:int=4, max_strings:int=300, max_iocs:int=100) -> dict:
    if not _exists(path): return {"error": f"file not found: {path}"}
    with open(path,"rb") as f: data=f.read()
    strings = _ascii_strings(data, min_len=min_length)[:max_strings]
    url_re = re.compile(r"\bhttps?://[^\s'\"<>]+", re.I)
    urls = _uniq([m.group(0).rstrip(").,]") for s in strings for m in url_re.finditer(s)])
    domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I)
    domains_all = _uniq([m.group(0).lower() for s in strings for m in domain_re.finditer(s)])
    url_domains=set()
    for u in urls:
        try:
            netloc=urlparse(u).netloc.lower()
            if netloc: url_domains.add(netloc)
        except: pass
    domains=[d for d in domains_all if d not in url_domains]
    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    def _valid(ip):
        try:
            parts=[int(p) for p in ip.split(".")]
            return len(parts)==4 and all(0<=p<=255 for p in parts)
        except: return False
    ipv4s_all=_uniq([m.group(0) for s in strings for m in ipv4_re.finditer(s)])
    ipv4s=[ip for ip in ipv4s_all if _valid(ip)]
    btc_legacy=re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    btc_bech32=re.compile(r"\bbc1[ac-hj-np-z02-9]{25,39}\b")
    eth_re=re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    btc=_uniq([m.group(0) for s in strings for m in btc_legacy.finditer(s)] +
              [m.group(0) for s in strings for m in btc_bech32.finditer(s)])
    eth=_uniq([m.group(0) for s in strings for m in eth_re.finditer(s)])
    return {"path": os.path.abspath(path), "counts":{"urls":len(urls),"domains":len(domains),"ipv4s":len(ipv4s),
            "btc_addresses":len(btc),"eth_addresses":len(eth)}, "urls":urls[:max_iocs], "domains":domains[:max_iocs],
            "ipv4s":ipv4s[:max_iocs], "btc_addresses":btc[:max_iocs], "eth_addresses":eth[:max_iocs]}
