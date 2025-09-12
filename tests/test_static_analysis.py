import hashlib
from pathlib import Path
from src.agent.static_agent import start_triage

def write_bytes(tmp_path, name: str, data: bytes) -> Path:
    """Helper: write bytes to a temp file and return its Path."""
    p = tmp_path / name
    p.write_bytes(data)
    return p

def test_comprehensive_triage_non_pe_with_iocs(tmp_path):
    """Run comprehensive triage on a small non-PE file and assert key sections."""
    data = (
        b"Hello http://example.com [.]defanged.com IP 8.8.8.8 "
        b"BTC bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 ETH 0xabcDEF1234567890abcDEF1234567890abcDEF12"
    )
    p = write_bytes(tmp_path, "triage.bin", data)

    out = start_triage.invoke({"path": p.as_posix(), "strings_min_len": 3})
    assert isinstance(out, dict)

    # basic_info sanity
    basic = out.get("basic_info", {})
    assert basic.get("size_bytes") == len(data)
    assert basic.get("md5") == hashlib.md5(data).hexdigest()
    assert basic.get("type") in ("Unknown", "PE", "ELF")

    # entropy wrapper
    ent = out.get("shannon_entropy", {})
    assert isinstance(ent.get("entropy"), float)
    assert ent.get("sampled_bytes") == len(data)

    # iocs detected from strings
    iocs = out.get("iocs", {})
    counts = iocs.get("counts", {})
    assert counts.get("urls", 0) >= 1
    assert counts.get("domains", 0) >= 1
    assert counts.get("ipv4s", 0) >= 1
    assert counts.get("btc_addresses", 0) >= 1
    assert counts.get("eth_addresses", 0) >= 1

    # stable_strings should be a list
    assert isinstance(out.get("stable_strings", []), list)

    # advanced_indicators present with expected keys
    adv = out.get("advanced_indicators", {})
    for k in ("packer_indicators", "suspicious_characteristics", "anti_analysis", "obfuscation"):
        assert k in adv
