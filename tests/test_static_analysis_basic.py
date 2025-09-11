import hashlib
from pathlib import Path

from src.agent.static_agent import (
    compute_hashes,
    file_head_entropy,
    extract_hex_signature,
    is_stable_string,
)
from src.tools.static_analysis import (
    extract_iocs_from_strings,
)


def write_bytes(tmp_path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_compute_hashes_and_entropy(tmp_path):
    data = b"HELLO http://example.com [.]bad.com 1.2.3.4 bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 0xabcDEF1234567890abcDEF1234567890abcDEF12"
    p = write_bytes(tmp_path, "sample.bin", data)

    # compute_hashes
    out = compute_hashes.invoke({"path": p.as_posix()})
    assert out.get("size_bytes") == len(data)
    assert out.get("md5") == hashlib.md5(data).hexdigest()
    assert out.get("sha1") == hashlib.sha1(data).hexdigest()
    assert out.get("sha256") == hashlib.sha256(data).hexdigest()

    # file_head_entropy via wrapper
    ent = file_head_entropy.invoke({"path": p.as_posix(), "head_bytes": 8})
    assert ent.get("sampled_bytes") == 8
    assert isinstance(ent.get("entropy"), float)


def test_extract_iocs_from_strings(tmp_path):
    data = b"Visit http://example.com now, also defanged [.]bad.com and IP 10.0.0.5 " \
           b"BTC bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 ETH 0xabcDEF1234567890abcDEF1234567890abcDEF12"
    p = write_bytes(tmp_path, "iocs.bin", data)

    res = extract_iocs_from_strings(p.as_posix(), min_length=3, max_strings=500, max_iocs=50)
    counts = res.get("counts", {})

    assert counts.get("urls", 0) >= 1
    assert any("example.com" in u for u in res.get("urls", []))
    assert any(d == "bad.com" for d in res.get("domains", []))
    assert counts.get("ipv4s", 0) >= 1
    assert any(ip == "10.0.0.5" for ip in res.get("ipv4s", []))
    assert counts.get("btc_addresses", 0) >= 1
    assert counts.get("eth_addresses", 0) >= 1


def test_extract_hex_signature(tmp_path):
    data = bytes.fromhex("de ad be ef 01 02 03 04")
    p = write_bytes(tmp_path, "sig.bin", data)

    sig = extract_hex_signature.invoke({"path": p.as_posix(), "file_offset": 0, "length": 4})
    assert sig.get("hex") == "de ad be ef"
    assert sig.get("length") == 4


def test_is_stable_string():
    good = is_stable_string.invoke({"s": "download config value=42"})
    bad = is_stable_string.invoke({"s": r"C:\\Users\\name\\AppData\\Local"})

    assert good.get("stable") is True
    assert bad.get("stable") is False
