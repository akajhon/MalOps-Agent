import pytest

from src.tools import cti_analysis as cti
def test_vt_lookup_no_key():
    out = cti.vt_lookup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert out.get("error") == "VT_API_KEY not set"
def test_malwarebazaar_lookup_no_key():
    out = cti.malwarebazaar_lookup("d41d8cd98f00b204e9800998ecf8427e")
    assert out.get("error") == "ABUSE_API_KEY not set"
def test_otx_query_unsupported_type_without_key():
    out = cti.otx_query_ioc("not-an-ioc")
    assert "unsupported ioc type" in out.get("error", "")
def test_normalize_hash_merges_labels_and_refs():
    vt = {"data": {"attributes": {"tags": ["trojan", "loader"], "last_analysis_stats": {"malicious": 1}}}}
    mb = {"query_status": "ok", "data": [{"signature": "FakeSig", "download_url": "http://mb.example"}]}
    ha = [{"vx_family": "FamX"}]
    otx = {"pulse_info": {"pulses": [{"name": "Pulse1"}]}, "indicator": {"description": "desc"}}
    out = cti.normalize_hash(vt, mb, ha, otx, "00" * 32)
    labels = out.get("summary", {}).get("threat_labels", [])
    refs = out.get("summary", {}).get("references", [])
    assert any("trojan" in x for x in labels)
    assert any("Pulse1" in x for x in labels)
    assert any("http://mb.example" in x for x in refs)