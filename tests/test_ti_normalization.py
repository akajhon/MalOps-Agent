
from src.malops_agent.tools.askjoe_threatintel_tool import _normalize

def test_ti_normalization_minimal():
    vt = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 50}, "tags": ["trojan"], "names": ["sample.exe"], "last_analysis_date": 123456}}}
    mb = {"query_status": "ok", "data": [{"signature": "Emotet", "file_type": "exe", "download_url": "http://example"}]}
    tf = {"data": [{"malware": "Botnet", "reference": "http://ref", "first_seen": "2022-01-01"}]}
    abuse = {"1.2.3.4": {"data": {"abuseConfidenceScore": 60, "countryCode": "US"}}}
    res = _normalize(vt, mb, tf, abuse, "deadbeef")
    assert res["summary"]["known_malicious"] is True
    assert "Emotet" in res["summary"]["threat_labels"]
