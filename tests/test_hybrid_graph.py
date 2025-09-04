
from src.malops_agent.agent.hybrid_graph import run_hybrid

def test_hybrid_smoke(tmp_path, monkeypatch):
    p = tmp_path / "z.bin"
    p.write_bytes(b"UPX! http://example.com 1.2.3.4")
    # Patch VT & others to avoid live calls
    from src.malops_agent.tools import ti_providers as tp
    monkeypatch.setattr(tp, "vt_lookup_tool", type("T", (), {"func": lambda sha: {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}}))
    monkeypatch.setattr(tp, "malwarebazaar_lookup_tool", type("T", (), {"func": lambda sha: {"query_status": "ok", "data":[{"signature":"TestFam"}]}}))
    monkeypatch.setattr(tp, "threatfox_bulk_search_tool", type("T", (), {"func": lambda **k: {"data":[{"malware":"TFam"}]}}))
    monkeypatch.setattr(tp, "abuseipdb_bulk_check_tool", type("T", (), {"func": lambda **k: {"1.2.3.4":{"data":{"abuseConfidenceScore":10}}}}))
    res = run_hybrid(str(p))
    assert isinstance(res, dict)
