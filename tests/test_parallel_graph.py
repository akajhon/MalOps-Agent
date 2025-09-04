
from src.malops_agent.agent.parallel_graph import run_parallel

def test_parallel_smoke(tmp_path, monkeypatch):
    p = tmp_path / "z.bin"
    p.write_bytes(b"UPX! hello 1.2.3.4 http://example.com")
    # Monkeypatch TI to avoid network
    from src.malops_agent.tools import askjoe_threat_intel as ti_tool
    def fake_askjoe(path: str, sha256=None, iocs=None):
        return {"hash": "x"*64, "summary": {"known_malicious": None, "threat_labels": ["test"]}}
    monkeypatch.setattr(ti_tool, "askjoe_threat_intel", type("X", (), {"func": lambda *a, **k: fake_askjoe(*a, **k)}))
    res = run_parallel(str(p))
    assert isinstance(res, dict)
