
from fastapi.testclient import TestClient
from src.malops_agent.api.app import app
import io

client = TestClient(app)

def test_analyze_by_path(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello UPX! world")
    r = client.post("/analyze", json={"file_path": str(p), "hint": "test", "model": "gemini-2.0-flash"})
    assert r.status_code == 200
    assert isinstance(r.json(), dict)

def test_upload_analyze(tmp_path):
    content = b"hello UPX! world"
    files = {"file": ("a.bin", io.BytesIO(content), "application/octet-stream")}
    r = client.post("/analyze/upload", files=files, data={"hint":"u", "model":"gemini-2.0-flash"})
    assert r.status_code == 200