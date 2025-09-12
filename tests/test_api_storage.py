import pytest
from src.api import storage

def test_save_and_get_analysis_by_sha256(tmp_path, monkeypatch):
    db_path = tmp_path / "analyses_test.db"
    monkeypatch.setenv("DB_PATH", str(db_path))

    hashes = {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    result = {"ok": True, "score": 42}

    rec_id = storage.save_analysis("file.bin", 0, hashes, result, hint="h", model="m")
    assert isinstance(rec_id, str) and len(rec_id) > 0

    fetched = storage.get_analysis_by_sha256(hashes["sha256"])
    assert fetched == result
