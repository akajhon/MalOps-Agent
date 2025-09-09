import sqlite3
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

from ..config import get_settings
import logging

log = logging.getLogger("api.storage")


def _db_path() -> Path:
    p = Path(get_settings()["DB_PATH"]).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _init_db() -> None:
    con = sqlite3.connect(str(_db_path()))
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
              id TEXT PRIMARY KEY,
              created_at TEXT NOT NULL,
              file_name TEXT,
              size_bytes INTEGER,
              md5 TEXT,
              sha1 TEXT,
              sha256 TEXT,
              hint TEXT,
              model TEXT,
              result_json TEXT NOT NULL
            )
            """
        )
        # Helpful index for lookups by sha256
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256)"
        )
        con.commit()
    finally:
        con.close()


def save_analysis(file_name: str, size_bytes: int, hashes: Dict[str, str], result: Dict[str, Any], hint: str = "", model: str = "") -> str:
    _init_db()
    rec_id = uuid.uuid4().hex
    created_at = datetime.utcnow().isoformat() + "Z"
    con = sqlite3.connect(str(_db_path()))
    try:
        con.execute(
            """
            INSERT INTO analyses (id, created_at, file_name, size_bytes, md5, sha1, sha256, hint, model, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec_id,
                created_at,
                file_name,
                int(size_bytes),
                hashes.get("md5", ""),
                hashes.get("sha1", ""),
                hashes.get("sha256", ""),
                hint or "",
                model or "",
                json.dumps(result, ensure_ascii=False),
            ),
        )
        con.commit()
        log.info("analysis saved id=%s sha256=%s file=%s", rec_id, hashes.get("sha256", ""), file_name)
        return rec_id
    finally:
        con.close()


def get_analysis_by_sha256(sha256: str) -> Optional[Dict[str, Any]]:
    """Return the most recent analysis result JSON for a given sha256, if present."""
    if not sha256:
        return None
    _init_db()
    con = sqlite3.connect(str(_db_path()))
    try:
        cur = con.execute(
            "SELECT result_json FROM analyses WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1",
            (sha256,),
        )
        row = cur.fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None
    finally:
        con.close()
