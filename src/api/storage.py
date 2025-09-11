import sqlite3
import json
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from ..config import get_settings

log = logging.getLogger("api.storage")

def db_path() -> Path:
    p = Path(get_settings()["DB_PATH"]).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def init_db() -> None:
    con = sqlite3.connect(str(db_path()))
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
        # Index for lookups by sha256
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256)"
        )
        con.commit()
    finally:
        con.close()

def save_analysis(file_name: str, size_bytes: int, hashes: Dict[str, str], result: Dict[str, Any], hint: str = "", model: str = "") -> str:
    init_db()
    rec_id = uuid.uuid4().hex
    created_at = datetime.utcnow().isoformat() + "Z"
    con = sqlite3.connect(str(db_path()))
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
    init_db()
    con = sqlite3.connect(str(db_path()))
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

# Helpers for API routes

def get_analysis_by_id(rec_id: str) -> Optional[Dict[str, Any]]:
    """Return stored analysis result JSON for a given record id, if present."""
    if not rec_id:
        return None
    init_db()
    con = sqlite3.connect(str(db_path()))
    try:
        cur = con.execute(
            "SELECT result_json FROM analyses WHERE id = ? LIMIT 1",
            (rec_id,),
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


def list_analyses(
    page: int = 1,
    page_size: int = 20,
    sha256: Optional[str] = None,
    sha1: Optional[str] = None,
    md5: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> Dict[str, Any]:
    """List analyses with pagination and optional hash/date filtering.

    Returns a dict: {"page", "page_size", "total", "items": [...]}
    Items exclude the heavy result JSON to keep responses light.
    """
    init_db()
    page = max(1, int(page))
    page_size = min(max(1, int(page_size)), 200)

    where: List[str] = []
    args: List[Any] = []
    if sha256:
        where.append("sha256 = ?")
        args.append(sha256)
    if sha1:
        where.append("sha1 = ?")
        args.append(sha1)
    if md5:
        where.append("md5 = ?")
        args.append(md5)
    if date_from:
        where.append("created_at >= ?")
        args.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        args.append(date_to)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    con = sqlite3.connect(str(db_path()))
    try:
        cur = con.execute(f"SELECT COUNT(*) FROM analyses{where_sql}", tuple(args))
        total = int(cur.fetchone()[0])
        offset = (page - 1) * page_size
        cur = con.execute(
            f"""
            SELECT id, created_at, file_name, size_bytes, md5, sha1, sha256, hint, model
            FROM analyses
            {where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            tuple(args) + (page_size, offset),
        )
        cols = [c[0] for c in cur.description]
        items = [dict(zip(cols, row)) for row in cur.fetchall()]

        return {"page": page, "page_size": page_size, "total": total, "items": items}
    finally:
        con.close()


def delete_analysis_by_id(rec_id: str) -> int:
    """Delete a single analysis by id. Returns number of rows deleted (0 or 1)."""
    if not rec_id:
        return 0
    init_db()
    con = sqlite3.connect(str(db_path()))
    try:
        cur = con.execute("DELETE FROM analyses WHERE id = ?", (rec_id,))
        con.commit()
        return cur.rowcount or 0
    finally:
        con.close()


def purge_analyses_by_sha256(sha256: str) -> int:
    """Delete all analyses for a given sha256. Returns number of rows deleted."""
    if not sha256:
        return 0
    init_db()
    con = sqlite3.connect(str(db_path()))
    try:
        cur = con.execute("DELETE FROM analyses WHERE sha256 = ?", (sha256,))
        con.commit()
        return cur.rowcount or 0
    finally:
        con.close()