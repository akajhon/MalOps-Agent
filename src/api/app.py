
import tempfile, os, shutil, hashlib, logging
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException
from contextlib import asynccontextmanager
from pydantic import BaseModel
from ..agent.graph import run_graph
from ..config import get_settings
from ..logging_config import configure_logging
from ..tools.cti_analysis import (
    vt_lookup,
    malwarebazaar_lookup,
    otx_query_ioc,
    hybrid_analysis_lookup,
    normalize_hash,
)
from ..tools.helpers import detect_ioc_type
from .storage import (
    save_analysis,
    get_analysis_by_sha256,
    list_analyses as storage_list_analyses,
    get_analysis_by_id as storage_get_analysis_by_id,
    delete_analysis_by_id as storage_delete_analysis_by_id,
    purge_analyses_by_sha256 as storage_purge_analyses_by_sha256,
)

log = logging.getLogger("api")

class HashLookup(BaseModel):
    hash: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(get_settings().get("LOG_LEVEL"))
    log.info("API startup: log level configured")
    yield
    # Shutdown

app = FastAPI(title="MalOps Agent API", version="0.5.0", lifespan=lifespan)

@app.get("/healthz")
def healthz():
    """Lightweight healthcheck endpoint."""
    return {"status": "ok"}

@app.post("/ti/hash")
def ti_lookup(req: HashLookup):
    """Lookup a hash across TI providers and return a normalized summary.

    Supports sha256 (VT, HA, MB, OTX) and md5 (MB, OTX).
    """
    h = (req.hash or "").strip()
    if not h:
        raise HTTPException(status_code=400, detail="hash is required")
    t = detect_ioc_type(h)
    if t not in ("sha256", "md5"):
        raise HTTPException(status_code=400, detail=f"unsupported hash type: {t}")

    vt = vt_lookup(h) if t == "sha256" else None
    ha = hybrid_analysis_lookup(h) if t == "sha256" else None
    mb = malwarebazaar_lookup(h)
    otx = otx_query_ioc(h)

    return normalize_hash(vt, mb, ha, otx, h)

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...), hint: str = Form(default=None), model: str = Form(default="gemini-2.0-flash")):
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, file.filename)
        with open(dst, "wb") as f:
            shutil.copyfileobj(file.file, f)
        log.info("/analyze/upload saved temp file: %s", dst)
        try:
            with open(dst, "rb") as rf:
                b = rf.read()
            hashes = {
                "md5": hashlib.md5(b).hexdigest(),
                "sha1": hashlib.sha1(b).hexdigest(),
                "sha256": hashlib.sha256(b).hexdigest(),
            }
            cached = get_analysis_by_sha256(hashes["sha256"]) or None
            if cached is not None:
                log.info("cache hit (upload) for sha256=%s — returning stored result", hashes["sha256"])
                return cached

            out = run_graph(dst, hint=hint, model=model)
            save_analysis(file_name=file.filename or os.path.basename(dst), size_bytes=len(b), hashes=hashes, result=out, hint=hint or "", model=model or "")
            return out
        except Exception as e:
            log.warning("Failed to persist analysis: %s", e)
            out = run_graph(dst, hint=hint, model=model)
            return out

@app.get("/analyses")
def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    sha256: str | None = Query(None),
    sha1: str | None = Query(None),
    md5: str | None = Query(None),
    date_from: str | None = Query(None, description="ISO8601 inclusive lower bound"),
    date_to: str | None = Query(None, description="ISO8601 inclusive upper bound"),
):
    """List analyses with pagination and optional filters.

    Items exclude heavy result payloads; use fetch endpoints to retrieve full result JSON.
    """
    log.info("/analyses list page=%s size=%s filters sha256=%s sha1=%s md5=%s from=%s to=%s",
            page, page_size, bool(sha256), bool(sha1), bool(md5), date_from, date_to)
    return storage_list_analyses(
        page=page,
        page_size=page_size,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        date_from=date_from,
        date_to=date_to,
    )

@app.get("/analyses/sha256/{hash}")
def fetch_by_sha256(hash: str):
    """Return stored analysis JSON for the most recent record with given sha256."""
    log.info("/analyses/sha256 fetch hash=%s", hash)
    out = get_analysis_by_sha256(hash)
    if out is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return out

@app.get("/analyses/{rec_id}")
def fetch_by_id(rec_id: str):
    """Return stored analysis JSON for a specific record id."""
    log.info("/analyses fetch id=%s", rec_id)
    out = storage_get_analysis_by_id(rec_id)
    if out is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return out

@app.delete("/analyses/{rec_id}")
def delete_by_id(rec_id: str):
    """Delete a stored analysis by id."""
    log.info("/analyses delete id=%s", rec_id)
    n = storage_delete_analysis_by_id(rec_id)
    if n <= 0:
        raise HTTPException(status_code=404, detail="analysis not found")
    return {"deleted": True, "count": n, "id": rec_id}

@app.post("/analyses/purge")
def purge_by_sha256(sha256: str = Query(..., description="sha256 to purge")):
    """Delete all records for a given sha256."""
    log.info("/analyses/purge sha256=%s", sha256)
    n = storage_purge_analyses_by_sha256(sha256)
    return {"purged": n, "sha256": sha256}
