
from fastapi import FastAPI, UploadFile, File, Form
import logging
from pydantic import BaseModel
import tempfile, os, shutil
from ..agent.graph import run_hybrid
from ..config import get_settings
from ..logging_config import configure_logging
from ..agent.graph import export_graph_artifacts
from .storage import save_analysis, get_analysis_by_sha256
import hashlib

app = FastAPI(title="MalOps Agent API", version="0.5.0")
log = logging.getLogger("api")

@app.on_event("startup")
def _startup_logging():
    configure_logging(get_settings().get("LOG_LEVEL"))
    log.info("API startup: log level configured")
    try:
        out = export_graph_artifacts(os.getenv("GRAPH_OUT_DIR"))
        log.info("Graph exported: %s", out)
    except Exception as e:
        log.warning("Graph export failed: %s", e)

class AnalyzeByPath(BaseModel):
    file_path: str
    hint: str | None = None
    model: str | None = "gemini-2.0-flash"

@app.post("/analyze")
def analyze(req: AnalyzeByPath):
    log.info("/analyze path=%s model=%s", req.file_path, req.model)
    try:
        with open(req.file_path, "rb") as f:
            b = f.read()
        hashes = {
            "md5": hashlib.md5(b).hexdigest(),
            "sha1": hashlib.sha1(b).hexdigest(),
            "sha256": hashlib.sha256(b).hexdigest(),
        }
        # Check cache
        cached = get_analysis_by_sha256(hashes["sha256"]) or None
        if cached is not None:
            log.info("cache hit for sha256=%s — returning stored result", hashes["sha256"])
            return cached

        out = run_hybrid(req.file_path, hint=req.hint, model=req.model or "gemini-2.0-flash")
        # Persist analysis
        save_analysis(file_name=os.path.basename(req.file_path), size_bytes=len(b), hashes=hashes, result=out, hint=req.hint or "", model=req.model or "")
    except Exception as e:
        log.warning("Failed to persist analysis: %s", e)
        out = run_hybrid(req.file_path, hint=req.hint, model=req.model or "gemini-2.0-flash")
    return out

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...), hint: str = Form(default=None), model: str = Form(default="gemini-2.0-flash")):
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, file.filename or "sample.bin")
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

            out = run_hybrid(dst, hint=hint, model=model)
            # Persist
            save_analysis(file_name=file.filename or os.path.basename(dst), size_bytes=len(b), hashes=hashes, result=out, hint=hint or "", model=model or "")
            return out
        except Exception as e:
            log.warning("Failed to persist analysis: %s", e)
            # If persistence failed, still attempt analysis and return result
            out = run_hybrid(dst, hint=hint, model=model)
            return out
