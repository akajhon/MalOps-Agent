
from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
import tempfile, os, shutil
from ..agent.hybrid_graph import run_hybrid
from dotenv import load_dotenv
load_dotenv()  # carrega .env antes de tudo

app = FastAPI(title="MalOps Agent API", version="0.5.0")

class AnalyzeByPath(BaseModel):
    file_path: str
    hint: str | None = None
    model: str | None = "gemini-2.0-flash"

@app.post("/analyze")
def analyze(req: AnalyzeByPath):
    return run_hybrid(req.file_path, hint=req.hint, model=req.model or "gemini-2.0-flash")

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...), hint: str = Form(default=None), model: str = Form(default="gemini-2.0-flash")):
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, file.filename or "sample.bin")
        with open(dst, "wb") as f:
            shutil.copyfileobj(file.file, f)
        return run_hybrid(dst, hint=hint, model=model)
