from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil, os, uuid, json
from scanner.auditor import audit_model
from scanner.hf_scanner import scan_hf_model

app = FastAPI(
    title="AI Supply Chain Auditor",
    description="VirusTotal for AI models",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
def root():
    return {"message": "AI Supply Chain Auditor is running", "version": "0.1.0"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
async def scan_model(
    model_file: UploadFile = File(...),
    requirements_file: UploadFile = File(None)
):
    scan_id = str(uuid.uuid4())[:8]
    model_path = f"{UPLOAD_DIR}/{scan_id}_{model_file.filename}"
    req_path = None

    try:
        with open(model_path, "wb") as f:
            shutil.copyfileobj(model_file.file, f)

        if requirements_file:
            req_path = f"{UPLOAD_DIR}/{scan_id}_requirements.txt"
            with open(req_path, "wb") as f:
                shutil.copyfileobj(requirements_file.file, f)

        result = audit_model(model_path, req_path)
        result["scan_id"] = scan_id
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if os.path.exists(model_path):
            os.remove(model_path)
        if req_path and os.path.exists(req_path):
            os.remove(req_path)

@app.post("/scan/huggingface")
async def scan_huggingface(payload: dict):
    model_url = payload.get("model_url", "").strip()

    if not model_url:
        raise HTTPException(status_code=400, detail="model_url is required")

    try:
        result = scan_hf_model(model_url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))