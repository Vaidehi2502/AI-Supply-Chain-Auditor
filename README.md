# AI Supply Chain Auditor

**"VirusTotal for AI models."** Scan a model file — or a HuggingFace repo by URL — for the three ways a supply-chain attack actually shows up: unsafe serialization (pickle RCE), anomalous/backdoored weights, and vulnerable or typosquatted dependencies.

## Why

Model files are code. A `.pkl` or `.pt` checkpoint can execute arbitrary Python on load via pickle's `REDUCE`/`STACK_GLOBAL` opcodes, `requirements.txt` files can pull in typosquatted or CVE-laden packages, and fine-tuned weights can carry statistically detectable backdoors. This tool runs all three checks and rolls them up into a single risk verdict — `SAFE`, `WARNING`, `DANGER`, or `ERROR`.

## How it works

| Scanner | What it checks | Signal |
|---|---|---|
| `scanner/serialization_scanner.py` | File format via magic bytes | Pickle → `DANGER` (scans for dangerous opcodes); safetensors → `SAFE`; raw PyTorch `.pt/.pth/.bin` → `WARNING` |
| `scanner/weight_scanner.py` | Per-layer statistical fingerprint (mean, std, kurtosis, sparsity, NaN/Inf) | Feeds an **IsolationForest** anomaly detector to flag layers that don't match the rest of the model — a proxy for backdoor injection |
| `scanner/dependency_scanner.py` | `requirements.txt` packages | Typosquat watchlist (e.g. `torchh` → `torch`) + `pip-audit` against the OSV vulnerability database |
| `scanner/hf_scanner.py` | Orchestrates the above for a HuggingFace model ID/URL | Lists repo files, downloads scannable weights + `requirements.txt`, scans each |
| `scanner/auditor.py` | Orchestrates the above for a local upload | Runs serialization + weight + dependency scans, computes overall risk |

## Architecture

```
frontend/   Next.js 16 + React 19 dashboard (primary UI)
dashboard/  Static HTML dashboard (earlier prototype)
api/        FastAPI backend — /scan, /scan/huggingface, /health
scanner/    Core scanning logic (framework-agnostic, used by both API and CLI)
```

Both frontends talk to the API at `http://127.0.0.1:8000`.

## Running it

**Backend**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```
Visit `http://localhost:3000`.

**CLI (no server)**
```bash
python -m scanner.auditor test_model.pkl test_requirements.txt
```

## API

```bash
# Scan an uploaded model file (+ optional requirements.txt)
curl -X POST http://127.0.0.1:8000/scan \
  -F "model_file=@model.pkl" \
  -F "requirements_file=@requirements.txt"

# Scan a HuggingFace model by ID or URL
curl -X POST http://127.0.0.1:8000/scan/huggingface \
  -H "Content-Type: application/json" \
  -d '{"model_url": "prajjwal1/bert-tiny"}'
```

## Risk levels

- **SAFE** — no issues found (e.g. safetensors, clean dependencies)
- **WARNING** — needs caution (e.g. raw PyTorch pickle from a trusted source, anomalous-but-not-conclusive weight layer)
- **DANGER** — reject (e.g. pickle file, typosquatted package, NaN/Inf weights)
- **ERROR** — scan itself failed (unreadable file, network issue, unknown model)

## Status

Actively developed. Core scan pipeline (serialization → weights → dependencies) is functional end-to-end via both the local-upload and HuggingFace paths.
