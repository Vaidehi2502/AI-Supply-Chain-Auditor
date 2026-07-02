import os
import tempfile
import requests
from huggingface_hub import hf_hub_download, list_repo_files, model_info
from scanner.serialization_scanner import scan_file as scan_serialization
from scanner.weight_scanner import scan_weights

# File extensions we care about scanning
SCANNABLE_EXTENSIONS = ['.pkl', '.pt', '.pth', '.safetensors', '.bin']
REQUIREMENTS_FILES = ['requirements.txt', 'requirements-dev.txt']

def parse_hf_url(url_or_id: str) -> str:
    """
    Accept either a full URL or a model ID.
    
    Both of these should work:
    - "https://huggingface.co/bert-base-uncased"
    - "bert-base-uncased"
    - "microsoft/DialoGPT-medium"
    """
    url_or_id = url_or_id.strip()
    
    if "huggingface.co/" in url_or_id:
        # Extract the model ID from the URL
        # "https://huggingface.co/bert-base-uncased" -> "bert-base-uncased"
        parts = url_or_id.split("huggingface.co/")
        model_id = parts[1].strip("/")
        return model_id
    
    return url_or_id  # Already a model ID


def get_repo_info(model_id: str) -> dict:
    """Fetch basic info about the model from HuggingFace."""
    try:
        info = model_info(model_id)
        return {
            "model_id": model_id,
            "author": getattr(info, 'author', 'unknown'),
            "downloads": getattr(info, 'downloads', 0),
            "likes": getattr(info, 'likes', 0),
            "tags": getattr(info, 'tags', []),
            "private": getattr(info, 'private', False),
        }
    except Exception as e:
        return {"model_id": model_id, "error": str(e)}


def scan_hf_model(url_or_id: str) -> dict:
    """
    Main function — given a HuggingFace URL or model ID,
    download and scan all model files.
    """
    model_id = parse_hf_url(url_or_id)
    
    result = {
        "model_id": model_id,
        "source": "huggingface",
        "overall_risk": "SAFE",
        "repo_info": {},
        "files_found": [],
        "files_scanned": [],
        "scan_results": {},
        "findings_summary": [],
        "error": None
    }

    # ── Step 1: Get repo info ──────────────────────────────────────────
    print(f"[HF] Fetching info for: {model_id}")
    result["repo_info"] = get_repo_info(model_id)
    
    if "error" in result["repo_info"]:
        result["error"] = f"Model not found: {model_id}"
        result["overall_risk"] = "ERROR"
        return result

    # ── Step 2: List all files in the repo ────────────────────────────
    print(f"[HF] Listing files...")
    try:
        all_files = list(list_repo_files(model_id))
    except Exception as e:
        result["error"] = f"Could not list repo files: {e}"
        result["overall_risk"] = "ERROR"
        return result

    result["files_found"] = all_files
    print(f"[HF] Found {len(all_files)} files: {all_files}")

    # ── Step 3: Filter to only scannable files ────────────────────────
    # We don't need to download README, configs, etc.
    model_files = [
        f for f in all_files
        if any(f.endswith(ext) for ext in SCANNABLE_EXTENSIONS)
    ]
    req_files = [f for f in all_files if f in REQUIREMENTS_FILES]

    if not model_files:
        result["findings_summary"].append(
            "No scannable model files found (.pkl, .pt, .safetensors, .bin)"
        )
        result["overall_risk"] = "WARNING"
        return result

    # ── Step 4: Download and scan each model file ─────────────────────
    # We use a temp directory that auto-cleans up after we're done
    with tempfile.TemporaryDirectory() as tmpdir:
        
        # Scan requirements.txt if it exists
        for req_file in req_files:
            try:
                print(f"[HF] Downloading {req_file}...")
                local_path = hf_hub_download(
                    repo_id=model_id,
                    filename=req_file,
                    local_dir=tmpdir
                )
                from scanner.dependency_scanner import scan_requirements
                dep_result = scan_requirements(local_path)
                result["scan_results"][f"dependencies:{req_file}"] = dep_result
                
                if dep_result["risk_level"] in ["WARNING", "DANGER"]:
                    result["findings_summary"].extend(dep_result["findings"])
                    
            except Exception as e:
                print(f"[HF] Could not scan {req_file}: {e}")

        # Scan model weight files
        # Limit to first 2 files to avoid downloading huge models
        for filename in model_files[:2]:
            try:
                print(f"[HF] Downloading {filename} for scanning...")
                
                local_path = hf_hub_download(
                    repo_id=model_id,
                    filename=filename,
                    local_dir=tmpdir
                )
                
                result["files_scanned"].append(filename)
                file_scans = {}

                # Run serialization scan
                print(f"[HF] Scanning serialization: {filename}")
                ser_result = scan_serialization(local_path)
                file_scans["serialization"] = ser_result

                # Run weight scan
                print(f"[HF] Scanning weights: {filename}")
                weight_result = scan_weights(local_path)
                file_scans["weights"] = weight_result

                result["scan_results"][filename] = file_scans

                # Collect high-risk findings into summary
                for scan_type, scan_data in file_scans.items():
                    if scan_data.get("risk_level") in ["WARNING", "DANGER"]:
                        for finding in scan_data.get("findings", []):
                            result["findings_summary"].append(
                                f"[{filename}] {finding}"
                            )

            except Exception as e:
                print(f"[HF] Error scanning {filename}: {e}")
                result["scan_results"][filename] = {
                    "error": str(e),
                    "risk_level": "ERROR"
                }

    # ── Step 5: Calculate overall risk ───────────────────────────────
    RISK_ORDER = {"SAFE": 0, "WARNING": 1, "DANGER": 2, "ERROR": 3}
    highest = "SAFE"
    
    for key, scan_data in result["scan_results"].items():
        if isinstance(scan_data, dict):
            # Could be nested (filename -> {serialization: {}, weights: {}})
            for sub_key, sub_data in scan_data.items():
                if isinstance(sub_data, dict):
                    level = sub_data.get("risk_level", "SAFE")
                    if RISK_ORDER.get(level, 0) > RISK_ORDER.get(highest, 0):
                        highest = level

    result["overall_risk"] = highest

    if not result["findings_summary"]:
        result["findings_summary"].append(
            f"Scanned {len(result['files_scanned'])} file(s) — no major issues found."
        )

    return result


# Test it directly
if __name__ == "__main__":
    import sys, json
    model = sys.argv[1] if len(sys.argv) > 1 else "prajjwal1/bert-tiny"
    result = scan_hf_model(model)
    print(json.dumps(result, indent=2))