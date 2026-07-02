from scanner.serialization_scanner import scan_file as scan_serialization
from scanner.dependency_scanner import scan_requirements
from scanner.weight_scanner import scan_weights
import json
from pathlib import Path

RISK_ORDER = {"SAFE": 0, "WARNING": 1, "DANGER": 2, "ERROR": 3}

def calculate_overall_risk(reports: list) -> str:
    """Return the highest risk level found across all scans."""
    highest = "SAFE"
    for report in reports:
        level = report.get("risk_level", "SAFE")
        if RISK_ORDER.get(level, 0) > RISK_ORDER.get(highest, 0):
            highest = level
    return highest

def audit_model(model_path: str, requirements_path: str = None) -> dict:
    """
    Run the full audit suite on a model file.
    Optionally also scan its requirements.txt.
    """
    report = {
        "model": model_path,
        "overall_risk": None,
        "scan_results": {}
    }

    # Run serialization scan
    print(f"[1/3] Running serialization scan...")
    report["scan_results"]["serialization"] = scan_serialization(model_path)

    # Run weight scan
    print(f"[2/3] Running weight anomaly scan...")
    report["scan_results"]["weights"] = scan_weights(model_path)

    # Run dependency scan if requirements provided
    if requirements_path:
        print(f"[3/3] Running dependency scan...")
        report["scan_results"]["dependencies"] = scan_requirements(requirements_path)
    else:
        print(f"[3/3] No requirements.txt provided, skipping dependency scan.")

    # Calculate overall risk
    report["overall_risk"] = calculate_overall_risk(
        list(report["scan_results"].values())
    )

    return report


if __name__ == "__main__":
    import sys
    model = sys.argv[1] if len(sys.argv) > 1 else "test_model.pkl"
    reqs = sys.argv[2] if len(sys.argv) > 2 else None
    result = audit_model(model, reqs)
    print("\n" + "="*50)
    print("AUDIT COMPLETE")
    print("="*50)
    print(json.dumps(result, indent=2))