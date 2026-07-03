#!/usr/bin/env python3
"""Runs the auditor on each model file, builds scan_report.md, exits 1 if any DANGER/ERROR."""
import sys
import json
import subprocess

RESULT_ICON = {"DANGER": "❌", "ERROR": "❌", "WARNING": "⚠️", "SAFE": "✅"}


def scan_one(path):
    proc = subprocess.run(
        [sys.executable, "-m", "scanner.auditor", path],
        capture_output=True,
        text=True,
    )
    try:
        return json.loads(proc.stdout)
    except Exception:
        return {
            "overall_risk": "ERROR",
            "scan_results": {
                "serialization": {
                    "findings": [f"Could not parse auditor output for {path}."],
                    "recommendation": "",
                }
            },
        }


def main(files):
    lines = ["## Model Gate scan results", ""]
    any_fail = False
    if not files:
        lines.append("No model files to scan.")
        _write(lines)
        return 0
    for f in files:
        result = scan_one(f)
        risk = result.get("overall_risk", "ERROR")
        icon = RESULT_ICON.get(risk, "❌")
        if risk in ("DANGER", "ERROR"):
            any_fail = True
        lines.append(f"### {icon} `{f}` — **{risk}**")
        lines.append("")
        ser = result.get("scan_results", {}).get("serialization", {})
        for finding in ser.get("findings", []):
            lines.append(f"- {finding}")
        rec = ser.get("recommendation", "")
        if rec:
            lines.append("")
            lines.append(f"> {rec}")
        lines.append("")
    if any_fail:
        lines.append("---")
        lines.append("**Merge blocked by Model Gate.** A dangerous model was detected.")
    _write(lines)
    return 1 if any_fail else 0


def _write(lines):
    with open("scan_report.md", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
