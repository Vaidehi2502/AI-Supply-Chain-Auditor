import subprocess
import json
import re

# Known typosquatting patterns - fake names that look like real ML packages
TYPOSQUAT_WATCHLIST = {
    "torchh": "torch",
    "tensorfow": "tensorflow", 
    "nump": "numpy",
    "scikit-learns": "scikit-learn",
    "hggingface": "huggingface-hub",
    "transforemrs": "transformers",
    "pandes": "pandas",
}

def scan_requirements(filepath: str) -> dict:
    """
    Scan a requirements.txt file for vulnerable or suspicious packages.
    """
    result = {
        "file": filepath,
        "packages_checked": 0,
        "vulnerabilities": [],
        "typosquats_found": [],
        "risk_level": "SAFE",
        "findings": []
    }

    # Step 1: Read the requirements file
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception as e:
        result["risk_level"] = "ERROR"
        result["findings"].append(f"Could not read file: {e}")
        return result

    # Step 2: Parse package names
    packages = []
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue
        # Extract just the package name (before ==, >=, etc.)
        pkg_name = re.split(r'[>=<!]', line)[0].strip().lower()
        packages.append(pkg_name)

    result["packages_checked"] = len(packages)

    # Step 3: Check for typosquatting
    for pkg in packages:
        if pkg in TYPOSQUAT_WATCHLIST:
            result["typosquats_found"].append({
                "suspicious": pkg,
                "likely_meant": TYPOSQUAT_WATCHLIST[pkg]
            })
            result["risk_level"] = "DANGER"
            result["findings"].append(
                f"TYPOSQUAT: '{pkg}' looks like '{TYPOSQUAT_WATCHLIST[pkg]}' - possible malicious package"
            )

    # Step 4: Run pip-audit for CVE checks
    # pip-audit scans the packages against the OSV vulnerability database
    try:
        proc = subprocess.run(
            ["pip-audit", "-r", filepath, "--format", "json"],
            capture_output=True, text=True, timeout=60
        )
        
        if proc.stdout:
            audit_data = json.loads(proc.stdout)
            # pip-audit returns a list of vulnerable packages
            for item in audit_data.get("dependencies", []):
                if item.get("vulns"):
                    for vuln in item["vulns"]:
                        result["vulnerabilities"].append({
                            "package": item["name"],
                            "version": item["version"],
                            "cve": vuln.get("id"),
                            "description": vuln.get("description", "")[:200]
                        })
                        result["findings"].append(
                            f"CVE FOUND: {item['name']}=={item['version']} - {vuln.get('id')}"
                        )
            
            if result["vulnerabilities"] and result["risk_level"] != "DANGER":
                result["risk_level"] = "WARNING"

    except subprocess.TimeoutExpired:
        result["findings"].append("pip-audit timed out - network issue?")
    except Exception as e:
        result["findings"].append(f"pip-audit error: {e}")

    if not result["findings"]:
        result["findings"].append(f"All {len(packages)} packages look clean.")

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dependency_scanner.py <requirements.txt>")
    else:
        report = scan_requirements(sys.argv[1])
        print(json.dumps(report, indent=2))