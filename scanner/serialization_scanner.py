import pickle
import struct

# These pickle opcodes can execute system commands - red flags
DANGEROUS_OPCODES = {
    b'R': 'REDUCE - can call arbitrary functions',
    b'i': 'INST - can instantiate arbitrary classes', 
    b'\x93': 'STACK_GLOBAL - can import and call anything',
    b'o': 'OBJ - can create arbitrary objects',
}

def scan_file(filepath: str) -> dict:
    """
    Scan a file for unsafe serialization patterns.
    Returns a risk report.
    """
    result = {
        "file": filepath,
        "format": None,
        "risk_level": "SAFE",
        "findings": [],
        "recommendation": ""
    }

    # Step 1: Read the file as raw bytes
    try:
        with open(filepath, "rb") as f:
            header = f.read(10)  # first 10 bytes tell us the format
            f.seek(0)
            content = f.read()
    except Exception as e:
        result["risk_level"] = "ERROR"
        result["findings"].append(f"Could not read file: {e}")
        return result

    # Step 2: Detect file format by magic bytes (like a CTF challenge!)
    # Pickle files start with \x80\x0 to \x80\x05
    if header[0:2] in [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05']:
        result["format"] = "pickle"
        result["risk_level"] = "DANGER"
        result["findings"].append("File is a pickle - can execute code on load")

        # Step 3: Scan for dangerous opcodes inside
        for opcode, description in DANGEROUS_OPCODES.items():
            if opcode in content:
                result["findings"].append(f"Found opcode: {description}")

        result["recommendation"] = (
            "REJECT this file. Never load pickle files from untrusted sources. "
            "Ask the model author to re-export using safetensors format."
        )

    # Safetensors files start with a JSON length header (8 bytes little-endian)
    elif filepath.endswith(".safetensors"):
        result["format"] = "safetensors"
        result["risk_level"] = "SAFE"
        result["findings"].append("Safetensors format - sandboxed, cannot execute code")
        result["recommendation"] = "Safe to load."

    # PyTorch .pt/.pth files use pickle internally
    elif filepath.endswith((".pt", ".pth", ".bin")):
        result["format"] = "pytorch"
        result["risk_level"] = "WARNING"
        result["findings"].append(
            "PyTorch files use pickle internally. "
            "Safe only if from a trusted source AND loaded with weights_only=True"
        )
        result["recommendation"] = (
            "Use torch.load(filepath, weights_only=True) to mitigate risk. "
            "Prefer safetensors format."
        )

    else:
        result["format"] = "unknown"
        result["risk_level"] = "WARNING"
        result["findings"].append("Unknown format - could not determine safety")
        result["recommendation"] = "Manually inspect before loading."

    return result


# This lets you run the file directly to test it
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python serialization_scanner.py <filepath>")
    else:
        report = scan_file(sys.argv[1])
        import json
        print(json.dumps(report, indent=2))