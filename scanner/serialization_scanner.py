import pickletools

# Modules/functions that indicate real code-execution intent inside a pickle.
# If a GLOBAL/STACK_GLOBAL resolves to one of these, it's a genuine threat.
DANGEROUS_GLOBALS = {
    ("os", "system"), ("posix", "system"), ("nt", "system"),
    ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "run"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "__import__"),
    ("builtins", "compile"), ("builtins", "getattr"),
    ("importlib", "import_module"),
    ("pty", "spawn"), ("commands", "getoutput"),
    ("socket", "socket"),
}

# Module prefixes considered safe (normal model serialization machinery).
SAFE_MODULE_PREFIXES = (
    "numpy", "torch", "collections", "__builtin__.list", "__builtin__.dict",
    "builtins.list", "builtins.dict", "builtins.set", "builtins.tuple",
    "builtins.bytearray", "_codecs", "pandas", "scipy", "sklearn",
)

PICKLE_MAGIC = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")


def _resolve_globals(content: bytes):
    """
    Walk the pickle's opcodes and collect every (module, name) that a GLOBAL or
    STACK_GLOBAL resolves to. This tells us WHAT the file would import/call,
    not merely that it contains a call opcode.
    """
    found = []
    try:
        ops = list(pickletools.genops(content))
    except Exception:
        return found, True  # parse failed -> treat as suspicious

    # For STACK_GLOBAL, the module and name are the two preceding string pushes.
    recent_strings = []
    for opcode, arg, _pos in ops:
        name = opcode.name
        if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
                    "SHORT_BINSTRING", "BINSTRING", "STRING"):
            recent_strings.append(arg)
            if len(recent_strings) > 4:
                recent_strings.pop(0)
        elif name == "GLOBAL":
            # arg is "module name" (space-separated)
            parts = str(arg).split(" ", 1)
            if len(parts) == 2:
                found.append((parts[0], parts[1]))
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                found.append((recent_strings[-2], recent_strings[-1]))
    return found, False


def _is_dangerous(module, funcname):
    if (module, funcname) in DANGEROUS_GLOBALS:
        return True
    full = f"{module}.{funcname}"
    if any(full.startswith(p) for p in SAFE_MODULE_PREFIXES):
        return False
    # Unknown module calling into system-ish names -> flag conservatively
    if funcname in ("system", "popen", "spawn", "eval", "exec"):
        return True
    return False


def scan_file(filepath: str) -> dict:
    result = {"file": filepath, "format": None, "risk_level": "SAFE",
              "findings": [], "recommendation": ""}
    try:
        with open(filepath, "rb") as f:
            header = f.read(10)
            f.seek(0)
            content = f.read()
    except Exception as e:
        result["risk_level"] = "ERROR"
        result["findings"].append(f"Could not read file: {e}")
        return result

    if filepath.endswith(".safetensors"):
        result["format"] = "safetensors"
        result["findings"].append("Safetensors format - sandboxed, cannot execute code.")
        result["recommendation"] = "Safe to load."
        return result

    is_pickle = header[0:2] in PICKLE_MAGIC
    is_torch = filepath.endswith((".pt", ".pth", ".bin"))

    if is_pickle or is_torch:
        result["format"] = "pytorch" if is_torch else "pickle"
        globals_found, parse_failed = _resolve_globals(content)
        dangerous = [(m, n) for (m, n) in globals_found if _is_dangerous(m, n)]

        if parse_failed:
            result["risk_level"] = "WARNING"
            result["findings"].append("Could not fully parse pickle opcodes - inspect manually.")
        if dangerous:
            result["risk_level"] = "DANGER"
            for m, n in dangerous:
                result["findings"].append(
                    f"Dangerous call: imports {m}.{n} - can execute code on load.")
            result["recommendation"] = (
                "REJECT this file. It imports functions capable of executing "
                "system commands. Never load it. Ask the author to re-export as safetensors.")
        else:
            # It's a pickle, but nothing dangerous resolved.
            result["risk_level"] = "WARNING"
            safe_list = ", ".join(sorted({m for m, _ in globals_found})) or "none"
            result["findings"].append(
                f"Pickle format with no dangerous imports (uses: {safe_list}). "
                "Still executable in principle - prefer safetensors.")
            result["recommendation"] = (
                "No malicious calls detected, but pickle can execute code by design. "
                "Prefer safetensors for untrusted sources.")
    else:
        result["format"] = "unknown"
        result["risk_level"] = "WARNING"
        result["findings"].append("Unknown format - could not determine safety.")
        result["recommendation"] = "Manually inspect before loading."
    return result


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python serialization_scanner.py <filepath>")
    else:
        print(json.dumps(scan_file(sys.argv[1]), indent=2))
