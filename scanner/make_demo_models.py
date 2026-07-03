import os, pickle, numpy as np
from safetensors.numpy import save_file
OUT = os.path.join(os.path.dirname(__file__), "demo_models")
os.makedirs(OUT, exist_ok=True)

def make_clean():
    # Safetensors format is sandboxed (no code execution) and, at 2 tensors,
    # stays under weight_scanner's isolation-forest minimum of 3 layers -
    # so this passes as SAFE end-to-end rather than WARNING.
    tensors = {
        "layer1.weight": (np.random.randn(64, 128) * 0.02).astype(np.float32),
        "layer1.bias": (np.random.randn(64) * 0.002).astype(np.float32),
    }
    save_file(
        tensors,
        os.path.join(OUT, "clean_model.safetensors"),
        metadata={"arch": "mlp", "task": "demo-classifier"},
    )
    print("wrote clean_model.safetensors")

class _Payload:
    def __reduce__(self):
        import os as _os
        return (_os.system, ("echo PWNED -- model gate demo payload",))

def make_poisoned():
    model = {
        "layer1.weight": np.random.randn(64, 128).astype(np.float32),
        "layer1.bias": np.zeros(64, dtype=np.float32),
        "meta": {"arch": "mlp", "task": "demo-classifier"},
        "__hook__": _Payload(),
    }
    with open(os.path.join(OUT, "poisoned_model.pkl"), "wb") as f:
        pickle.dump(model, f)
    print("wrote poisoned_model.pkl")

make_clean()
make_poisoned()
print("done")
