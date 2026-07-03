import os, pickle, numpy as np
OUT = os.path.join(os.path.dirname(__file__), "demo_models")
os.makedirs(OUT, exist_ok=True)

def make_clean():
    model = {
        "layer1.weight": np.random.randn(64, 128).astype(np.float32),
        "layer1.bias": np.zeros(64, dtype=np.float32),
        "layer2.weight": np.random.randn(10, 64).astype(np.float32),
        "meta": {"arch": "mlp", "task": "demo-classifier"},
    }
    with open(os.path.join(OUT, "clean_model.pkl"), "wb") as f:
        pickle.dump(model, f)
    print("wrote clean_model.pkl")

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
