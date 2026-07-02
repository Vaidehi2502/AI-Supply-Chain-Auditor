import json
from pathlib import Path
import torch
import numpy as np
from sklearn.ensemble import IsolationForest

def extract_weight_features(tensor) -> dict:
    """
    Extract statistical features from a weight tensor.
    These become the 'fingerprint' of each layer.
    Think of it like extracting features from a packet for IDS.
    """
    flat = tensor.float().flatten().numpy()
    
    if len(flat) == 0:
        return None

    features = {
        "mean": float(np.mean(flat)),
        "std": float(np.std(flat)),
        "min": float(np.min(flat)),
        "max": float(np.max(flat)),
        "abs_mean": float(np.mean(np.abs(flat))),
        # Kurtosis: measures how 'peaked' the distribution is
        # Normal weights ~ 3.0, backdoored weights often much higher
        "kurtosis": float(np.mean((flat - np.mean(flat))**4) / (np.std(flat)**4 + 1e-8)),
        # Sparsity: percentage of near-zero weights
        # Heavily pruned/backdoored models have unusual sparsity
        "sparsity": float(np.mean(np.abs(flat) < 1e-6)),
        "has_nan": bool(np.any(np.isnan(flat))),
        "has_inf": bool(np.any(np.isinf(flat))),
        "percentile_99": float(np.percentile(np.abs(flat), 99)),
    }
    return features


def run_isolation_forest(layer_features: list) -> dict:
    """
    Isolation Forest is an unsupervised ML algorithm.
    
    How it works:
    - It randomly splits the data space
    - Anomalous points get isolated faster (need fewer splits)
    - Returns anomaly score: -1 = anomaly, 1 = normal
    
    Think of it like: normal weights cluster together,
    backdoored layers stand out as outliers.
    """
    if len(layer_features) < 3:
        return {"anomalous_layers": [], "anomaly_scores": [], "method": "isolation_forest"}

    # Build feature matrix — each row is one layer's stats
    feature_matrix = []
    layer_names = []
    
    for name, features in layer_features:
        if features is None:
            continue
        row = [
            features["mean"],
            features["std"],
            features["abs_mean"],
            features["kurtosis"],
            features["sparsity"],
            features["percentile_99"],
        ]
        feature_matrix.append(row)
        layer_names.append(name)

    if len(feature_matrix) < 3:
        return {"anomalous_layers": [], "anomaly_scores": [], "method": "isolation_forest"}

    feature_matrix = np.array(feature_matrix)
    
    # Replace any NaN/Inf in features with 0
    feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=0.0, neginf=0.0)

    # Train Isolation Forest
    # contamination=0.1 means we expect up to 10% of layers to be anomalous
    clf = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100
    )
    predictions = clf.fit_predict(feature_matrix)
    scores = clf.score_samples(feature_matrix)

    # Collect anomalous layers
    anomalous = []
    for i, (pred, score) in enumerate(zip(predictions, scores)):
        if pred == -1:  # -1 means anomaly
            anomalous.append({
                "layer": layer_names[i],
                "anomaly_score": round(float(score), 4),
                # Lower score = more anomalous
                "severity": "HIGH" if score < -0.15 else "MEDIUM"
            })

    return {
        "anomalous_layers": anomalous,
        "total_layers": len(layer_names),
        "method": "isolation_forest",
        "anomaly_scores": [round(float(s), 4) for s in scores]
    }


def scan_weights(filepath: str) -> dict:
    """
    Scan model weights using ML-based anomaly detection.
    """
    result = {
        "file": filepath,
        "format": None,
        "layers_analyzed": 0,
        "risk_level": "SAFE",
        "findings": [],
        "stats": {},
        "ml_analysis": {},
        "recommendation": ""
    }

    filepath_obj = Path(filepath)

    # ── Safetensors ────────────────────────────────────────────────────
    if filepath_obj.suffix == ".safetensors":
        try:
            from safetensors import safe_open
            result["format"] = "safetensors"
            layer_features = []

            with safe_open(str(filepath_obj), framework="pt", device="cpu") as f:
                keys = list(f.keys())
                result["layers_analyzed"] = len(keys)

                for key in keys:
                    tensor = f.get_tensor(key)
                    features = extract_weight_features(tensor)
                    layer_features.append((key, features))

                    # Hard checks — these are always dangerous
                    if features and features["has_nan"]:
                        result["findings"].append(f"NaN values in layer: {key}")
                        result["risk_level"] = "DANGER"
                    if features and features["has_inf"]:
                        result["findings"].append(f"Inf values in layer: {key}")
                        result["risk_level"] = "DANGER"

            # Run ML analysis
            ml_result = run_isolation_forest(layer_features)
            result["ml_analysis"] = ml_result

            if ml_result["anomalous_layers"]:
                for anomaly in ml_result["anomalous_layers"]:
                    result["findings"].append(
                        f"ML anomaly detected in layer '{anomaly['layer']}' "
                        f"(severity: {anomaly['severity']}, score: {anomaly['anomaly_score']})"
                    )
                if result["risk_level"] == "SAFE":
                    result["risk_level"] = "WARNING"

        except Exception as e:
            result["findings"].append(f"Error: {e}")
            result["risk_level"] = "ERROR"

    # ── PyTorch / .bin ─────────────────────────────────────────────────
    elif filepath_obj.suffix in [".pt", ".pth", ".bin"]:
        try:
            result["format"] = "pytorch"
            state_dict = torch.load(
                str(filepath_obj),
                weights_only=True,
                map_location="cpu"
            )
            result["layers_analyzed"] = len(state_dict)
            layer_features = []

            for key, tensor in state_dict.items():
                features = extract_weight_features(tensor)
                layer_features.append((key, features))

                if features and features["has_nan"]:
                    result["findings"].append(f"NaN in layer: {key}")
                    result["risk_level"] = "DANGER"
                if features and features["has_inf"]:
                    result["findings"].append(f"Inf in layer: {key}")
                    result["risk_level"] = "DANGER"

            # Run ML analysis
            ml_result = run_isolation_forest(layer_features)
            result["ml_analysis"] = ml_result

            if ml_result["anomalous_layers"]:
                for anomaly in ml_result["anomalous_layers"]:
                    result["findings"].append(
                        f"ML anomaly in layer '{anomaly['layer']}' "
                        f"(severity: {anomaly['severity']}, score: {anomaly['anomaly_score']})"
                    )
                if result["risk_level"] == "SAFE":
                    result["risk_level"] = "WARNING"

            # Overall stats
            all_stds = [f["std"] for _, f in layer_features if f]
            if all_stds:
                result["stats"] = {
                    "mean_std_across_layers": round(float(np.mean(all_stds)), 4),
                    "max_std_across_layers": round(float(np.max(all_stds)), 4),
                    "layers": result["layers_analyzed"]
                }

        except Exception as e:
            result["findings"].append(f"Could not load model: {e}")
            result["risk_level"] = "ERROR"

    else:
        result["findings"].append("Unsupported format for weight analysis.")
        result["risk_level"] = "WARNING"

    if not result["findings"]:
        result["findings"].append(
            f"No anomalies detected across {result['layers_analyzed']} layers."
        )
        result["recommendation"] = "Weight distribution looks normal."

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python weight_scanner.py <model_file>")
    else:
        report = scan_weights(sys.argv[1])
        print(json.dumps(report, indent=2))