"""Anomaly detection over ASEG node features using an Isolation Forest.

The model scores each port-node by how structurally unusual it is relative to
the rest of the surface. When scikit-learn is unavailable, it falls back to a
robust z-score so the pipeline still produces sensible output.
"""
import config

FEATURE_KEYS = ["degree_centrality", "betweenness_centrality", "rarity",
                "exposure_hours", "propagation"]


def _vectorise(features: dict):
    nodes, X = [], []
    for node, f in features.items():
        if f.get("kind") != "port":
            continue
        nodes.append(node)
        X.append([float(f.get(k, 0.0)) for k in FEATURE_KEYS])
    return nodes, X


def score_anomalies(features: dict, threshold: float = None) -> dict:
    """Return {node: {'anomaly_score': 0..1, 'is_anomaly': bool}} for port nodes."""
    threshold = config.ANOMALY_THRESHOLD if threshold is None else threshold
    nodes, X = _vectorise(features)
    if not nodes:
        return {}

    scores = None
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np
        if len(X) >= 4:  # IsolationForest needs a few samples to be meaningful
            model = IsolationForest(contamination="auto", random_state=42)
            model.fit(X)
            raw = model.score_samples(X)  # higher = more normal
            arr = np.array(raw)
            lo, hi = arr.min(), arr.max()
            # invert + normalise to 0..1 where 1 = most anomalous
            norm = (hi - arr) / (hi - lo) if hi > lo else np.zeros_like(arr)
            scores = norm.tolist()
    except Exception:
        scores = None

    if scores is None:
        scores = _zscore_fallback(X)

    out = {}
    for node, sc in zip(nodes, scores):
        out[node] = {"anomaly_score": round(float(sc), 3),
                     "is_anomaly": bool(sc >= threshold)}
    return out


def _zscore_fallback(X):
    n = len(X)
    dim = len(X[0])
    means = [sum(row[j] for row in X) / n for j in range(dim)]
    vars_ = [sum((row[j] - means[j]) ** 2 for row in X) / n for j in range(dim)]
    stds = [v ** 0.5 or 1.0 for v in vars_]
    out = []
    for row in X:
        z = sum(abs((row[j] - means[j]) / stds[j]) for j in range(dim)) / dim
        out.append(min(1.0, z / 3.0))  # ~3 sigma -> 1.0
    return out
