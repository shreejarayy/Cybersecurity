"""Context-aware risk scoring.

The composite risk for a port-node is:

    risk = CVSS_base * (1 + w_c*centrality + w_e*exposure_norm
                          + w_r*rarity + w_p*propagation)

capped at 10.0. The result is fully explainable: every composite can be broken
back down into the base score and each weighted contribution, so an analyst can
always see WHY something is ranked where it is.
"""
import config


def _norm_exposure(hours: float) -> float:
    """Map exposure hours to 0..1 (saturating at ~30 days)."""
    return min(1.0, hours / (24.0 * 30.0)) if hours > 0 else 0.0


def score_node(cvss_base: float, feat: dict, weights: dict = None) -> dict:
    """Return an explainable risk breakdown for a single port-node."""
    w = weights or config.RISK_WEIGHTS
    centrality = feat.get("degree_centrality", 0.0)
    exposure = _norm_exposure(feat.get("exposure_hours", 0.0))
    rarity = feat.get("rarity", 0.0)
    propagation = feat.get("propagation", 0.0)

    contrib = {
        "centrality": w["centrality"] * centrality,
        "exposure": w["exposure"] * exposure,
        "rarity": w["rarity"] * rarity,
        "propagation": w["propagation"] * propagation,
    }
    multiplier = 1.0 + sum(contrib.values())
    composite = min(10.0, round(cvss_base * multiplier, 2))

    return {
        "cvss_base": round(cvss_base, 2),
        "multiplier": round(multiplier, 3),
        "composite_risk": composite,
        "contributions": {k: round(v, 3) for k, v in contrib.items()},
        "inputs": {
            "degree_centrality": round(centrality, 4),
            "exposure_norm": round(exposure, 4),
            "rarity": round(rarity, 4),
            "propagation": round(propagation, 4),
        },
    }


def score_surface(features: dict, cvss_by_node: dict,
                  anomalies: dict = None, weights: dict = None) -> list:
    """Score every port-node and return a list sorted by composite risk desc."""
    anomalies = anomalies or {}
    rows = []
    for node, feat in features.items():
        if feat.get("kind") != "port":
            continue
        cvss = cvss_by_node.get(node, 0.0)
        # If no CVE matched, still surface exposure-driven risk with a small base.
        base = cvss if cvss > 0 else 2.0
        breakdown = score_node(base, feat, weights)
        breakdown["node"] = node
        breakdown["service"] = feat.get("service")
        breakdown["product"] = feat.get("product", "")
        breakdown["cve_matched"] = cvss > 0
        an = anomalies.get(node, {})
        breakdown["anomaly_score"] = an.get("anomaly_score", 0.0)
        breakdown["is_anomaly"] = an.get("is_anomaly", False)
        rows.append(breakdown)
    rows.sort(key=lambda r: r["composite_risk"], reverse=True)
    return rows
