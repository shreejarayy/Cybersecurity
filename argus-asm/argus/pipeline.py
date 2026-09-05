"""End-to-end scan pipeline: recon -> change detection -> persist -> analyse.

This is the function the CLI, the scheduler, and the API's on-demand endpoint all
call. It returns a single dict containing the recon result, detected changes, the
ASEG graph, anomaly scores, and the ranked, explainable risk report.
"""
import config
from .recon.runner import run_recon
from .detection.change_detector import detect_changes
from .analysis import aseg, anomaly, risk, cve as cve_mod


def run_full_scan(target: str, use_db: bool = True, correlate_cve: bool = True,
                  previous_result: dict = None) -> dict:
    """Run one complete analysis cycle for an authorised target."""
    # 1. Reconnaissance (authorisation is enforced inside run_recon).
    recon = run_recon(target)

    # 2. Change detection against the previous baseline.
    prev = previous_result
    if use_db and prev is None:
        prev = _load_previous_from_db(target)
    changes = detect_changes(prev, recon)

    # 3. Persist (optional).
    scan_id = None
    if use_db:
        from .persistence.db import persist_scan
        scan_id = persist_scan(recon, changes)

        # 4. Build the ASEG and features.
    graph, features = aseg.build_graph(recon)

    # 4b. Build the previous scan's graph too, so the dashboard can overlay the
    # current and last scans and show the visual difference.
    prev_graph_dict = {}
    if prev and prev.get("assets"):
        try:
            _pg, _pf = aseg.build_graph({"target": target,
                                         "assets": prev.get("assets", []),
                                         "subdomains": prev.get("subdomains", {})})
            prev_graph_dict = aseg.graph_to_dict(_pg, _pf)
        except Exception:
            prev_graph_dict = {}

    # 5. CVE correlation per port -> base CVSS by node.
    cvss_by_node = {}
    cve_details = {}
    if correlate_cve:
        for a in recon.get("assets", []):
            for p in a.get("ports", []):
                node = f"{a['ip']}:{p['port']}"
                corr = cve_mod.correlate(p.get("product", ""))
                cvss_by_node[node] = corr["max_cvss"]
                if corr["cve_count"]:
                    cve_details[node] = corr

    # 6. Anomaly detection over the structural features.
    anomalies = anomaly.score_anomalies(features)

    # 7. Context-aware, explainable risk ranking.
    risk_report = risk.score_surface(features, cvss_by_node, anomalies)

    # 7b. Persist the top risk for this scan (drives the trend chart) and raise
    # alerts for newly-opened ports that score at or above the alert threshold.
    top_risk = risk_report[0]["composite_risk"] if risk_report else 0.0
    if use_db and scan_id is not None:
        try:
            from .persistence.db import update_scan_max_risk
            update_scan_max_risk(scan_id, top_risk)
        except Exception:
            pass

    new_ports = {c["detail"].split()[1] for c in changes if c["event_type"] == "new_port"}
    alerts = []
    for r in risk_report:
        port_str = r["node"].split(":")[-1]
        if r["composite_risk"] >= config.ALERT_THRESHOLD and port_str in new_ports:
            alerts.append({"node": r["node"], "service": r["service"],
                           "risk": r["composite_risk"], "cvss_base": r["cvss_base"]})
    if alerts:
        _dispatch_alerts(target, alerts)

    return {
        "target": target,
        "scan_id": scan_id,
        "recon": recon,
        "changes": changes,
        "graph": aseg.graph_to_dict(graph, features),
        "prev_graph": prev_graph_dict,        "anomalies": anomalies,
        "cve_details": cve_details,
        "risk_report": risk_report,
        "alerts": alerts,
        "summary": {
            "assets": len(recon.get("assets", [])),
            "open_ports": sum(a["port_count"] for a in recon.get("assets", [])),
            "changes": len(changes),
            "anomalies": sum(1 for v in anomalies.values() if v["is_anomaly"]),
            "top_risk": top_risk,
            "alerts": len(alerts),
            "duration_seconds": recon.get("duration_seconds", 0.0),
        },
    }


def _dispatch_alerts(target: str, alerts: list) -> None:
    """Log high-risk alerts and optionally POST them to a configured webhook."""
    for a in alerts:
        print(f"[ALERT] {target}: {a['node']} ({a['service']}) risk {a['risk']}")
    if config.ALERT_WEBHOOK:
        try:
            import requests
            requests.post(config.ALERT_WEBHOOK,
                          json={"text": f"ArgusPredict alert on {target}: "
                                        f"{len(alerts)} high-risk finding(s)",
                                "alerts": alerts}, timeout=6)
        except Exception:
            pass


def _load_previous_from_db(target: str):
    """Reconstruct the previous scan's result dict from the database, if any."""
    try:
        from sqlalchemy import select
        from .persistence.db import session_scope, latest_scan
        from .persistence.models import Target, Asset, Port, Banner
        with session_scope() as s:
            t = s.scalar(select(Target).where(Target.hostname == target))
            if not t:
                return None
            scan = latest_scan(s, t.id)
            if not scan:
                return None
            assets = []
            for a in s.scalars(select(Asset).where(Asset.scan_id == scan.id)):
                ports = []
                for p in s.scalars(select(Port).where(Port.asset_id == a.id)):
                    ban = s.scalar(select(Banner).where(Banner.port_id == p.id))
                    ports.append({"port": p.number, "service": p.service,
                                  "product": ban.product if ban else "",
                                  "banner": ban.raw if ban else ""})
                assets.append({"ip": a.ip, "ports": ports, "port_count": len(ports)})
            return {"target": target, "assets": assets, "subdomains": {}}
    except Exception:
        return None