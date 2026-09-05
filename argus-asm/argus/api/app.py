"""Flask REST API for ArgusPredict.

Endpoints:
  GET  /                       -> dashboard (static)
  GET  /api/health            -> liveness + authorised targets
  GET  /api/targets           -> configured/known targets
  POST /api/scan              -> run an on-demand scan {"target": "..."} (authorised only)
  GET  /api/latest/<target>   -> last in-memory pipeline result (graph/risk/changes)
  GET  /api/history/<target>  -> scan history with per-scan metrics (ports, changes, risk)
  GET  /api/changes/<target>  -> recent change events from the database
  GET  /api/diff/<target>?a=<id>&b=<id> -> typed differences between two stored scans
  GET  /api/report/<target>   -> PDF findings report for the last scan
  GET  /api/schedule          -> scheduled-scan status
  POST /api/schedule/start    -> start periodic scans {"target","hours"}
  POST /api/schedule/stop     -> stop periodic scans {"target"}
"""
import os
import hmac

from flask import Flask, jsonify, request, send_from_directory, Response
from sqlalchemy import select, func

import config
from argus.pipeline import run_full_scan
from argus.detection.change_detector import detect_changes
from argus.persistence.db import init_db, session_scope
from argus.persistence.models import Target, Scan, Asset, Port, Banner, Change

# In-memory cache of the most recent full result per target (for the dashboard).
_LATEST = {}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Background scheduler for periodic scans started from the UI (created lazily).
_scheduler = None


def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            _scheduler = BackgroundScheduler()
            _scheduler.start()
        except Exception:
            _scheduler = None
    return _scheduler


def _scheduled_scan(target):
    try:
        _LATEST[target] = run_full_scan(target, use_db=True, correlate_cve=True)
    except Exception as e:
        print(f"[scheduler] {target}: {e}")


def _reconstruct_scan(session, scan_id: int, target: str) -> dict:
    """Rebuild a recon-result-shaped dict from a stored scan (for diffing)."""
    assets = []
    for a in session.scalars(select(Asset).where(Asset.scan_id == scan_id)):
        ports = []
        for p in session.scalars(select(Port).where(Port.asset_id == a.id)):
            ban = session.scalar(select(Banner).where(Banner.port_id == p.id))
            ports.append({"port": p.number, "service": p.service,
                          "product": ban.product if ban else "",
                          "banner": ban.raw if ban else ""})
        assets.append({"ip": a.ip, "ports": ports, "port_count": len(ports)})
    return {"target": target, "assets": assets, "subdomains": {}}


def create_app():
    app = Flask(__name__, static_folder=None)
    try:
        from flask_cors import CORS
        CORS(app)
    except Exception:
        pass
        init_db()

    @app.before_request
    def _require_login():
        # Auth off when no password configured (local dev). Health check is
        # always open so hosting platforms can probe liveness.
        if not config.APP_PASSWORD or request.path == "/api/health":
            return None
        auth = request.authorization
        ok = (auth and auth.username == config.APP_USERNAME
              and hmac.compare_digest(auth.password or "", config.APP_PASSWORD))
        if not ok:
            return Response("Authentication required.", 401,
                            {"WWW-Authenticate": 'Basic realm="ArgusPredict"'})
        return None

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:fname>")
    def static_files(fname):
        return send_from_directory(STATIC_DIR, fname)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "authorised_targets": config.AUTHORISED_TARGETS})

    @app.get("/api/targets")
    def targets():
        known = []
        with session_scope() as s:
            for t in s.scalars(select(Target)):
                known.append({"hostname": t.hostname, "authorised": t.authorised})
        return jsonify({"authorised": config.AUTHORISED_TARGETS, "known": known})

    @app.post("/api/scan")
    def scan():
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        if not target:
            return jsonify({"error": "missing 'target'"}), 400
        if not config.is_authorised(target):
            return jsonify({"error": f"'{target}' is not authorised",
                            "authorised": config.AUTHORISED_TARGETS}), 403
        try:
            result = run_full_scan(target, use_db=True,
                                   correlate_cve=data.get("correlate_cve", True))
        except config.UnauthorisedTargetError as e:
            return jsonify({"error": str(e)}), 403
        _LATEST[target] = result
        return jsonify(result)

    @app.get("/api/latest/<path:target>")
    def latest(target):
        if target not in _LATEST:
            return jsonify({"error": "no scan run yet for this target"}), 404
        return jsonify(_LATEST[target])

    @app.get("/api/history/<path:target>")
    def history(target):
        """Scan history with per-scan metrics so the UI can plot trends."""
        out = []
        with session_scope() as s:
            t = s.scalar(select(Target).where(Target.hostname == target))
            if t:
                for sc in s.scalars(select(Scan).where(Scan.target_id == t.id)
                                    .order_by(Scan.started_at.asc())):
                    # open ports = ports on assets belonging to this scan
                    port_count = s.scalar(
                        select(func.count(Port.id)).join(Asset, Port.asset_id == Asset.id)
                        .where(Asset.scan_id == sc.id)) or 0
                    asset_count = s.scalar(
                        select(func.count(Asset.id)).where(Asset.scan_id == sc.id)) or 0
                    change_count = s.scalar(
                        select(func.count(Change.id)).where(Change.scan_id == sc.id)) or 0
                    out.append({
                        "scan_id": sc.id,
                        "started_at": str(sc.started_at),
                        "duration_seconds": sc.duration_seconds,
                        "assets": int(asset_count),
                        "open_ports": int(port_count),
                        "changes": int(change_count),
                        "max_risk": round(getattr(sc, "max_risk", 0.0) or 0.0, 2),
                    })
        return jsonify({"target": target, "scans": out})

    @app.get("/api/changes/<path:target>")
    def changes(target):
        out = []
        with session_scope() as s:
            t = s.scalar(select(Target).where(Target.hostname == target))
            if t:
                scan_ids = [sc.id for sc in s.scalars(
                    select(Scan).where(Scan.target_id == t.id))]
                if scan_ids:
                    q = select(Change).where(Change.scan_id.in_(scan_ids)) \
                        .order_by(Change.detected_at.desc())
                    for c in s.scalars(q):
                        out.append({"event_type": c.event_type, "detail": c.detail,
                                    "asset_ip": c.asset_ip, "scan_id": c.scan_id,
                                    "detected_at": str(c.detected_at)})
        return jsonify({"target": target, "changes": out[:200]})

    @app.get("/api/diff/<path:target>")
    def diff(target):
        """Typed differences between two stored scans (?a=<id>&b=<id>)."""
        try:
            a_id = int(request.args.get("a"))
            b_id = int(request.args.get("b"))
        except (TypeError, ValueError):
            return jsonify({"error": "provide integer scan ids ?a=<id>&b=<id>"}), 400
        with session_scope() as s:
            a = _reconstruct_scan(s, a_id, target)
            b = _reconstruct_scan(s, b_id, target)
        events = detect_changes(a, b)  # what changed going from A -> B
        return jsonify({"target": target, "from_scan": a_id, "to_scan": b_id,
                        "changes": events})

    @app.get("/api/report/<path:target>")
    def report(target):
        """Download a PDF findings report for the last scan of this target."""
        if target not in _LATEST:
            return jsonify({"error": "run a scan for this target first"}), 404
        try:
            from argus.api.report import build_pdf
            pdf = build_pdf(_LATEST[target])
        except Exception as e:
            return jsonify({"error": f"report generation failed: {e}"}), 500
        return Response(pdf, mimetype="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="arguspredict_{target}.pdf"'})

    @app.get("/api/schedule")
    def schedule_status():
        sched = _get_scheduler()
        jobs = []
        if sched:
            for j in sched.get_jobs():
                jobs.append({"target": j.id.replace("scan:", ""),
                             "next_run": str(j.next_run_time) if j.next_run_time else None})
        return jsonify({"running": sched is not None, "jobs": jobs})

    @app.post("/api/schedule/start")
    def schedule_start():
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        hours = float(data.get("hours", config.SCAN_INTERVAL_HOURS))
        if not config.is_authorised(target):
            return jsonify({"error": f"'{target}' is not authorised"}), 403
        sched = _get_scheduler()
        if not sched:
            return jsonify({"error": "scheduler unavailable (install APScheduler)"}), 500
        sched.add_job(_scheduled_scan, "interval", hours=max(0.02, hours),
                      args=[target], id=f"scan:{target}", replace_existing=True)
        # run one immediately so the user sees data straight away
        _scheduled_scan(target)
        return jsonify({"ok": True, "target": target, "hours": hours})

    @app.post("/api/schedule/stop")
    def schedule_stop():
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        sched = _get_scheduler()
        if sched:
            try:
                sched.remove_job(f"scan:{target}")
            except Exception:
                pass
        return jsonify({"ok": True, "target": target})

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8050"))
    create_app().run(host="0.0.0.0", port=port, debug=False)