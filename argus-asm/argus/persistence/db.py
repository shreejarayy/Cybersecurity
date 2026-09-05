"""Database engine, session management, and helpers to persist a scan result."""
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import config
from .models import Base, Target, Scan, Asset, Port, Banner, Change

_engine = None
_Session = None


def init_db(url: str = None):
    """Create the engine and tables. Safe to call repeatedly."""
    global _engine, _Session
    url = url or config.DATABASE_URL
    _engine = create_engine(url, future=True)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)
    return _engine


@contextmanager
def session_scope():
    """Transactional session: commits on success, rolls back on error."""
    if _Session is None:
        init_db()
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_or_create_target(session, hostname: str) -> Target:
    t = session.scalar(select(Target).where(Target.hostname == hostname))
    if t is None:
        t = Target(hostname=hostname, authorised=config.is_authorised(hostname))
        session.add(t)
        session.flush()
    return t


def latest_scan(session, target_id: int):
    """Return the most recent completed scan for a target, or None."""
    return session.scalar(
        select(Scan).where(Scan.target_id == target_id)
        .order_by(Scan.started_at.desc())
    )


def persist_scan(recon_result: dict, changes: list = None) -> int:
    """Persist a recon result (and optional detected changes). Returns scan id."""
    changes = changes or []
    with session_scope() as s:
        target = get_or_create_target(s, recon_result["target"])
        scan = Scan(
            target_id=target.id,
            started_at=_parse(recon_result.get("started_at")),
            finished_at=_parse(recon_result.get("finished_at")),
            duration_seconds=recon_result.get("duration_seconds", 0.0),
            error_count=len(recon_result.get("errors", [])),
        )
        s.add(scan)
        s.flush()

        for a in recon_result.get("assets", []):
            asset = Asset(scan_id=scan.id, ip=a["ip"], hostname=recon_result["target"])
            s.add(asset)
            s.flush()
            for p in a.get("ports", []):
                port = Port(asset_id=asset.id, number=p["port"],
                            service=p.get("service", "unknown"), state="open")
                s.add(port)
                s.flush()
                if p.get("banner") or p.get("product"):
                    s.add(Banner(port_id=port.id, raw=p.get("banner", ""),
                                 product=p.get("product", "")))

        for c in changes:
            s.add(Change(scan_id=scan.id, asset_ip=c.get("asset_ip", ""),
                         event_type=c["event_type"], detail=c.get("detail", "")))
        return scan.id


def _parse(v):
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None


def update_scan_max_risk(scan_id: int, max_risk: float) -> None:
    """Store the top composite risk for a scan (used by the trend chart)."""
    from .models import Scan
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is not None:
            scan.max_risk = float(max_risk)