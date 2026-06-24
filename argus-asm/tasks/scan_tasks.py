"""
Argus ASM — scan task

Wraps the existing recon -> normalise -> change-detect -> save
pipeline as a Celery task, so it can be:
    - triggered on a schedule (see scheduler.py)
    - queued and retried automatically on failure
    - run asynchronously without blocking a calling process (e.g. API)

This re-uses the exact same save_results() logic that main.py uses,
just imported here instead of duplicated.
"""

import logging
from datetime import datetime

from tasks.celery_app import celery_app
from recon import run_all
from pipeline.normalise import normalise_results
from db import get_db, init_db
from db.models import Asset
from db.change_detector import detect_changes

logger = logging.getLogger(__name__)


@celery_app.task(
    name="tasks.run_scan_task",
    bind=True,
    max_retries=2,
    default_retry_delay=60,  # seconds before retry
)
def run_scan_task(self, target: str, wordlist: str | None = None) -> dict:
    """
    Run a full recon scan against *target*, normalise the results,
    detect changes against the previous scan, and persist everything.

    Args:
        target:   Domain or IP to scan.
        wordlist: Optional path to a subdomain wordlist.

    Returns:
        Summary dict: {"target": ..., "changes_found": N, "scanned_at": ...}
    """
    logger.info(f"Starting scan for target: {target}")

    try:
        init_db()

        # Run the existing recon pipeline (Week 1)
        raw_results = run_all(target=target, wordlist=wordlist)

        # Clean the results (Week 2)
        normalised = normalise_results(raw_results)

        changes_found = 0

        with get_db() as db:
            asset = db.query(Asset).filter_by(domain=target).first()

            if asset is None:
                # First-ever scan of this target — nothing to diff against
                asset = Asset(domain=target)
                db.add(asset)
                db.flush()
                logger.info(f"First scan for {target} — no baseline to diff")
            else:
                # Detect changes BEFORE overwriting asset state
                events = detect_changes(db, asset, normalised)
                changes_found = len(events)
                if changes_found:
                    logger.info(
                        f"{changes_found} change(s) detected for {target}"
                    )

            # Update asset fields from this scan
            port_data = normalised.get("ports", {})
            if "resolved_ip" in port_data:
                asset.ip = port_data["resolved_ip"]

            whois = normalised.get("whois", {})
            if "error" not in whois:
                asset.registrar    = whois.get("registrar")
                asset.org          = whois.get("org")
                asset.country      = whois.get("country")
                asset.whois_expiry = whois.get("expires")

            asset.last_seen = datetime.utcnow()
            db.flush()

            _upsert_ports_and_banners(db, asset, normalised)

        logger.info(f"Scan complete for {target}: {changes_found} changes")

        return {
            "target": target,
            "changes_found": changes_found,
            "scanned_at": datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        logger.error(f"Scan failed for {target}: {exc}")
        # Retry with exponential-ish backoff up to max_retries
        raise self.retry(exc=exc)


def _upsert_ports_and_banners(db, asset: Asset, normalised: dict) -> None:
    """
    Shared upsert logic for ports + banners.
    Mirrors main.py's save_results() port/banner handling so both
    the CLI and the Celery task stay in sync.
    """
    import json
    from db.models import Port, Banner

    port_data = normalised.get("ports", {})
    existing_ports = {p.port: p for p in asset.ports}

    banners_by_port = {
        b["port"]: b
        for b in normalised.get("banners", {}).get("banners", [])
    }

    seen_ports = set()

    for port_info in port_data.get("open", []):
        port_num = port_info["port"]
        seen_ports.add(port_num)

        if port_num in existing_ports:
            port_obj = existing_ports[port_num]
            port_obj.state     = port_info.get("state", "open")
            port_obj.service   = port_info.get("service")
            port_obj.last_seen = datetime.utcnow()
            port_obj.is_active = True
        else:
            port_obj = Port(
                asset_id=asset.id,
                port=port_num,
                protocol="tcp",
                state=port_info.get("state", "open"),
                service=port_info.get("service"),
            )
            db.add(port_obj)
            db.flush()

        if port_num in banners_by_port:
            b = banners_by_port[port_num]
            banner_obj = port_obj.banner or Banner(port_id=port_obj.id)
            if not port_obj.banner:
                db.add(banner_obj)

            banner_obj.banner_type  = b.get("type")
            banner_obj.raw_banner   = b.get("banner")
            banner_obj.http_status  = b.get("status")
            banner_obj.http_headers = json.dumps(b.get("headers", {}))
            banner_obj.server       = b.get("server")
            banner_obj.powered_by   = b.get("powered_by")
            banner_obj.tls_subject  = json.dumps(b.get("tls_subject", {}))
            banner_obj.tls_issuer   = json.dumps(b.get("tls_issuer", {}))
            banner_obj.tls_expiry   = b.get("tls_expiry")
            banner_obj.scraped_at   = datetime.utcnow()

    # Mark ports not seen in this scan as inactive (don't delete — keep history)
    for port_num, port_obj in existing_ports.items():
        if port_num not in seen_ports:
            port_obj.is_active = False
