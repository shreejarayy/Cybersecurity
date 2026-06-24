"""
Argus ASM — change detection

Compares a freshly normalised scan result against what's currently
stored in the database for the same target, and produces a list of
"change events":
    - new_port_opened
    - port_closed
    - new_subdomain_found
    - banner_changed
    - whois_changed

Each change event is written to the `changes` table so the dashboard
(Week 8-9) can show a timeline, and so the AI anomaly detector
(Week 5-7) has labelled history to train on.
"""

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from db.models import Asset, Port, Banner, Change


def _get_existing_port_numbers(asset: Asset) -> set[int]:
    """Return the set of currently-active port numbers for an asset."""
    return {p.port for p in asset.ports if p.is_active}


def _get_existing_banner_text(asset: Asset, port_num: int) -> str | None:
    """Return the stored banner text for a given port, if any."""
    for p in asset.ports:
        if p.port == port_num and p.banner:
            return p.banner.raw_banner or p.banner.server
    return None


def detect_changes(
    db: Session,
    asset: Asset,
    normalised: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Compare *normalised* scan results against the current DB state
    for *asset*, and return a list of change-event dicts.

    This function does NOT write the new scan data to the asset —
    that's still main.py's job. It only detects and records changes,
    so it should be called BEFORE the new data overwrites the old.

    Args:
        db:         Active SQLAlchemy session.
        asset:      The Asset ORM object as it currently exists in DB
                    (i.e. state from the previous scan).
        normalised: The normalised results dict for the CURRENT scan.

    Returns:
        List of change-event dicts, e.g.:
        [
            {"type": "new_port_opened", "port": 8080, "detail": "..."},
            {"type": "port_closed",     "port": 21,   "detail": "..."},
        ]
        Each event is also persisted to the `changes` table.
    """
    events: list[dict[str, Any]] = []

    # ---------------------------------------------------------------- #
    # Port changes
    # ---------------------------------------------------------------- #
    old_ports = _get_existing_port_numbers(asset)
    new_ports_data = normalised.get("ports", {}).get("open", [])
    new_ports = {p["port"] for p in new_ports_data}

    newly_opened = new_ports - old_ports
    newly_closed = old_ports - new_ports

    for port_num in newly_opened:
        port_info = next(
            (p for p in new_ports_data if p["port"] == port_num), {}
        )
        events.append({
            "type": "new_port_opened",
            "port": port_num,
            "detail": f"Port {port_num} ({port_info.get('service', 'unknown')}) "
                      f"opened on {asset.domain}",
        })

    for port_num in newly_closed:
        events.append({
            "type": "port_closed",
            "port": port_num,
            "detail": f"Port {port_num} closed on {asset.domain}",
        })

    # ---------------------------------------------------------------- #
    # Banner changes — only check ports that were open in both scans
    # ---------------------------------------------------------------- #
    persisting_ports = old_ports & new_ports
    new_banners = {
        b["port"]: (b.get("banner") or b.get("server"))
        for b in normalised.get("banners", {}).get("banners", [])
    }

    for port_num in persisting_ports:
        old_banner = _get_existing_banner_text(asset, port_num)
        new_banner = new_banners.get(port_num)
        if new_banner and old_banner and new_banner != old_banner:
            events.append({
                "type": "banner_changed",
                "port": port_num,
                "detail": f"Banner on port {port_num} changed from "
                          f"'{old_banner[:60]}' to '{new_banner[:60]}'",
            })

    # ---------------------------------------------------------------- #
    # Subdomain changes
    # ---------------------------------------------------------------- #
    old_subdomains = {
        p.domain for p in db.query(Asset).filter(
            Asset.domain.like(f"%.{asset.domain}")
        ).all()
    }
    new_subdomains_data = normalised.get("subdomains", {}).get("found", [])
    new_subdomains = {s["subdomain"] for s in new_subdomains_data}

    for sub in (new_subdomains - old_subdomains):
        events.append({
            "type": "new_subdomain_found",
            "port": None,
            "detail": f"New subdomain discovered: {sub}",
        })

    # ---------------------------------------------------------------- #
    # WHOIS changes — registrar or expiry date changed
    # ---------------------------------------------------------------- #
    new_whois = normalised.get("whois", {})
    if "error" not in new_whois:
        if asset.registrar and new_whois.get("registrar") and \
           asset.registrar != new_whois["registrar"]:
            events.append({
                "type": "whois_changed",
                "port": None,
                "detail": f"Registrar changed from '{asset.registrar}' "
                          f"to '{new_whois['registrar']}'",
            })
        if asset.whois_expiry and new_whois.get("expires") and \
           asset.whois_expiry != new_whois["expires"]:
            events.append({
                "type": "whois_changed",
                "port": None,
                "detail": f"Domain expiry date changed to "
                          f"{new_whois['expires']}",
            })

    # ---------------------------------------------------------------- #
    # Persist all events to the changes table
    # ---------------------------------------------------------------- #
    for event in events:
        change = Change(
            asset_id=asset.id,
            change_type=event["type"],
            port=event.get("port"),
            detail=event["detail"],
            detected_at=datetime.utcnow(),
        )
        db.add(change)

    return events
