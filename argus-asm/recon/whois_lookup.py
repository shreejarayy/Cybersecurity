"""
Argus ASM — WHOIS lookup
Retrieves registrar, registrant org, creation/expiry dates,
name servers, and status flags for a domain using python-whois.
"""

import whois
from typing import Any
from datetime import datetime


def _normalise_date(val: Any) -> str | None:
    """
    python-whois returns dates as datetime objects or lists of datetimes.
    Normalise to an ISO-8601 string, or None if unavailable.
    """
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _normalise_list(val: Any) -> list[str]:
    """Ensure the value is always a list of strings."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def lookup_whois(target: str) -> dict[str, Any]:
    """
    Perform a WHOIS lookup on *target*.

    Args:
        target: Domain name (e.g. "example.com").

    Returns:
        {
            "target":       "example.com",
            "registrar":    "IANA",
            "org":          "Internet Assigned Numbers Authority",
            "country":      "US",
            "created":      "1992-01-01T00:00:00",
            "expires":      "2024-01-01T00:00:00",
            "updated":      "2023-08-01T00:00:00",
            "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
            "status":       ["clientDeleteProhibited", ...],
            "emails":       ["abuse@iana.org"],
        }
    """
    try:
        w = whois.whois(target)
    except Exception as exc:
        return {"target": target, "error": str(exc)}

    return {
        "target":       target,
        "registrar":    w.registrar or None,
        "org":          w.org or None,
        "country":      w.country or None,
        "created":      _normalise_date(w.creation_date),
        "expires":      _normalise_date(w.expiration_date),
        "updated":      _normalise_date(w.updated_date),
        "name_servers": _normalise_list(w.name_servers),
        "status":       _normalise_list(w.status),
        "emails":       _normalise_list(w.emails),
    }
