"""
Argus ASM — normalisation pipeline

Raw output from recon/runner.py is inconsistent in small ways:
  - domains sometimes have trailing dots ("example.com.")
  - IPs may appear as strings with leading/trailing whitespace
  - subdomain results may contain duplicates if DNS returns multiple
    matching records across different queries
  - banner text may contain control characters from raw TCP reads

normalise_results() takes the raw dict from run_all() and returns
a cleaned version safe to pass directly to change_detector.py and
the database layer.
"""

import re
from typing import Any


def _clean_domain(domain: str) -> str:
    """Lowercase, strip whitespace, remove trailing dot."""
    return domain.strip().lower().rstrip(".")


def _clean_ip(ip: str) -> str:
    """Strip whitespace from an IP string."""
    return ip.strip()


def _clean_banner_text(text: str) -> str:
    """
    Remove non-printable control characters from raw banner strings.
    Keeps the banner readable and safe for DB storage / display.
    """
    if not text:
        return ""
    # Strip ASCII control chars except newline/tab, then collapse whitespace
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:500]  # cap length — banners shouldn't be unbounded


def _dedupe_list_of_dicts(items: list[dict], key: str) -> list[dict]:
    """Remove duplicate dicts from a list based on a given key."""
    seen = set()
    result = []
    for item in items:
        val = item.get(key)
        if val not in seen:
            seen.add(val)
            result.append(item)
    return result


def normalise_results(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Clean and deduplicate a raw results dict from recon.run_all().

    Args:
        raw: The dict returned by run_all(), with keys
             dns, subdomains, ports, whois, banners.

    Returns:
        A new dict with the same shape, but cleaned values.
        Does not mutate the input.
    """
    normalised: dict[str, Any] = {}

    # ---------------------------------------------------------------- #
    # DNS records — strip whitespace, dedupe within each record type
    # ---------------------------------------------------------------- #
    dns = raw.get("dns", {})
    if "error" not in dns:
        normalised["dns"] = {
            "target": _clean_domain(dns.get("target", "")),
            "records": {
                rtype: sorted(set(v.strip() for v in values if v.strip()))
                for rtype, values in dns.get("records", {}).items()
            },
        }
    else:
        normalised["dns"] = dns

    # ---------------------------------------------------------------- #
    # Subdomains — clean domain names, dedupe by subdomain string
    # ---------------------------------------------------------------- #
    subs = raw.get("subdomains", {})
    if "error" not in subs:
        cleaned_found = []
        for entry in subs.get("found", []):
            cleaned_found.append({
                "subdomain": _clean_domain(entry.get("subdomain", "")),
                "ips": sorted(set(_clean_ip(ip) for ip in entry.get("ips", []))),
            })
        cleaned_found = _dedupe_list_of_dicts(cleaned_found, "subdomain")
        normalised["subdomains"] = {
            "target": _clean_domain(subs.get("target", "")),
            "found": cleaned_found,
            "total_checked": subs.get("total_checked", 0),
        }
    else:
        normalised["subdomains"] = subs

    # ---------------------------------------------------------------- #
    # Ports — dedupe by port number, normalise service names
    # ---------------------------------------------------------------- #
    ports = raw.get("ports", {})
    if "error" not in ports:
        cleaned_open = _dedupe_list_of_dicts(ports.get("open", []), "port")
        for p in cleaned_open:
            p["service"] = (p.get("service") or "unknown").strip()
        cleaned_open.sort(key=lambda x: x["port"])
        normalised["ports"] = {
            "target": _clean_domain(ports.get("target", "")),
            "resolved_ip": _clean_ip(ports.get("resolved_ip", "")),
            "open": cleaned_open,
            "total_scanned": ports.get("total_scanned", 0),
        }
    else:
        normalised["ports"] = ports

    # ---------------------------------------------------------------- #
    # WHOIS — strip whitespace from all string fields
    # ---------------------------------------------------------------- #
    whois = raw.get("whois", {})
    if "error" not in whois:
        normalised["whois"] = {
            "target":       _clean_domain(whois.get("target", "")),
            "registrar":    (whois.get("registrar") or "").strip() or None,
            "org":          (whois.get("org") or "").strip() or None,
            "country":      (whois.get("country") or "").strip() or None,
            "created":      whois.get("created"),
            "expires":      whois.get("expires"),
            "updated":      whois.get("updated"),
            "name_servers": sorted(set(
                ns.strip().lower().rstrip(".")
                for ns in whois.get("name_servers", [])
            )),
            "status":       whois.get("status", []),
            "emails":       sorted(set(
                e.strip().lower() for e in whois.get("emails", [])
            )),
        }
    else:
        normalised["whois"] = whois

    # ---------------------------------------------------------------- #
    # Banners — dedupe by port, clean raw banner text
    # ---------------------------------------------------------------- #
    banners = raw.get("banners", {})
    if "error" not in banners:
        cleaned_banners = _dedupe_list_of_dicts(
            banners.get("banners", []), "port"
        )
        for b in cleaned_banners:
            if "banner" in b:
                b["banner"] = _clean_banner_text(b["banner"])
            if "server" in b and b["server"]:
                b["server"] = _clean_banner_text(b["server"])
        cleaned_banners.sort(key=lambda x: x["port"])
        normalised["banners"] = {
            "target": _clean_domain(banners.get("target", "")),
            "banners": cleaned_banners,
        }
    else:
        normalised["banners"] = banners

    return normalised
