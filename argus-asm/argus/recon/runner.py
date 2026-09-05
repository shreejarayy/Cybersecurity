"""Reconnaissance runner: orchestrates the five recon modules concurrently.

This is the concurrency backbone described in FR1. DNS, subdomain discovery,
port scanning and WHOIS run in parallel; banner grabbing runs after the port
scan because it needs the list of open ports. The whole thing is gated by the
authorisation allow-list before any network activity begins.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import config
from .dns_enum import enumerate_dns
from .subdomain import discover_subdomains
from .port_scan import scan_ports, TOP_PORTS_LIST
from .banner import grab_banner
from .whois_lookup import lookup_whois
from .tls_cert import inspect_tls


def run_recon(target: str, threads: int = None, timeout: float = None,
              do_subdomains: bool = True) -> dict:
    """Run a full reconnaissance sweep against an AUTHORISED target.

    Returns a structured result dict. Raises UnauthorisedTargetError if the
    target is not on the allow-list (the safety gate).
    """
    # --- SAFETY GATE: nothing below runs for an unauthorised target ---
    config.require_authorised(target)

    threads = threads or config.PORT_SCAN_THREADS
    timeout = timeout or config.PORT_SCAN_TIMEOUT
    started = time.time()

    result = {
        "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "dns": {}, "subdomains": {}, "whois": {},
        "assets": [],   # one entry per resolved IP, with its ports+banners
        "errors": [],
    }

    # Subdomain discovery only makes sense for a domain, not a bare IP.
    import ipaddress
    try:
        ipaddress.ip_address(target)
        target_is_ip = True
    except Exception:
        target_is_ip = False

    # Kick off the independent tasks in parallel.
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_dns = pool.submit(enumerate_dns, target)
        f_who = pool.submit(lookup_whois, target)
        f_sub = pool.submit(discover_subdomains, target) \
            if (do_subdomains and not target_is_ip) else None

        result["dns"] = _safe(f_dns.result, result, "dns")
        result["whois"] = _safe(f_who.result, result, "whois")
        if f_sub is not None:
            result["subdomains"] = _safe(f_sub.result, result, "subdomains")

    # Determine the set of IPs to scan. Prefer IPv4; include IPv6 only if the
    # operator has explicitly enabled it (SCAN_IPV6).
    dns = result["dns"]
    ipv4 = dns.get("ipv4") or []
    ipv6 = dns.get("ipv6") or []
    if config.SCAN_IPV6:
        ips = ipv4 + ipv6
    else:
        ips = ipv4
    if not ips:
        # Fall back to any resolved address, then to the raw target.
        ips = (dns.get("ips") or [])[:1] or [target]

    # Port scan + banner grab per resolved IP.
    for ip in ips:
        ps = scan_ports(ip, ports=TOP_PORTS_LIST, threads=threads, timeout=timeout)
        ports = []
        for entry in ps["open_ports"]:
            b = grab_banner(ip, entry["port"], timeout=config.BANNER_TIMEOUT)
            port_rec = {
                "port": entry["port"],
                "service": entry["service"],
                "banner": b["banner"],
                "product": b["product"],
            }
            # Inspect the TLS certificate on encrypted service ports.
            if entry["port"] in config.TLS_PORTS:
                tls = inspect_tls(ip, entry["port"], timeout=config.BANNER_TIMEOUT + 2)
                if tls:
                    port_rec["tls"] = tls
            ports.append(port_rec)
        result["assets"].append({"ip": ip, "ports": ports, "port_count": len(ports)})

    result["duration_seconds"] = round(time.time() - started, 2)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result


def _safe(fn, result, label):
    try:
        return fn()
    except Exception as e:  # pragma: no cover - defensive
        result["errors"].append({"stage": label, "error": str(e)})
        return {}