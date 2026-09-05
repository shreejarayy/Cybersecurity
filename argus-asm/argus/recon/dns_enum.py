"""DNS enumeration: resolve a target's A/AAAA/MX/NS/TXT records.

Uses dnspython when available and falls back to the standard library so the
module still returns useful results in a restricted environment.
"""
import socket

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def enumerate_dns(target: str) -> dict:
    """Return a dict of DNS records for `target`. Never raises on lookup failure."""
    records = {"target": target, "records": {}, "ips": []}

    # Preferred path: dnspython for rich record types.
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(target, rtype)
                values = [r.to_text() for r in answers]
                if values:
                    records["records"][rtype] = values
            except Exception:
                continue
    except Exception:
        pass

    # Resolve IPv4 and IPv6 addresses explicitly and keep them separate, so the
    # scanner can prefer IPv4 (which routes reliably on most home/campus networks).
    ipv4, ipv6 = [], []
    try:
        v4 = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        ipv4 = sorted({i[4][0] for i in v4})
    except Exception:
        pass
    try:
        v6 = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
        ipv6 = sorted({i[4][0] for i in v6})
    except Exception:
        pass
    records["ipv4"] = ipv4
    records["ipv6"] = ipv6
    records["ips"] = ipv4 + ipv6  # IPv4 first
    if ipv4:
        records["records"].setdefault("A", ipv4)
    if ipv6:
        records["records"].setdefault("AAAA", ipv6)

    return records