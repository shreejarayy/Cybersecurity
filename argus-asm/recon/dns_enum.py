"""
Argus ASM — DNS enumeration
Resolves A, MX, NS, and TXT records for a given domain using dnspython.
Returns structured dicts suitable for direct ORM insertion.
"""

import dns.resolver
import dns.exception
from typing import Any


# Record types to query
RECORD_TYPES = ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]


def _query(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
    """
    Query a single record type. Returns a list of string values.
    Returns an empty list on NXDOMAIN / NoAnswer / timeout.
    """
    try:
        answers = resolver.resolve(domain, rtype, lifetime=5)
        results = []
        for rdata in answers:
            if rtype == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            elif rtype == "TXT":
                # TXT records are sequences of byte strings
                results.append(" ".join(part.decode() for part in rdata.strings))
            else:
                results.append(str(rdata))
        return results
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


def enumerate_dns(target: str) -> dict[str, Any]:
    """
    Enumerate DNS records for *target*.

    Args:
        target: Domain name (e.g. "example.com").

    Returns:
        {
            "target": "example.com",
            "records": {
                "A":     ["93.184.216.34"],
                "MX":    ["0 ."],
                "NS":    ["a.iana-servers.net.", ...],
                "TXT":   ["v=spf1 -all"],
                "AAAA":  [],
                "CNAME": [],
            }
        }
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        records[rtype] = _query(resolver, target, rtype)

    return {
        "target": target,
        "records": records,
    }
