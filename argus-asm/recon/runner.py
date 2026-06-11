"""
Argus ASM — recon runner
Executes all recon modules concurrently using ThreadPoolExecutor
and merges results into a single dict keyed by module name.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .dns_enum import enumerate_dns
from .subdomain_brute import brute_subdomains
from .port_scan import scan_ports
from .whois_lookup import lookup_whois
from .banner_grab import grab_banners


MODULES = {
    "dns":        enumerate_dns,
    "subdomains": brute_subdomains,
    "ports":      scan_ports,
    "whois":      lookup_whois,
}


def run_all(target: str, wordlist: str | None = None) -> dict[str, Any]:
    """
    Run all recon modules against *target* concurrently.

    Args:
        target:   Domain name or IP address to scan.
        wordlist: Optional path to a subdomain wordlist file.
                  Defaults to the bundled top-500 list if None.

    Returns:
        Dict with keys: dns, subdomains, ports, whois, banners
        Each value is the raw output dict from its module,
        or {"error": <message>} if the module raised an exception.
    """
    results: dict[str, Any] = {}

    kwargs_map = {
        "dns":        {"target": target},
        "subdomains": {"target": target, "wordlist": wordlist},
        "ports":      {"target": target},
        "whois":      {"target": target},
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fn, **kwargs_map[name]): name
            for name, fn in MODULES.items()
        }

        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"error": str(exc)}

    # Banner grab runs after port scan since it needs the open ports list
    open_ports = []
    if "ports" in results and "open" in results["ports"]:
        open_ports = results["ports"]["open"]

    try:
        results["banners"] = grab_banners(target=target, ports=open_ports)
    except Exception as exc:
        results["banners"] = {"error": str(exc)}

    return results
