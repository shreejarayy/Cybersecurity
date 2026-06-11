"""
Argus ASM — Subdomain brute-force
Resolves each word in a wordlist as a subdomain of the target domain.
Uses a thread pool for concurrent DNS lookups.
"""

import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


# Bundled minimal wordlist — replace with a larger list (e.g. SecLists) for real use
DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "subdomains-500.txt"

# How many concurrent DNS workers to use
MAX_WORKERS = 20


def _resolve(subdomain: str) -> dict[str, Any] | None:
    """
    Attempt to resolve *subdomain*. Returns a result dict if it resolves,
    or None if NXDOMAIN / timeout.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(subdomain, "A", lifetime=5)
        ips = [str(r) for r in answers]
        return {"subdomain": subdomain, "ips": ips}
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return None


def _load_wordlist(path: Path | None) -> list[str]:
    """Load words from file, stripping blanks and comments."""
    wl_path = path or DEFAULT_WORDLIST
    if not wl_path.exists():
        # Fallback: a tiny inline list so the module never crashes cold
        return [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "vpn", "remote", "test", "portal", "webmail", "smtp",
            "pop", "imap", "ns1", "ns2", "mx", "cdn", "blog",
        ]
    with open(wl_path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def brute_subdomains(
    target: str,
    wordlist: str | None = None,
) -> dict[str, Any]:
    """
    Brute-force subdomains of *target* using *wordlist*.

    Args:
        target:   Base domain (e.g. "example.com").
        wordlist: Path to a newline-separated word file.
                  Uses the bundled 500-word list if None.

    Returns:
        {
            "target": "example.com",
            "found": [
                {"subdomain": "www.example.com", "ips": ["93.184.216.34"]},
                ...
            ],
            "total_checked": 500,
        }
    """
    wl_path = Path(wordlist) if wordlist else None
    words = _load_wordlist(wl_path)
    candidates = [f"{word}.{target}" for word in words]

    found: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_resolve, c): c for c in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                found.append(result)

    # Sort alphabetically for consistent output
    found.sort(key=lambda x: x["subdomain"])

    return {
        "target": target,
        "found": found,
        "total_checked": len(candidates),
    }
