"""Subdomain discovery via a small built-in wordlist brute-force.

This is intentionally light-touch: it only resolves candidate names (a passive
DNS operation) and never sends traffic to the hosts themselves. A production
deployment could add passive sources (certificate transparency, OSINT) here.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# A compact wordlist keeps the demo fast; extend as needed.
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dev",
    "staging", "test", "portal", "admin", "api", "app", "blog", "shop",
    "vpn", "remote", "git", "gitlab", "jenkins", "docs", "cdn", "static",
    "assets", "img", "images", "m", "mobile", "beta", "demo", "secure",
    "dashboard", "monitor", "status", "help", "support", "login", "auth",
]


def _resolve(name: str):
    try:
        ip = socket.gethostbyname(name)
        return (name, ip)
    except Exception:
        return None


def discover_subdomains(domain: str, wordlist=None, threads: int = 40) -> dict:
    """Return discovered subdomains that resolve. Never raises."""
    wordlist = wordlist or DEFAULT_WORDLIST
    found = []
    candidates = [f"{w}.{domain}" for w in wordlist]
    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(_resolve, c) for c in candidates]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    found.append({"subdomain": res[0], "ip": res[1]})
    except Exception:
        pass
    return {"domain": domain, "subdomains": found, "count": len(found)}
