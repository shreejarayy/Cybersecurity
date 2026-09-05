"""WHOIS lookup for domain registration metadata.

Uses the python-whois library when available; degrades gracefully to an empty
record when WHOIS is unreachable (e.g. in a restricted network). All library
output (which is printed to stdout/stderr) is suppressed so it never clutters
the scan report.
"""


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def lookup_whois(domain: str) -> dict:
    """Return selected WHOIS fields for `domain`. Never raises and stays quiet."""
    import os
    import socket as _socket
    import sys
    result = {"domain": domain, "registrar": None, "creation_date": None,
              "expiration_date": None, "name_servers": [], "available": True}
    # WHOIS is meaningless for a bare IP; skip it quietly.
    if _is_ip(domain):
        result["available"] = False
        return result
    # Cap how long WHOIS can block, and silence the library's stdout/stderr chatter.
    old_timeout = _socket.getdefaulttimeout()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    devnull = open(os.devnull, "w")
    try:
        _socket.setdefaulttimeout(5.0)
        sys.stdout = devnull
        sys.stderr = devnull
        import whois  # type: ignore
        data = whois.whois(domain)

        def _first(v):
            if isinstance(v, (list, tuple)):
                return v[0] if v else None
            return v

        def _iso(v):
            v = _first(v)
            try:
                return v.isoformat() if hasattr(v, "isoformat") else (str(v) if v else None)
            except Exception:
                return str(v) if v else None

        result["registrar"] = _first(getattr(data, "registrar", None))
        result["creation_date"] = _iso(getattr(data, "creation_date", None))
        result["expiration_date"] = _iso(getattr(data, "expiration_date", None))
        ns = getattr(data, "name_servers", None) or []
        if isinstance(ns, str):
            ns = [ns]
        result["name_servers"] = sorted({str(n).lower() for n in ns}) if ns else []
        result["available"] = bool(result["registrar"])
    except Exception:
        result["available"] = False
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        try:
            devnull.close()
        except Exception:
            pass
        _socket.setdefaulttimeout(old_timeout)
    return result