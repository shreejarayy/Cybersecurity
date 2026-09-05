"""Banner grabbing: read the service banner / HTTP response header for a port.

Light-touch and observational: it sends at most a minimal HTTP HEAD-style probe
for web ports and otherwise just reads whatever the service volunteers on
connect. It never attempts authentication or exploitation.
"""
import socket
import re

WEB_PORTS = {80, 8000, 8080, 8081, 8443, 8888, 9000, 3000, 5000, 443}


def _extract_version(banner: str) -> str:
    """Best-effort extraction of a product/version token from a banner."""
    banner = banner.strip()
    # e.g. "Server: Apache/2.4.7 (Ubuntu)" or "SSH-2.0-OpenSSH_6.6.1p1"
    m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"(SSH-[\d.]+-\S+)", banner)
    if m:
        return m.group(1).strip()
    first = banner.split("\n")[0][:120]
    # Only return it if it's mostly printable; otherwise call it binary.
    if first:
        printable = sum(c.isprintable() or c.isspace() for c in first)
        if printable / len(first) > 0.8:
            return first
    return "(binary service - no text banner)"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> dict:
    """Return {'port', 'banner', 'product'} for an open port. Never raises."""
    banner = ""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in WEB_PORTS:
                req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                s.sendall(req.encode())
            data = s.recv(2048)
            banner = data.decode("utf-8", errors="replace")
    except Exception:
        banner = ""
    return {
        "port": port,
        "banner": banner.strip(),
        "product": _extract_version(banner) if banner else "",
    }