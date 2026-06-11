"""
Argus ASM — Banner grabbing
For each open port:
  - HTTP/HTTPS ports (80, 443, 8080, 8443, etc.): sends a HEAD request
    and captures response headers + status code.
  - All other ports: opens a raw TCP socket and reads the first 1024 bytes
    as a banner string.
"""

import socket
import ssl
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


# Suppress insecure-request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS  = {80, 8080, 8000, 8008}
HTTPS_PORTS = {443, 8443, 4443, 9443}

CONNECT_TIMEOUT = 3   # seconds
READ_TIMEOUT    = 5   # seconds
MAX_WORKERS     = 20


def _grab_http(target: str, port: int) -> dict[str, Any]:
    """Send a HEAD request and return status + headers."""
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{target}:{port}/"
    try:
        resp = requests.head(
            url,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,         # Allow self-signed certs
            allow_redirects=True,
        )
        return {
            "port":       port,
            "type":       "http",
            "url":        url,
            "status":     resp.status_code,
            "headers":    dict(resp.headers),
            "server":     resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
        }
    except requests.RequestException as exc:
        return {"port": port, "type": "http", "error": str(exc)}


def _grab_tcp(target: str, port: int) -> dict[str, Any]:
    """Connect via raw TCP, send a newline probe, and read the banner."""
    try:
        with socket.create_connection((target, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            # Send a minimal probe — some services (SSH, FTP) send unprompted
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
            try:
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
        return {"port": port, "type": "tcp", "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"port": port, "type": "tcp", "error": str(exc)}


def _grab_https_tcp(target: str, port: int) -> dict[str, Any]:
    """
    For HTTPS ports, also attempt a TLS handshake to extract
    the certificate subject / issuer as extra context.
    """
    http_result = _grab_http(target, port)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                http_result["tls_subject"] = dict(cert.get("subject", []))
                http_result["tls_issuer"]  = dict(cert.get("issuer", []))
                http_result["tls_expiry"]  = cert.get("notAfter")
    except Exception:
        pass  # TLS info is a bonus; don't fail the whole result
    return http_result


def grab_banners(target: str, ports: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Grab banners for all *ports* (list of port-info dicts from port_scan).

    Args:
        target: Hostname or IP.
        ports:  List of {"port": int, "state": "open", ...} dicts.

    Returns:
        {
            "target": "example.com",
            "banners": [
                {
                    "port": 80, "type": "http", "status": 200,
                    "server": "nginx/1.18.0", "headers": {...}
                },
                {
                    "port": 22, "type": "tcp",
                    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
                },
                ...
            ]
        }
    """
    port_numbers = [p["port"] for p in ports if p.get("state") == "open"]

    def _dispatch(port: int) -> dict[str, Any]:
        if port in HTTPS_PORTS:
            return _grab_https_tcp(target, port)
        if port in HTTP_PORTS:
            return _grab_http(target, port)
        return _grab_tcp(target, port)

    banners: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_dispatch, p): p for p in port_numbers}
        for future in as_completed(futures):
            banners.append(future.result())

    banners.sort(key=lambda x: x["port"])

    return {"target": target, "banners": banners}
