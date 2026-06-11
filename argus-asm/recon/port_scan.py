"""
Argus ASM — Port scanner
Performs a concurrent TCP connect scan of the top-1000 ports.
Not a SYN scan — uses full TCP connect, so no raw socket privileges needed.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


# IANA top-1000 most common ports (condensed — extend as needed)
TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 194, 389, 443,
    445, 465, 500, 514, 515, 587, 631, 636, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1080, 1110, 1433, 1521, 1720, 1723, 1755, 1900, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9090, 9100, 9999,
    10000, 10001, 27017, 27018, 27019, 28017,
    # Fill the rest of the top-1000 range
    *range(1030, 1110),
    *range(1200, 1250),
    *range(2000, 2030),
    *range(4000, 4020),
    *range(5100, 5160),
    *range(6100, 6120),
    *range(7000, 7020),
    *range(8500, 8520),
    *range(9000, 9050),
]
# Deduplicate and sort
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))

MAX_WORKERS = 150   # Concurrent socket connections
TIMEOUT     = 1.0   # Seconds per connect attempt


# Human-readable service names for common ports
WELL_KNOWN: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP/TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _probe(host: str, port: int) -> dict[str, Any] | None:
    """
    Attempt a TCP connect to host:port.
    Returns a port-info dict if open, None if closed/filtered.
    """
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            service = WELL_KNOWN.get(port, "unknown")
            return {"port": port, "state": "open", "service": service}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(target: str) -> dict[str, Any]:
    """
    TCP connect scan of TOP_1000_PORTS against *target*.

    Args:
        target: Hostname or IP address.

    Returns:
        {
            "target": "example.com",
            "open": [
                {"port": 80,  "state": "open", "service": "HTTP"},
                {"port": 443, "state": "open", "service": "HTTPS"},
            ],
            "total_scanned": 1000,
        }
    """
    # Resolve hostname once to avoid repeated DNS lookups in threads
    try:
        host_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "target": target,
            "error": f"Could not resolve hostname: {target}",
            "open": [],
            "total_scanned": 0,
        }

    open_ports: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(_probe, host_ip, port): port
            for port in TOP_1000_PORTS
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    return {
        "target": target,
        "resolved_ip": host_ip,
        "open": open_ports,
        "total_scanned": len(TOP_1000_PORTS),
    }
