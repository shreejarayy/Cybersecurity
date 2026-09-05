"""Concurrent TCP connect port scanner.

Uses a ThreadPoolExecutor so the slowest port rather than the sum of all ports
sets the pace (matches the report's FR1 design). A plain TCP connect is used -
it is observational and does not attempt exploitation.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common service names for readable output (subset of IANA assignments).
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9000: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

# A pragmatic "top ~130 ports" list for a fast default scan. TOP_PORTS in config
# can request more; this list is the fast path used for demos and CI.
TOP_PORTS_LIST = sorted(set(list(COMMON_SERVICES.keys()) + [
    20, 69, 88, 123, 137, 138, 161, 162, 389, 427, 465, 514, 515, 543, 544,
    548, 554, 587, 631, 636, 873, 902, 989, 990, 1025, 1080, 1194, 1433, 1521,
    2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3690, 4444, 5000, 5060,
    5601, 5672, 5984, 7001, 7077, 8008, 8081, 8088, 8181, 8888, 9090, 9092,
    9418, 9929, 9999, 10000, 11211, 15672, 31337, 50000,
]))


def _probe(host: str, port: int, timeout: float):
    # Choose the right socket family so IPv6 targets are handled correctly.
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except Exception:
        return None
    return None


def scan_ports(host: str, ports=None, threads: int = 150, timeout: float = 1.0) -> dict:
    """Return the list of open TCP ports on `host`. Never raises."""
    ports = ports or TOP_PORTS_LIST
    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_probe, host, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                p = fut.result()
                if p is not None:
                    open_ports.append({"port": p, "service": COMMON_SERVICES.get(p, "unknown")})
    except Exception:
        pass
    open_ports.sort(key=lambda x: x["port"])
    return {"host": host, "open_ports": open_ports, "scanned": len(ports)}