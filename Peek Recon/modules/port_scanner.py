# modules/port_scanner.py
# scans for open ports on the target and tries to grab service banners
# banner grabbing = connecting to an open port and reading whatever the service sends back
# this tells us what software is running (e.g. "OpenSSH 8.2", "Apache httpd 2.4")
#
# we use threading here so we can scan multiple ports at the same time
# without it, scanning 1000 ports one-by-one would take forever

import socket
import threading
from utils.display import section, success, warning, info, make_table, show_table

# top ports to scan — covers most common services
# add more if you want but keep it reasonable, we're not nmap
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]

# well-known port → service name mapping (so output is readable)
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}


def grab_banner(ip, port):
    # try to read the banner — what does the service say when we connect?
    # not all services send a banner so we just return empty string if nothing comes back
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))

        # some services need a nudge before they respond (HTTP needs a request)
        if port in (80, 8080, 8443, 443):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner.split("\n")[0]  # just the first line, banners can be long
    except:
        return ""


def scan_port(ip, port, results, lock):
    # results = shared list, lock = makes sure threads don't write at the same time
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)  # half second timeout — fast but fair

        result = s.connect_ex((ip, port))  # returns 0 if connection succeeded
        s.close()

        if result == 0:
            # port is open — grab the banner
            banner  = grab_banner(ip, port)
            service = PORT_SERVICES.get(port, "unknown")

            # lock makes sure only one thread writes to results at a time
            with lock:
                results.append((port, service, banner))

    except Exception:
        pass


def run(target):
    section("Port Scanner")
    info(f"Scanning {len(TOP_PORTS)} common ports on {target}...")

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        from utils.display import error
        error(f"Couldn't resolve: {target}")
        return

    results = []        # shared list where threads dump their findings
    lock    = threading.Lock()  # prevents race conditions on results list
    threads = []

    # spin up one thread per port — they all run simultaneously
    for port in TOP_PORTS:
        t = threading.Thread(target=scan_port, args=(ip, port, results, lock))
        threads.append(t)
        t.start()

    # wait for all threads to finish before we print results
    for t in threads:
        t.join()

    if not results:
        warning("No open ports found.")
        return

    # sort by port number so output looks clean
    results.sort(key=lambda x: x[0])

    table = make_table(f"Open Ports — {ip}", [
        ("Port", "cyan"),
        ("Service", "yellow"),
        ("Banner", "dim white")
    ])

    for port, service, banner in results:
        table.add_row(str(port), service, banner or "—")

    show_table(table)
    success(f"Found {len(results)} open port(s).")
