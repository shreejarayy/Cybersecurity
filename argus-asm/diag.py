import socket
import config
from argus.recon.dns_enum import enumerate_dns
from argus.recon.port_scan import scan_ports

print("SCAN_IPV6        =", getattr(config, "SCAN_IPV6", ">>> MISSING (config.py not updated)"))
print("PORT_SCAN_TIMEOUT =", config.PORT_SCAN_TIMEOUT)

r = enumerate_dns("scanme.nmap.org")
print("dns keys :", list(r.keys()))
print("ipv4     :", r.get("ipv4", ">>> MISSING (dns_enum.py not updated)"))
print("ipv6     :", r.get("ipv6"))
print("ips      :", r.get("ips"))

print("\nDirect connect test to 45.33.32.156:")
for p in (22, 80, 9929, 31337):
    s = socket.socket(); s.settimeout(4)
    r2 = s.connect_ex(("45.33.32.156", p))
    print(f"  port {p:>5}:", "OPEN" if r2 == 0 else f"closed/filtered ({r2})")
    s.close()

print("\nscan_ports() on the IPv4 address directly:")
res = scan_ports("45.33.32.156", threads=100, timeout=4.0)
print("  open ports:", res["open_ports"])