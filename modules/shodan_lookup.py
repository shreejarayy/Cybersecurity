# modules/shodan_lookup.py
# shodan is a search engine for internet-connected devices
# it continuously scans the whole internet and stores what it finds
# so instead of us scanning the target, we just ask shodan what IT already found
# requires a free API key from shodan.io

import socket
import shodan
from utils.display import section, success, warning, error, kv, make_table, show_table


def run(target, api_key):
    section("Shodan Lookup")

    if not api_key:
        warning("No Shodan API key set. Add it to config.py to use this module.")
        return

    try:
        ip = socket.gethostbyname(target)
        success(f"Resolved {target} → {ip}")
    except socket.gaierror:
        error(f"Couldn't resolve: {target}")
        return

    try:
        api  = shodan.Shodan(api_key)
        host = api.host(ip)

        # basic info about the IP
        kv("IP",           host.get("ip_str"))
        kv("Org",          host.get("org"))
        kv("ISP",          host.get("isp"))
        kv("OS",           host.get("os"))
        kv("Country",      host.get("country_name"))
        kv("City",         host.get("city"))
        kv("Last Updated", host.get("last_update"))
        kv("Hostnames",    host.get("hostnames"))
        kv("Tags",         host.get("tags"))

        # shodan stores each open port as a separate "banner" entry
        banners = host.get("data", [])

        if banners:
            table = make_table("Shodan — Open Ports & Banners", [
                ("Port",      "cyan"),
                ("Transport", "yellow"),
                ("Product",   "white"),
                ("Banner",    "dim")
            ])

            for item in banners:
                port      = str(item.get("port", ""))
                transport = item.get("transport", "tcp")
                product   = item.get("product", "")
                banner    = item.get("data", "").strip().split("\n")[0]  # first line only

                table.add_row(port, transport, product, banner[:80])  # cap banner at 80 chars

            show_table(table)

        # vulns that shodan has flagged (only available on paid plans)
        vulns = host.get("vulns", [])
        if vulns:
            warning(f"Shodan flagged {len(vulns)} potential CVE(s): {', '.join(vulns)}")

        success("Shodan lookup complete.")

    except shodan.APIError as e:
        # common errors: invalid key, IP not in shodan db, rate limit
        error(f"Shodan API error: {e}")
    except Exception as e:
        error(f"Shodan lookup failed: {e}")
