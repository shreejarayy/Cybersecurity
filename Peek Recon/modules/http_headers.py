# modules/http_headers.py
# grabs the HTTP response headers from a web server
# headers reveal a LOT — server software, security config, cookies, redirects
# this is pure passive recon — we're just reading what the server sends back normally

import requests
from utils.display import section, success, warning, error, make_table, show_table, kv, console

# security headers we specifically want to check for
# missing ones = potential vulnerability
SECURITY_HEADERS = [
    "Strict-Transport-Security",   # forces HTTPS
    "Content-Security-Policy",     # prevents XSS
    "X-Frame-Options",             # prevents clickjacking
    "X-Content-Type-Options",      # prevents MIME sniffing
    "Referrer-Policy",             # controls referrer info leakage
    "Permissions-Policy",          # controls browser features
]


def run(target):
    section("HTTP Header Analysis")

    # make sure we have a proper URL — target might just be a domain name
    if not target.startswith("http"):
        url = f"https://{target}"
    else:
        url = target

    try:
        # HEAD request = ask for headers only, no body downloaded — faster
        # allow_redirects=True follows any 301/302 redirects automatically
        resp = requests.head(url, timeout=5, allow_redirects=True)

        kv("URL",           resp.url)
        kv("Status Code",   str(resp.status_code))
        kv("Server",        resp.headers.get("Server", "not disclosed"))
        kv("Powered By",    resp.headers.get("X-Powered-By", "not disclosed"))
        kv("Content-Type",  resp.headers.get("Content-Type"))

        # ── all headers ──────────────────────────────────────────────
        console.print()
        all_table = make_table("All Response Headers", [("Header", "cyan"), ("Value", "white")])
        for key, val in resp.headers.items():
            all_table.add_row(key, val)
        show_table(all_table)

        # ── security header check ─────────────────────────────────────
        console.print()
        sec_table = make_table("Security Header Audit", [("Header", "cyan"), ("Status", "white")])

        for header in SECURITY_HEADERS:
            if header in resp.headers:
                sec_table.add_row(header, "[green]Present[/green]")
            else:
                sec_table.add_row(header, "[red]MISSING[/red]")

        show_table(sec_table)
        success("Header analysis complete.")

    except requests.exceptions.SSLError:
        # SSL cert error — try HTTP instead
        warning("SSL error on HTTPS, retrying with HTTP...")
        run(f"http://{target}")
    except requests.exceptions.ConnectionError:
        error(f"Couldn't connect to {url}")
    except requests.exceptions.Timeout:
        error("Request timed out.")
    except Exception as e:
        error(f"Header fetch failed: {e}")
