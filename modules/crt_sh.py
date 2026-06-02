# modules/crt_sh.py
# certificate transparency logs are public records of every SSL cert ever issued
# crt.sh is a free search engine for these logs — 100% passive, we never touch the target
# their API can be flaky sometimes so we retry a couple times before giving up

import requests
import time
from utils.display import section, success, warning, error, make_table, show_table


def fetch_crtsh(target, attempt=1):
    # sometimes crt.sh returns empty on first hit, so we retry up to 3 times
    url  = f"https://crt.sh/?q=%.{target}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (pyrecon/1.0)"}  # some servers block no-UA requests

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code != 200:
            raise Exception(f"HTTP {resp.status_code}")

        if not resp.text.strip():
            # empty body — retry after a short wait
            if attempt < 3:
                warning(f"crt.sh returned empty response, retrying ({attempt}/3)...")
                time.sleep(2)
                return fetch_crtsh(target, attempt + 1)
            else:
                return None

        return resp.json()

    except requests.exceptions.Timeout:
        if attempt < 3:
            warning(f"crt.sh timed out, retrying ({attempt}/3)...")
            time.sleep(2)
            return fetch_crtsh(target, attempt + 1)
        return None


def run(target):
    section("Certificate Transparency (crt.sh)")

    data = fetch_crtsh(target)

    if data is None:
        warning("crt.sh didn't respond after 3 attempts. Try running --crtsh again later.")
        return

    if not data:
        warning("No certificate records found.")
        return

    # deduplicate — crt.sh returns the same domain across multiple cert entries
    seen   = set()
    unique = []

    for entry in data:
        names = entry.get("name_value", "").split("\n")

        for name in names:
            name = name.strip().lower()

            if name.startswith("*"):
                continue  # skip wildcards like *.example.com

            if name not in seen:
                seen.add(name)
                unique.append({
                    "name":   name,
                    "issuer": entry.get("issuer_name", ""),
                    "logged": entry.get("entry_timestamp", "")[:10]
                })

    table = make_table(f"Certificates — {target}", [
        ("Domain",      "cyan"),
        ("Issuer",      "dim white"),
        ("Date Logged", "dim")
    ])

    for item in sorted(unique, key=lambda x: x["name"]):
        issuer = item["issuer"]
        if "CN=" in issuer:
            issuer = issuer.split("CN=")[-1].split(",")[0]

        table.add_row(item["name"], issuer, item["logged"])

    show_table(table)
    success(f"Found {len(unique)} unique domain(s) in cert logs.")