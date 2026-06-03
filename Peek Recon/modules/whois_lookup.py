# modules/whois_lookup.py
# WHOIS tells us who registered a domain and when
# it's like a phonebook for domain ownership
# useful for finding registrar, creation date, expiry, nameservers, contact info

import whois
from utils.display import section, success, warning, kv


def run(target):
    section("WHOIS Lookup")

    try:
        w = whois.whois(target)

        # whois() returns an object with attributes — some may be None if not disclosed
        # privacy protection services often hide contact info, so we handle None gracefully

        kv("Domain",        w.domain_name)
        kv("Registrar",     w.registrar)
        kv("Created",       w.creation_date)
        kv("Expires",       w.expiration_date)
        kv("Updated",       w.updated_date)
        kv("Status",        w.status)
        kv("Name Servers",  w.name_servers)
        kv("Emails",        w.emails)
        kv("Org",           w.org)
        kv("Country",       w.country)

        success("WHOIS lookup complete.")

    except Exception as e:
        # sometimes whois fails if the TLD doesn't support it or rate limits kick in
        warning(f"WHOIS failed: {e}")
