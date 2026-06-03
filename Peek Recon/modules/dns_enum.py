# modules/dns_enum.py
# DNS enumeration — basically asking "what do we know about this domain?"
# DNS has different record types, each tells us something different:
#   A     → domain to IPv4 address
#   AAAA  → domain to IPv6 address
#   MX    → mail servers (who handles email for this domain)
#   NS    → nameservers (who controls DNS for this domain)
#   TXT   → text records (SPF, DKIM, site verification stuff)
#   CNAME → alias (this domain points to another domain)

import dns.resolver
from utils.display import section, success, warning, error, make_table, show_table

# these are the record types we'll try to fetch
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def run(target):
    section("DNS Enumeration")

    table = make_table(
        f"DNS Records — {target}",
        [("Type", "cyan"), ("Value", "white"), ("TTL", "dim")]
    )

    found_any = False

    for record_type in RECORD_TYPES:
        try:
            # dns.resolver.resolve() sends a query and waits for the response
            answers = dns.resolver.resolve(target, record_type)

            for rdata in answers:
                # rdata is one answer — a domain can have multiple A records for example
                value = str(rdata)
                ttl   = str(answers.rrset.ttl)  # TTL = time to live (how long to cache this)

                # MX records have a priority number before the hostname, stripping that
                if record_type == "MX":
                    value = str(rdata.exchange)

                table.add_row(record_type, value, ttl)
                found_any = True

        except dns.resolver.NoAnswer:
            # totally fine — just means this record type doesn't exist for the domain
            pass
        except dns.resolver.NXDOMAIN:
            # domain doesn't exist at all — no point checking other record types
            error(f"Domain '{target}' does not exist.")
            return
        except Exception as e:
            # something weird happened (timeout, etc), skip this record type
            warning(f"{record_type} lookup failed: {e}")

    if found_any:
        show_table(table)
        success("DNS enumeration complete.")
    else:
        warning("No DNS records found.")
