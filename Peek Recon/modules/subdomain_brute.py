# modules/subdomain_brute.py
# tries to find subdomains by guessing common names and checking if they resolve
# e.g. trying "mail.target.com", "dev.target.com", "api.target.com" etc.
# this is called brute-forcing — it's dumb but effective
#
# we use asyncio here because we're doing hundreds of DNS queries
# async lets us fire all of them off without waiting for each one to finish
# way faster than doing them one by one

import asyncio
import dns.asyncresolver
from utils.display import section, success, warning, info, make_table, show_table

# common subdomain names — real wordlists have thousands but this is a good start
WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "portal", "remote", "vpn", "cdn", "static", "assets", "media", "blog",
    "shop", "store", "app", "dashboard", "login", "auth", "secure", "web",
    "m", "mobile", "ns1", "ns2", "smtp", "pop", "imap", "webmail", "cpanel",
    "git", "jenkins", "jira", "confluence", "grafana", "monitor", "status",
    "docs", "help", "support", "careers", "jobs", "news", "forum", "community"
]

# limit how many DNS queries run at the same time — too many = DNS server gets upset
SEMAPHORE_LIMIT = 50


async def check_subdomain(subdomain, domain, semaphore, found):
    hostname = f"{subdomain}.{domain}"

    # semaphore = controls concurrency, like a ticket system — max 50 at a time
    async with semaphore:
        try:
            answers = await dns.asyncresolver.resolve(hostname, "A")
            ip = str(answers[0])  # just grab the first IP if there are multiple
            found.append((hostname, ip))
        except Exception:
            # NXDOMAIN, timeout, no answer — subdomain doesn't exist, just skip
            pass


async def brute_async(target):
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    found     = []

    # create all tasks upfront, then run them all concurrently
    tasks = [
        check_subdomain(word, target, semaphore, found)
        for word in WORDLIST
    ]

    info(f"Trying {len(WORDLIST)} subdomains...")
    await asyncio.gather(*tasks)  # gather = run all tasks and wait for all to finish

    return found


def run(target):
    section("Subdomain Brute-force")

    # asyncio.run() is the entry point for async code from normal (sync) code
    found = asyncio.run(brute_async(target))

    if not found:
        warning("No subdomains found.")
        return

    table = make_table(f"Subdomains — {target}", [
        ("Subdomain", "cyan"),
        ("IP Address", "white")
    ])

    for hostname, ip in sorted(found):
        table.add_row(hostname, ip)

    show_table(table)
    success(f"Found {len(found)} subdomain(s).")
