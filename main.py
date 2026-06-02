# main.py
# entry point — run this with: python main.py
# it'll ask you which site to scan and which modules to run

import sys

from config import SHODAN_API_KEY
from utils.display import print_banner, section, error, warning, info, console

from modules import dns_enum, whois_lookup, ip_geolocation, http_headers
from modules import port_scanner, subdomain_brute, crt_sh, shodan_lookup


def ask_target():
    console.print("\n  [bold cyan]Enter target domain or IP:[/bold cyan] ", end="")
    target = input().strip().lower()

    # strip http/https if they paste a full URL
    if target.startswith("http://"):  target = target[7:]
    if target.startswith("https://"): target = target[8:]
    target = target.rstrip("/")

    if not target:
        error("No target entered. Exiting.")
        sys.exit(0)

    return target


def ask_modules():
    console.print("\n  [bold cyan]Which modules do you want to run?[/bold cyan]")
    console.print("  [dim](press Enter to run ALL, or type numbers separated by commas e.g. 1,3,5)[/dim]\n")

    modules = [
        ("DNS Enumeration",              "dns"),
        ("WHOIS Lookup",                 "whois"),
        ("IP Geolocation",               "geo"),
        ("HTTP Header Analysis",         "headers"),
        ("Port Scanner + Banner Grab",   "ports"),
        ("Subdomain Brute-force",        "subdomains"),
        ("Certificate Transparency",     "crtsh"),
        ("Shodan Lookup",                "shodan"),
    ]

    for i, (name, _) in enumerate(modules, 1):
        console.print(f"  [cyan]{i}.[/cyan] {name}")

    console.print("\n  [bold cyan]Your choice:[/bold cyan] ", end="")
    choice = input().strip()

    # empty input = run everything
    if not choice:
        return [key for _, key in modules]

    # parse comma-separated numbers
    try:
        selected_indices = [int(x.strip()) for x in choice.split(",")]
        selected = [modules[i - 1][1] for i in selected_indices if 1 <= i <= len(modules)]
        if not selected:
            warning("No valid modules selected, running all.")
            return [key for _, key in modules]
        return selected
    except ValueError:
        warning("Couldn't parse input, running all modules.")
        return [key for _, key in modules]


def confirm_scope(target):
    console.print(f"\n  [yellow]Target:[/yellow] [bold]{target}[/bold]")
    console.print("  [dim]Only scan targets you own or have written permission to test.[/dim]\n")
    try:
        ans = input("  Continue? (y/n): ").strip().lower()
        return ans == "y"
    except KeyboardInterrupt:
        return False


def run_modules(target, selected):
    # runs only the modules the user picked
    def should(key): return key in selected

    if should("dns"):
        try: dns_enum.run(target)
        except Exception as e: error(f"DNS module crashed: {e}")

    if should("whois"):
        try: whois_lookup.run(target)
        except Exception as e: error(f"WHOIS module crashed: {e}")

    if should("geo"):
        try: ip_geolocation.run(target)
        except Exception as e: error(f"Geo module crashed: {e}")

    if should("headers"):
        try: http_headers.run(target)
        except Exception as e: error(f"Headers module crashed: {e}")

    if should("ports"):
        try: port_scanner.run(target)
        except Exception as e: error(f"Port scanner crashed: {e}")

    if should("subdomains"):
        try: subdomain_brute.run(target)
        except Exception as e: error(f"Subdomain module crashed: {e}")

    if should("crtsh"):
        try: crt_sh.run(target)
        except Exception as e: error(f"crt.sh module crashed: {e}")

    if should("shodan"):
        try: shodan_lookup.run(target, SHODAN_API_KEY)
        except Exception as e: error(f"Shodan module crashed: {e}")


def main():
    print_banner()

    while True:
        target   = ask_target()
        selected = ask_modules()

        if not confirm_scope(target):
            warning("Scan cancelled.")
        else:
            run_modules(target, selected)

        console.print("\n[bold cyan]━━━  scan complete  ━━━[/bold cyan]\n")

        # ask if they want to scan another target
        console.print("  [bold cyan]Scan another target? (y/n):[/bold cyan] ", end="")
        again = input().strip().lower()
        if again != "y":
            console.print("\n  [dim]bye.[/dim]\n")
            break


if __name__ == "__main__":
    main()