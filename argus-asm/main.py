"""
Argus ASM — main entrypoint

Usage:
    python main.py --target example.com
    python main.py --target example.com --wordlist path/to/wordlist.txt
    python main.py --target example.com --no-db       # skip DB, print only
"""

import argparse
import json
import sys
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from recon import run_all
from db import init_db, get_db
from db.models import Asset, Port, Banner

console = Console()


# ------------------------------------------------------------------ #
# Argument parsing
# ------------------------------------------------------------------ #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus ASM — Attack Surface Management Platform",
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Domain name or IP address to scan (e.g. example.com)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        default=None,
        help="Path to subdomain wordlist file (optional)",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Print results only, skip database storage",
    )
    return parser.parse_args()


# ------------------------------------------------------------------ #
# Database persistence
# ------------------------------------------------------------------ #

def save_results(target: str, results: dict) -> None:
    """Persist recon results to the database."""
    with get_db() as db:

        # Upsert asset — update last_seen if it already exists
        asset = db.query(Asset).filter_by(domain=target).first()
        if not asset:
            asset = Asset(domain=target)
            db.add(asset)
            db.flush()  # get asset.id before inserting ports

        # Update IP from port scan result
        port_data = results.get("ports", {})
        if "resolved_ip" in port_data:
            asset.ip = port_data["resolved_ip"]

        # Update WHOIS fields
        whois = results.get("whois", {})
        if "error" not in whois:
            asset.registrar    = whois.get("registrar")
            asset.org          = whois.get("org")
            asset.country      = whois.get("country")
            asset.whois_expiry = whois.get("expires")

        asset.last_seen = datetime.utcnow()
        db.flush()

        # Build a lookup of existing ports for this asset
        existing_ports = {p.port: p for p in asset.ports}

        # Build banner lookup keyed by port number
        banners_by_port = {}
        banner_data = results.get("banners", {})
        for b in banner_data.get("banners", []):
            banners_by_port[b["port"]] = b

        # Upsert ports
        for port_info in port_data.get("open", []):
            port_num = port_info["port"]

            if port_num in existing_ports:
                port_obj = existing_ports[port_num]
                port_obj.state    = port_info.get("state", "open")
                port_obj.service  = port_info.get("service")
                port_obj.last_seen = datetime.utcnow()
                port_obj.is_active = True
            else:
                port_obj = Port(
                    asset_id=asset.id,
                    port=port_num,
                    protocol="tcp",
                    state=port_info.get("state", "open"),
                    service=port_info.get("service"),
                )
                db.add(port_obj)
                db.flush()

            # Upsert banner for this port
            if port_num in banners_by_port:
                b = banners_by_port[port_num]
                if port_obj.banner:
                    banner_obj = port_obj.banner
                else:
                    banner_obj = Banner(port_id=port_obj.id)
                    db.add(banner_obj)

                banner_obj.banner_type  = b.get("type")
                banner_obj.raw_banner   = b.get("banner")
                banner_obj.http_status  = b.get("status")
                banner_obj.http_headers = json.dumps(b.get("headers", {}))
                banner_obj.server       = b.get("server")
                banner_obj.powered_by   = b.get("powered_by")
                banner_obj.tls_subject  = json.dumps(b.get("tls_subject", {}))
                banner_obj.tls_issuer   = json.dumps(b.get("tls_issuer", {}))
                banner_obj.tls_expiry   = b.get("tls_expiry")
                banner_obj.scraped_at   = datetime.utcnow()

    console.print("[green]Results saved to database.[/green]")


# ------------------------------------------------------------------ #
# Rich output tables
# ------------------------------------------------------------------ #

def print_summary(target: str, results: dict) -> None:
    """Print a formatted summary of all recon results."""

    console.print(Panel(
        f"[bold]Argus ASM[/bold] — scan complete for [cyan]{target}[/cyan]\n"
        f"[dim]{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]",
        box=box.ROUNDED,
    ))

    # DNS records
    dns = results.get("dns", {})
    if "error" not in dns:
        dns_table = Table(title="DNS records", box=box.SIMPLE, show_header=True)
        dns_table.add_column("Type", style="cyan", width=8)
        dns_table.add_column("Value")
        for rtype, values in dns.get("records", {}).items():
            for val in values:
                dns_table.add_row(rtype, val)
        if dns_table.row_count:
            console.print(dns_table)

    # Subdomains
    subs = results.get("subdomains", {})
    found_subs = subs.get("found", [])
    if found_subs:
        sub_table = Table(
            title=f"Subdomains ({len(found_subs)} found / "
                  f"{subs.get('total_checked', 0)} checked)",
            box=box.SIMPLE,
        )
        sub_table.add_column("Subdomain", style="cyan")
        sub_table.add_column("IPs")
        for s in found_subs:
            sub_table.add_row(s["subdomain"], ", ".join(s["ips"]))
        console.print(sub_table)
    else:
        console.print("[dim]No subdomains found.[/dim]")

    # Open ports
    ports = results.get("ports", {})
    open_ports = ports.get("open", [])
    if open_ports:
        port_table = Table(
            title=f"Open ports ({len(open_ports)} / "
                  f"{ports.get('total_scanned', 0)} scanned)",
            box=box.SIMPLE,
        )
        port_table.add_column("Port", style="cyan", width=8)
        port_table.add_column("Service")

        # Merge banner server info into port table
        banners_by_port = {}
        for b in results.get("banners", {}).get("banners", []):
            banners_by_port[b["port"]] = b

        port_table.add_column("Banner / Server")
        for p in open_ports:
            b = banners_by_port.get(p["port"], {})
            banner_str = (
                b.get("server")
                or b.get("banner", "")[:60]
                or ""
            )
            port_table.add_row(str(p["port"]), p.get("service", ""), banner_str)
        console.print(port_table)
    else:
        console.print("[dim]No open ports found.[/dim]")

    # WHOIS summary
    whois = results.get("whois", {})
    if "error" not in whois and whois:
        console.print(Panel(
            f"Registrar:  {whois.get('registrar') or 'N/A'}\n"
            f"Org:        {whois.get('org') or 'N/A'}\n"
            f"Country:    {whois.get('country') or 'N/A'}\n"
            f"Expires:    {whois.get('expires') or 'N/A'}\n"
            f"NS:         {', '.join(whois.get('name_servers', [])[:3])}",
            title="WHOIS",
            box=box.SIMPLE,
        ))

    # Errors
    for module, data in results.items():
        if isinstance(data, dict) and "error" in data:
            console.print(f"[yellow]Warning — {module}: {data['error']}[/yellow]")


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> None:
    args = parse_args()

    console.print(
        f"\n[bold cyan]Argus ASM[/bold cyan] — scanning "
        f"[bold]{args.target}[/bold]\n"
    )

    # Initialise DB tables (no-op if they already exist)
    if not args.no_db:
        try:
            init_db()
        except Exception as exc:
            console.print(
                f"[red]DB init failed:[/red] {exc}\n"
                "[yellow]Tip: check DATABASE_URL in your .env file.[/yellow]\n"
                "[yellow]Running in --no-db mode.[/yellow]"
            )
            args.no_db = True

    # Run all recon modules
    with console.status("[bold green]Running recon modules...[/bold green]"):
        results = run_all(target=args.target, wordlist=args.wordlist)

    # Print results
    print_summary(args.target, results)

    # Persist to DB
    if not args.no_db:
        try:
            save_results(args.target, results)
        except Exception as exc:
            console.print(f"[red]Failed to save to DB:[/red] {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
