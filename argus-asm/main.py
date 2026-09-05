#!/usr/bin/env python3
"""ArgusPredict command-line interface.

Examples:
    python main.py --target scanme.nmap.org            # full scan, stored in DB
    python main.py --target 127.0.0.1 --no-db          # quick scan, no database
    python main.py --target scanme.nmap.org --no-cve   # skip CVE correlation

Only targets on the AUTHORISED_TARGETS allow-list (config / .env) are scanned.
"""
import argparse
import json
import sys

import config
from argus.pipeline import run_full_scan


def _print_report(result: dict):
    s = result["summary"]
    print("\n" + "=" * 64)
    print(f"  ArgusPredict scan report  -  target: {result['target']}")
    print("=" * 64)
    print(f"  Assets discovered : {s['assets']}")
    print(f"  Open ports        : {s['open_ports']}")
    print(f"  Changes detected  : {s['changes']}")
    print(f"  Anomalies flagged : {s['anomalies']}")
    print(f"  Scan duration     : {s['duration_seconds']}s")
    print("-" * 64)

    if result["changes"]:
        print("  Changes since last scan:")
        for c in result["changes"][:15]:
            print(f"    [{c['event_type']}] {c['detail']}")
        print("-" * 64)

    print("  Top prioritised risks (context-aware):")
    if not result["risk_report"]:
        print("    (no open ports / services to score)")
    for r in result["risk_report"][:10]:
        flag = " *ANOMALY*" if r["is_anomaly"] else ""
        print(f"    {r['composite_risk']:>5}  {r['node']:<22} "
              f"{(r['service'] or ''):<12} base={r['cvss_base']}{flag}")
    print("=" * 64 + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="ArgusPredict attack-surface scanner")
    ap.add_argument("--target", required=True, help="hostname or IP to scan (must be authorised)")
    ap.add_argument("--no-db", action="store_true", help="do not persist to the database")
    ap.add_argument("--no-cve", action="store_true", help="skip NVD CVE correlation")
    ap.add_argument("--json", action="store_true", help="print full result as JSON")
    args = ap.parse_args(argv)

    try:
        result = run_full_scan(
            args.target,
            use_db=not args.no_db,
            correlate_cve=not args.no_cve,
        )
    except config.UnauthorisedTargetError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
