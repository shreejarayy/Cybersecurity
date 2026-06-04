# modules/local_scanner.py
# scans files and folders on your local machine for secrets
# walks through every file, reads line by line, runs both regex and entropy checks
#
# pathlib is python's modern way to handle file paths — way cleaner than os.path
# Path("some/folder").rglob("*") = recursively get every file inside that folder

from pathlib import Path
from modules.patterns import PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS, FALSE_POSITIVES
from modules.entropy import find_high_entropy_strings
from utils.display import section, success, warning, error, info, make_table, show_table, console


def should_skip(path: Path) -> bool:
    # returns True if we should skip this file

    # skip blacklisted directories anywhere in the path
    for part in path.parts:
        if part in SKIP_DIRS:
            return True

    # skip binary/useless file types
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True

    return False


def scan_line(line: str, line_num: int, filepath: str) -> list:
    # scans a single line using both regex patterns and entropy analysis
    # returns a list of finding dicts

    findings = []
    line_stripped = line.strip()

    # skip empty lines and comments — too noisy
    if not line_stripped or line_stripped.startswith(('#', '//', '/*', '*', '--')):
        return findings

    # ── regex scan ────────────────────────────────────────────────────────
    for pattern in PATTERNS:
        match = pattern["regex"].search(line)
        if match:
            matched_val = match.group(0)

            # skip if it's a known placeholder
            if any(fp in matched_val.lower() for fp in FALSE_POSITIVES):
                continue

            findings.append({
                "type":     "regex",
                "name":     pattern["name"],
                "severity": pattern["severity"],
                "file":     filepath,
                "line":     line_num,
                "value":    matched_val[:80],  # cap at 80 chars so table doesn't explode
            })

    # ── entropy scan ──────────────────────────────────────────────────────
    high_entropy = find_high_entropy_strings(line)
    for value, score in high_entropy:
        findings.append({
            "type":     "entropy",
            "name":     f"High Entropy String (score: {score})",
            "severity": "HIGH",
            "file":     filepath,
            "line":     line_num,
            "value":    value[:80],
        })

    return findings


def scan_file(filepath: Path) -> list:
    # reads a file line by line and scans each line
    findings = []

    try:
        # errors='ignore' skips bytes that can't be decoded — handles weird encodings
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, start=1):
                results = scan_line(line, line_num, str(filepath))
                findings.extend(results)

    except PermissionError:
        warning(f"Permission denied: {filepath}")
    except Exception as e:
        warning(f"Couldn't read {filepath}: {e}")

    return findings


def run(target_path: str) -> list:
    section("Local File Scanner")

    path = Path(target_path)

    if not path.exists():
        error(f"Path doesn't exist: {target_path}")
        return []

    all_findings = []
    scanned      = 0
    skipped      = 0

    # single file scan
    if path.is_file():
        info(f"Scanning file: {path}")
        all_findings = scan_file(path)
        scanned = 1

    # directory scan — rglob("*") walks everything recursively
    elif path.is_dir():
        info(f"Scanning directory: {path}")

        files = [f for f in path.rglob("*") if f.is_file()]

        for f in files:
            if should_skip(f):
                skipped += 1
                continue
            results = scan_file(f)
            all_findings.extend(results)
            scanned += 1

        info(f"Scanned {scanned} files, skipped {skipped} files.")

    # ── display results ───────────────────────────────────────────────────
    if not all_findings:
        success("No secrets found. Clean!")
        return []

    # sort by severity — CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    table = make_table("Findings", [
        ("Severity", "white"),
        ("Type",     "yellow"),
        ("File",     "cyan"),
        ("Line",     "dim"),
        ("Match",    "dim white"),
    ])

    # color code severity
    severity_colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH":     "[bold yellow]HIGH[/bold yellow]",
        "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    }

    for f in all_findings:
        table.add_row(
            severity_colors.get(f["severity"], f["severity"]),
            f["name"],
            f["file"],
            str(f["line"]),
            f["value"],
        )

    show_table(table)

    # summary line
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    console.print(f"\n  [bold red]CRITICAL: {critical}[/bold red]  "
                  f"[yellow]HIGH: {high}[/yellow]  "
                  f"MEDIUM: {medium}\n")

    return all_findings
