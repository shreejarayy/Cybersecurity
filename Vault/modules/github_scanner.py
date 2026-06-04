# modules/github_scanner.py
# scans public github repos for accidentally committed secrets
# uses the github api to fetch file contents — no git clone needed
#
# github api basics:
#   GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1  → get all file paths
#   GET /repos/{owner}/{repo}/contents/{path}                 → get file content (base64 encoded)
#
# rate limits:
#   unauthenticated: 60 requests/hour (runs out fast)
#   authenticated (with token): 5000 requests/hour
#   always use a token if you have one

import requests
import base64
import time
from modules.patterns import PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS, FALSE_POSITIVES
from modules.entropy import find_high_entropy_strings
from modules.local_scanner import scan_line
from utils.display import section, success, warning, error, info, make_table, show_table, console


GITHUB_API = "https://api.github.com"


def parse_repo_url(url: str):
    # extracts owner and repo name from a github url
    # handles: https://github.com/owner/repo or just owner/repo
    url = url.strip().rstrip('/')

    if 'github.com' in url:
        parts = url.split('github.com/')[-1].split('/')
    else:
        parts = url.split('/')

    if len(parts) < 2:
        return None, None

    return parts[0], parts[1]


def get_headers(token: str) -> dict:
    # github asks for a user-agent header, token is optional but recommended
    headers = {"User-Agent": "vault-scanner/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def get_file_tree(owner: str, repo: str, token: str) -> list:
    # fetches the full file tree of the repo — every file path in one request
    # ?recursive=1 means it goes into all subdirectories automatically

    url     = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    resp    = requests.get(url, headers=get_headers(token), timeout=10)

    if resp.status_code == 404:
        error(f"Repo not found: {owner}/{repo}")
        return []
    if resp.status_code == 403:
        error("Rate limit hit or access denied. Add a GitHub token in config.py.")
        return []
    if resp.status_code != 200:
        error(f"GitHub API error: {resp.status_code}")
        return []

    data  = resp.json()
    tree  = data.get("tree", [])

    # filter to only files (not directories) and skip binary/noisy types
    files = []
    for item in tree:
        if item.get("type") != "blob":  # blob = file, tree = directory
            continue

        path = item.get("path", "")

        # skip blacklisted dirs
        if any(skip in path.split('/') for skip in SKIP_DIRS):
            continue

        # skip blacklisted extensions
        from pathlib import Path
        if Path(path).suffix.lower() in SKIP_EXTENSIONS:
            continue

        # skip huge files — github won't return content > 1MB anyway
        if item.get("size", 0) > 500_000:
            continue

        files.append(path)

    return files


def get_file_content(owner: str, repo: str, path: str, token: str) -> str:
    # fetches the content of a single file
    # github returns it as base64 encoded — we decode it back to text

    url  = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=get_headers(token), timeout=10)

    if resp.status_code == 200:
        data    = resp.json()
        content = data.get("content", "")
        # decode base64 — github wraps it with newlines so we strip those first
        try:
            return base64.b64decode(content.replace('\n', '')).decode('utf-8', errors='ignore')
        except Exception:
            return ""

    return ""


def run(repo_url: str, token: str = "") -> list:
    section("GitHub Repository Scanner")

    owner, repo = parse_repo_url(repo_url)
    if not owner or not repo:
        error("Invalid repo URL. Use: https://github.com/owner/repo or owner/repo")
        return []

    info(f"Target: github.com/{owner}/{repo}")

    if not token:
        warning("No GitHub token set — rate limited to 60 requests/hour. Add token in config.py.")

    # get all file paths in the repo
    info("Fetching file tree...")
    files = get_file_tree(owner, repo, token)

    if not files:
        warning("No scannable files found.")
        return []

    info(f"Found {len(files)} files to scan.")

    all_findings = []

    for i, filepath in enumerate(files, 1):
        # show progress every 10 files so it doesn't look frozen
        if i % 10 == 0:
            info(f"Progress: {i}/{len(files)} files scanned...")

        content = get_file_content(owner, repo, filepath, token)

        if not content:
            continue

        # scan line by line — same logic as local scanner
        for line_num, line in enumerate(content.splitlines(), start=1):
            results = scan_line(line, line_num, f"{owner}/{repo}/{filepath}")
            all_findings.extend(results)

        # small delay to be polite to the API and avoid rate limits
        time.sleep(0.1)

    # ── display results ───────────────────────────────────────────────────
    if not all_findings:
        success(f"No secrets found in {owner}/{repo}. Clean!")
        return []

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    table = make_table(f"Findings — {owner}/{repo}", [
        ("Severity", "white"),
        ("Type",     "yellow"),
        ("File",     "cyan"),
        ("Line",     "dim"),
        ("Match",    "dim white"),
    ])

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

    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    console.print(f"\n  [bold red]CRITICAL: {critical}[/bold red]  "
                  f"[yellow]HIGH: {high}[/yellow]  "
                  f"MEDIUM: {medium}\n")

    return all_findings
