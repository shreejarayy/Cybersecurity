# ArgusPredict (argus-asm)

**A Predictive Attack Surface Evolution Framework for Proactive Cyber Risk
Intelligence — using temporal graph modelling and context-aware risk scoring.**

ArgusPredict continuously and automatically performs *authorised* reconnaissance,
remembers how an attack surface changes over time, models it as a temporal graph,
detects structurally unusual changes, and produces a prioritised, **explainable**
risk ranking — instead of a flat list ordered by raw CVSS.

> ⚠️ **Authorised use only.** ArgusPredict never contacts a host unless it is on
> the `AUTHORISED_TARGETS` allow-list, and it is observational (no exploitation,
> no login attempts). Only scan systems you are legally permitted to test.
> `scanme.nmap.org` is the Nmap Project's public, authorised educational target.

---

## Features

- **Reconnaissance** — five concurrent collectors: DNS, subdomains, TCP ports,
  service banners, and WHOIS (`argus/recon/`), plus TLS certificate inspection.
- **Persistence** — every scan stored (SQLAlchemy: Target → Scan → Asset → Port →
  Banner, and Asset → Change).
- **Change detection** — typed events: `new_asset`, `new_port`, `closed_port`,
  `banner_changed`, `new_subdomain`.
- **Attack Surface Evolution Graph (ASEG)** — NetworkX graph with per-node
  structural features (centrality, exposure, rarity, propagation).
- **CVE correlation** — banners matched to NVD CVEs (cached, offline-tolerant).
- **Anomaly detection** — Isolation Forest over the structural features.
- **Context-aware risk** — `risk = CVSS × (1 + weighted centrality/exposure/rarity/
  propagation)`, capped at 10, fully explainable.
- **Dashboard** — interactive graph with a **current-vs-last-scan diff overlay**,
  prioritised risk table, evolution timeline, on-demand **scan development sheet**,
  scan-to-scan compare, scheduled monitoring, high-risk alerts, TLS details, and
  PDF/CSV export.
- **Login gate** — optional HTTP Basic auth for safe exposure.

## Quick start (local, zero setup)

```bash
pip install -r requirements.txt

# Fast local scan, no database, no CVE lookup:
python main.py --target 127.0.0.1 --no-db --no-cve

# Full scan against the authorised Nmap target, stored in SQLite:
python main.py --target scanme.nmap.org
```

## Dashboard

```bash
python -m argus.api.app     # then open http://localhost:8050
```

Type an **authorised** target and click **Run scan**. Scan the same target twice
(changing something between runs) to see change detection, the timeline, and the
graph diff overlay come alive.

## Tests

```bash
pytest -q
```

## Configuration

All settings come from environment variables (see `.env.example`). Key ones:

| Variable | Purpose |
|---|---|
| `AUTHORISED_TARGETS` | Comma-separated allow-list (the safety control) |
| `DATABASE_URL` | SQLite by default; set to a PostgreSQL URL in production |
| `APP_PASSWORD` | Set to enable the dashboard login gate (off when empty) |
| `NVD_API_KEY` | Optional; raises NVD rate limits |
| `ALERT_THRESHOLD` / `ALERT_WEBHOOK` | High-risk alerting |
| `PORT_SCAN_THREADS` / `PORT_SCAN_TIMEOUT` | Scan tuning |

## Deployment (Railway / Render)

Both build directly from the included `Dockerfile`.

1. Push to a **private** GitHub repo (`.env` is git-ignored).
2. Create the service from the repo; add a **PostgreSQL** database.
3. Set environment variables: `DATABASE_URL`, `APP_PASSWORD`, `AUTHORISED_TARGETS`.
4. Health check path: `/api/health` (open by design).

> Note: many hosts throttle or prohibit outbound port-scanning. A deployed
> instance is ideal for the dashboard, history, and reports; run live scans
> locally.


## Academic context

Developed as an M.Sc. project. The authorisation allow-list, observational-only
scanning, and explainable scoring are deliberate security-by-design choices.