# Argus ASM
### Attack Surface Management Platform

> Built by Shreeja Ray | PG Cybersecurity | [github.com/shreejarayy/Cybersecurity](https://github.com/shreejarayy/Cybersecurity)

---

## What is this project, in plain terms?

Imagine you have a house. You know about the front door and the back door — but what about the window you forgot to lock on the second floor? Or the gap in the fence? An attacker doesn't just try the front door. They walk all the way around the house looking for anything you missed.

This project is a tool that does exactly that — but for websites, servers, and online services instead of houses.

**Argus** automatically scans the internet-facing parts of a target (with permission) and answers:
- What domains, subdomains, and IP addresses are exposed?
- Which ports and services are reachable from the outside?
- What software versions are running — and are any of them vulnerable?
- Has anything changed since the last scan?

Most companies only find out they had an exposed service *after* an attacker used it. Argus finds it first.

The name comes from Argus Panoptes — the 100-eyed giant from Greek mythology who never stopped watching.

---

## Tech stack

| Layer | Tools |
|-------|-------|
| Recon | Python, dnspython, python-whois, requests |
| Database | PostgreSQL, SQLAlchemy |
| Task queue | Celery, Redis |
| AI / ML | scikit-learn (Isolation Forest), sentence-transformers |
| API | Flask |
| Frontend | React, Recharts |
| Packaging | Docker, Docker Compose |

---

## Project roadmap

| Phase | What gets built | Status |
|-------|----------------|--------|
| Week 1 | Recon pipeline + DB schema | ✅ Done |
| Week 2 | Change detection + scheduler | 🔲 Planned |
| Week 3–4 | Processing pipeline | 🔲 Planned |
| Week 5–7 | AI analysis layer | 🔲 Planned |
| Week 8–9 | Dashboard + REST API | 🔲 Planned |

---

## Commit log

Each entry below is one commit. Update the status column as you push.

---

### Week 1 — Recon pipeline

---

#### `feat: initialise project structure`
**What changed:** Created the folder layout (`recon/`, `db/`, `config/`), added `.gitignore`, `README.md`, and empty `__init__.py` files.
**Why it matters:** Every repo needs a clean starting point before any real code goes in. This commit just sets the skeleton.
**Files touched:** `recon/__init__.py`, `db/__init__.py`, `config/__init__.py`, `.gitignore`, `README.md`
**Status:** 🔲

---

#### `feat: add DNS enumeration module`
**What changed:** `recon/dns_enum.py` — queries A, MX, NS, TXT, AAAA, and CNAME records for a target domain using `dnspython`. Returns a structured dict.
**Why it matters:** DNS records are the first thing any attacker or researcher looks up. They reveal mail servers, name servers, IP addresses, and SPF/DMARC config. This is the entry point of any recon run.
**Files touched:** `recon/dns_enum.py`
**Status:** 🔲

---

#### `feat: add subdomain brute-force module`
**What changed:** `recon/subdomain_brute.py` — takes a wordlist and tries resolving every word as a subdomain (e.g. `admin.example.com`). Uses 20 concurrent DNS workers so it doesn't take forever. Falls back to a built-in 20-word list if no wordlist is supplied.
**Why it matters:** Subdomains like `staging.company.com` or `dev.company.com` are often forgotten and left insecure. This module finds them.
**Files touched:** `recon/subdomain_brute.py`, `recon/wordlists/subdomains-500.txt`
**Status:** 🔲

---

#### `feat: add TCP port scanner`
**What changed:** `recon/port_scan.py` — scans the top-1000 TCP ports using full connect (no root required). Runs 150 threads simultaneously. Maps common ports to service names (SSH, HTTP, MySQL, etc.).
**Why it matters:** Open ports are open doors. Port 3306 open to the internet means someone left MySQL exposed. This module finds every open door.
**Files touched:** `recon/port_scan.py`
**Status:** 🔲

---

#### `feat: add WHOIS lookup module`
**What changed:** `recon/whois_lookup.py` — pulls registrar, organisation name, country, creation/expiry dates, name servers, and contact emails for a domain.
**Why it matters:** WHOIS tells you who owns the domain, when it expires (expiring domains can be hijacked), and often leaks internal org info. It's free public data and always worth collecting.
**Files touched:** `recon/whois_lookup.py`
**Status:** 🔲

---

#### `feat: add banner grabbing module`
**What changed:** `recon/banner_grab.py` — for HTTP/HTTPS ports it sends a HEAD request and captures response headers (Server, X-Powered-By, etc.). For other ports it opens a raw TCP connection and reads the first 1024 bytes. For HTTPS it also extracts TLS certificate details.
**Why it matters:** Banners reveal exact software versions — `Apache/2.2.34` or `OpenSSH_7.4`. These version strings are directly searchable in CVE databases. This module is what feeds the AI layer later.
**Files touched:** `recon/banner_grab.py`
**Status:** 🔲

---

#### `feat: add concurrent recon runner`
**What changed:** `recon/runner.py` — wires all modules together. Runs DNS, subdomains, ports, and WHOIS in parallel using `ThreadPoolExecutor`. Then runs banner grabbing on the open ports returned by the port scanner.
**Why it matters:** Without a runner, each module has to be called manually. This makes the whole recon pipeline a single function call: `run_all("example.com")`.
**Files touched:** `recon/runner.py`, `recon/__init__.py`
**Status:** 🔲

---

#### `feat: add database models and session setup`
**What changed:** `db/models.py` — SQLAlchemy ORM models for `Asset`, `Port`, and `Banner` tables. `db/database.py` — engine setup, session factory, and a `get_db()` context manager.
**Why it matters:** All recon results need to be stored so they can be compared across scans (change detection in Week 2). Without a database, every scan result disappears when the script ends.
**Files touched:** `db/models.py`, `db/database.py`
**Status:** 🔲

---

#### `feat: add config with environment variable loading`
**What changed:** `config/settings.py` — uses `pydantic-settings` to load config from a `.env` file. Variables include `DATABASE_URL`, `SHODAN_API_KEY`, `TARGET_DOMAIN`, and scan settings.
**Why it matters:** Hardcoding credentials in source code is a security anti-pattern (and embarrassing to push to GitHub). This separates config from code cleanly.
**Files touched:** `config/settings.py`, `.env.example`
**Status:** 🔲

---

#### `feat: add CLI entrypoint`
**What changed:** `main.py` — accepts a `--target` argument, runs all recon modules via `runner.run_all()`, persists results to the database, and prints a formatted summary table using `rich`.
**Why it matters:** This is the deliverable for Week 1. Running `python main.py --target example.com` now does the full recon pipeline end to end.
**Files touched:** `main.py`, `requirements.txt`
**Status:** 🔲

---

#### `chore: add requirements and pin versions`
**What changed:** `requirements.txt` with pinned versions for all dependencies: `dnspython`, `python-whois`, `requests`, `sqlalchemy`, `psycopg2-binary`, `pydantic-settings`, `rich`, `python-dotenv`, `urllib3`.
**Why it matters:** Without pinned versions, `pip install` can pull different package versions on different machines and break things silently.
**Files touched:** `requirements.txt`
**Status:** 🔲

---

### Week 2 — Change detection + scheduler

---

#### `feat: add change detection logic`
**What changed:** `db/change_detector.py` — compares the latest scan results against the previous scan stored in the database. Flags new assets, newly opened ports, closed ports, and changed banners.
**Why it matters:** The whole point of ASM is *continuous* monitoring. A single scan is just a snapshot. Change detection is what turns Argus from a one-shot tool into a platform.
**Files touched:** `db/change_detector.py`
**Status:** 🔲

---

#### `feat: add Celery task queue and scan scheduler`
**What changed:** `tasks/scan_tasks.py` — wraps `run_all()` as a Celery task. `tasks/scheduler.py` — APScheduler configuration that kicks off a full scan every 24 hours per target.
**Why it matters:** Scans need to run on a schedule without someone manually running the script. Celery handles queuing and retries; the scheduler handles timing.
**Files touched:** `tasks/scan_tasks.py`, `tasks/scheduler.py`, `docker-compose.yml`
**Status:** 🔲

---

### Week 3–4 — Processing pipeline

---

#### `feat: add data normalisation pipeline`
**What changed:** `pipeline/normalise.py` — standardises raw recon output into consistent formats before DB insertion (lowercased domains, stripped whitespace, validated IPs, deduplicated records).
**Why it matters:** Different modules return slightly different formats. Normalisation ensures the database stays clean and queries don't miss records due to formatting inconsistencies.
**Files touched:** `pipeline/normalise.py`
**Status:** 🔲

---

#### `feat: integrate NVD CVE API for vulnerability lookup`
**What changed:** `pipeline/cve_lookup.py` — queries the NVD REST API for CVEs matching software and version strings extracted from banners (e.g. `Apache 2.2.34`). Caches results locally to avoid rate-limit issues.
**Why it matters:** A banner that says `OpenSSH_7.4` is just text until you look up whether `OpenSSH 7.4` has known CVEs. This module does that lookup automatically.
**Files touched:** `pipeline/cve_lookup.py`
**Status:** 🔲

---

### Week 5–7 — AI analysis layer

---

#### `feat: add CVSS-based risk scoring`
**What changed:** `ai/risk_scorer.py` — takes CVE matches from the pipeline and computes a per-asset risk score using CVSS base scores, weighted by asset exposure (internet-facing scores higher).
**Why it matters:** Not all vulnerabilities are equal. A CVSS 9.8 on an internet-facing port is critical. A CVSS 3.1 on an internal-only service is low priority. This module does that prioritisation automatically.
**Files touched:** `ai/risk_scorer.py`
**Status:** 🔲

---

#### `feat: add NLP banner classification`
**What changed:** `ai/banner_classifier.py` — uses TF-IDF + a lightweight classifier to tag service banners with categories (outdated software, default config, admin panel exposed, etc.).
**Why it matters:** Raw banners are strings. This module turns them into actionable labels that can be surfaced on the dashboard without a human reading every banner manually.
**Files touched:** `ai/banner_classifier.py`
**Status:** 🔲

---

#### `feat: add Isolation Forest anomaly detection`
**What changed:** `ai/anomaly_detector.py` — trains an Isolation Forest on historical scan data to flag unusual changes in asset exposure (sudden spike in open ports, new service appearing overnight).
**Why it matters:** Not all threats come with CVE numbers. An Isolation Forest catches statistically unusual patterns — which is exactly what an attacker probing a network looks like.
**Files touched:** `ai/anomaly_detector.py`
**Status:** 🔲

---

### Week 8–9 — Dashboard and API

---

#### `feat: add Flask REST API`
**What changed:** `api/app.py` and route files under `api/routes/` — endpoints for assets, scan history, risk scores, and alert feed. Returns JSON.
**Why it matters:** The database and AI layer are useless if there's no way to query them. The API is what the frontend and any future integrations talk to.
**Files touched:** `api/app.py`, `api/routes/assets.py`, `api/routes/scans.py`, `api/routes/risks.py`
**Status:** 🔲

---

#### `feat: add React dashboard`
**What changed:** `frontend/` — React app with pages for: asset inventory, risk heatmap, scan timeline, and alert feed. Uses Recharts for visualisations.
**Why it matters:** This is the face of the platform. A recruiter or evaluator looking at the project should be able to open the dashboard and immediately see what Argus found.
**Files touched:** `frontend/src/`
**Status:** 🔲

---

#### `feat: add Docker Compose for full stack`
**What changed:** `docker-compose.yml` — orchestrates PostgreSQL, Redis, the Celery worker, the Flask API, and the React frontend as separate containers.
**Why it matters:** "Works on my machine" is not a portfolio project. Docker Compose means anyone can clone the repo and run `docker compose up` to get the full platform running.
**Files touched:** `docker-compose.yml`, `Dockerfile`, `frontend/Dockerfile`
**Status:** 🔲

---

#### `docs: final write-up and demo screenshots`
**What changed:** Updated `README.md` with architecture diagram, setup guide, sample output screenshots, and known limitations section.
**Why it matters:** The README is the first thing anyone sees on GitHub. A project with no explanation is a project that gets ignored.
**Files touched:** `README.md`, `docs/`
**Status:** 🔲

---

## Legal notice

This tool is for authorised security research only. Only scan domains and systems you own or have explicit written permission to test. Unauthorised scanning may violate the IT Act 2000 (India), the CFAA (US), and equivalent laws elsewhere.

---

## How to run (Week 1)

```bash
git clone https://github.com/shreejarayy/argus-asm
cd argus-asm
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # fill in DATABASE_URL
python main.py --target example.com
```
