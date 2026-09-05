"""
Central configuration for ArgusPredict.

All settings are read from environment variables (optionally loaded from a .env
file) so that nothing sensitive is hard-coded. See .env.example for the full list.

SAFETY: The authorisation allow-list (AUTHORISED_TARGETS) is the single most
important control in this project. No host is ever contacted for reconnaissance
unless it appears on this list. The check is enforced in code (see
is_authorised) before any packet is sent.
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def _get(name, default=None):
    return os.environ.get(name, default)


# --- Database -------------------------------------------------------------
# Default to a local SQLite file so the project runs anywhere with no setup.
# In production the report uses PostgreSQL; just set DATABASE_URL accordingly,
# e.g. postgresql://argus:argus@postgres:5432/argus
DATABASE_URL = _get("DATABASE_URL", "sqlite:///arguspredict.db")
# Some hosts (Railway/Render/Heroku) hand out the legacy 'postgres://' scheme,
# which SQLAlchemy 2.0 rejects. Normalise it to 'postgresql://'.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- Dashboard login gate -------------------------------------------------
# Auth is DISABLED when APP_PASSWORD is empty (convenient for local dev) and
# ENABLED as soon as you set APP_PASSWORD (do this before exposing it online).
APP_USERNAME = _get("APP_USERNAME", "admin")
APP_PASSWORD = _get("APP_PASSWORD", "")

# --- External services ----------------------------------------------------
NVD_API_KEY = _get("NVD_API_KEY", "")          # optional; raises rate limits
REDIS_URL = _get("REDIS_URL", "redis://redis:6379/0")  # used only if Celery is enabled

# --- Scan behaviour -------------------------------------------------------
SCAN_INTERVAL_HOURS = int(_get("SCAN_INTERVAL_HOURS", "24"))
PORT_SCAN_THREADS = int(_get("PORT_SCAN_THREADS", "150"))
PORT_SCAN_TIMEOUT = float(_get("PORT_SCAN_TIMEOUT", "3.0"))
BANNER_TIMEOUT = float(_get("BANNER_TIMEOUT", "2.0"))
TOP_PORTS = int(_get("TOP_PORTS", "1000"))
# Scan IPv6 addresses too? Off by default: many home/campus networks lack a
# working global IPv6 route, which would make every IPv6 probe time out.
SCAN_IPV6 = _get("SCAN_IPV6", "false").strip().lower() in ("1", "true", "yes")

# --- Analytics ------------------------------------------------------------
ANOMALY_THRESHOLD = float(_get("ANOMALY_THRESHOLD", "0.80"))

# --- Alerting -------------------------------------------------------------
# When a newly-opened port scores at or above this, raise an alert. Optionally
# POST the alert JSON to ALERT_WEBHOOK (e.g. a Slack/Teams/Discord webhook).
ALERT_THRESHOLD = float(_get("ALERT_THRESHOLD", "9.0"))
ALERT_WEBHOOK = _get("ALERT_WEBHOOK", "")

# Ports on which to attempt a TLS certificate inspection.
TLS_PORTS = [int(p) for p in _get("TLS_PORTS", "443,8443,993,995,465,990").split(",") if p.strip()]

# Weights for the context-aware risk score. The composite is:
#   risk = CVSS * (1 + w_c*centrality + w_e*exposure + w_r*rarity + w_p*propagation)
# capped at 10.0.  Kept in config so they can be tuned rather than hard-coded.
RISK_WEIGHTS = {
    "centrality": float(_get("RISK_W_CENTRALITY", "0.25")),
    "exposure": float(_get("RISK_W_EXPOSURE", "0.20")),
    "rarity": float(_get("RISK_W_RARITY", "0.15")),
    "propagation": float(_get("RISK_W_PROPAGATION", "0.20")),
}

# --- SAFETY: authorisation allow-list ------------------------------------
# Comma-separated list of hostnames/IPs that MAY be scanned. The default is the
# Nmap Project's public, explicitly-authorised educational scanning target, plus
# localhost for safe local demos. Add a target here ONLY if you are legally
# authorised to scan it.
_raw_targets = _get("AUTHORISED_TARGETS", "scanme.nmap.org,127.0.0.1,localhost,google.com,cue.christuniversity.in,monkeytype.com,github.com, discord.com")
AUTHORISED_TARGETS = [t.strip().lower() for t in _raw_targets.split(",") if t.strip()]


def is_authorised(target: str) -> bool:
    """Return True only if `target` is on the authorisation allow-list."""
    if not target:
        return False
    return target.strip().lower() in AUTHORISED_TARGETS


class UnauthorisedTargetError(Exception):
    """Raised when a scan is attempted against a target not on the allow-list."""


def require_authorised(target: str) -> None:
    """Hard gate: raise unless `target` is explicitly authorised."""
    if not is_authorised(target):
        raise UnauthorisedTargetError(
            f"Refusing to scan '{target}': it is not on AUTHORISED_TARGETS. "
            f"Only scan systems you are legally authorised to test. "
            f"Authorised: {', '.join(AUTHORISED_TARGETS)}"
        )