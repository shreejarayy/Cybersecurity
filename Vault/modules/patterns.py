# modules/patterns.py
# this is basically a dictionary of "what do secrets look like?"
# each pattern has a name, a regex, and a severity level
#
# regex quick recap:
#   [A-Z0-9]   = any uppercase letter or digit
#   {32}       = exactly 32 of the previous thing
#   +          = one or more
#   \b         = word boundary (so we don't match mid-word)
#   (?i)       = case insensitive
#
# severity levels:
#   CRITICAL = this is definitely a real secret (AWS keys, private keys)
#   HIGH     = very likely a secret (API keys, tokens)
#   MEDIUM   = probably a secret but could be a placeholder

import re

PATTERNS = [

    # ── cloud providers ────────────────────────────────────────────────────

    {
        "name":     "AWS Access Key ID",
        "severity": "CRITICAL",
        # AWS access keys always start with AKIA and are 20 chars
        "regex":    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    },
    {
        "name":     "AWS Secret Access Key",
        "severity": "CRITICAL",
        # 40 char base64-ish string usually next to "aws_secret" in config
        "regex":    re.compile(r'(?i)aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    },
    {
        "name":     "Google API Key",
        "severity": "HIGH",
        # google api keys start with AIza
        "regex":    re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    },
    {
        "name":     "Google OAuth Token",
        "severity": "HIGH",
        "regex":    re.compile(r'\b1\/\/[0-9A-Za-z\-_]{43}\b'),
    },

    # ── generic api keys & tokens ──────────────────────────────────────────

    {
        "name":     "Generic API Key",
        "severity": "HIGH",
        # catches patterns like: api_key = "abc123..." or apikey: "..."
        "regex":    re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
    },
    {
        "name":     "Generic Secret",
        "severity": "HIGH",
        # catches: secret = "..." or secret_key = "..."
        "regex":    re.compile(r'(?i)(secret|secret_key|secret_token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?'),
    },
    {
        "name":     "Generic Password",
        "severity": "MEDIUM",
        # catches: password = "abc123" — lots of false positives but worth checking
        "regex":    re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?'),
    },
    {
        "name":     "Bearer Token",
        "severity": "HIGH",
        # Authorization: Bearer <token> in code
        "regex":    re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)'),
    },

    # ── jwt tokens ─────────────────────────────────────────────────────────

    {
        "name":     "JWT Token",
        "severity": "HIGH",
        # JWTs are 3 base64 chunks separated by dots — easy to spot
        "regex":    re.compile(r'\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b'),
    },

    # ── private keys ───────────────────────────────────────────────────────

    {
        "name":     "RSA Private Key",
        "severity": "CRITICAL",
        # PEM format header — if someone committed a .pem file this catches it
        "regex":    re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    },
    {
        "name":     "Private Key (generic)",
        "severity": "CRITICAL",
        "regex":    re.compile(r'-----BEGIN (EC|PGP|DSA|OPENSSH) PRIVATE KEY-----'),
    },

    # ── service-specific tokens ────────────────────────────────────────────

    {
        "name":     "GitHub Token",
        "severity": "CRITICAL",
        # github personal access tokens start with ghp_ or github_pat_
        "regex":    re.compile(r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b'),
    },
    {
        "name":     "Slack Token",
        "severity": "HIGH",
        # slack tokens start with xox
        "regex":    re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b'),
    },
    {
        "name":     "Stripe API Key",
        "severity": "CRITICAL",
        # sk_live = live key (bad), sk_test = test key (less bad but still)
        "regex":    re.compile(r'\b(sk_live|sk_test)_[0-9A-Za-z]{24,}\b'),
    },
    {
        "name":     "Twilio Auth Token",
        "severity": "HIGH",
        "regex":    re.compile(r'(?i)twilio.*[0-9a-f]{32}'),
    },
    {
        "name":     "SendGrid API Key",
        "severity": "HIGH",
        "regex":    re.compile(r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b'),
    },
    {
        "name":     "Shodan API Key",
        "severity": "HIGH",
        "regex":    re.compile(r'(?i)shodan.*api.*key\s*=\s*["\']?([A-Za-z0-9]{32})["\']?'),
    },

    # ── database connection strings ────────────────────────────────────────

    {
        "name":     "Database URL",
        "severity": "CRITICAL",
        # catches postgres://, mysql://, mongodb:// style connection strings with credentials
        "regex":    re.compile(r'(?i)(postgres|mysql|mongodb|redis|sqlite):\/\/[^:]+:[^@]+@'),
    },

    # ── other common leaks ─────────────────────────────────────────────────

    {
        "name":     "Email + Password combo",
        "severity": "MEDIUM",
        "regex":    re.compile(r'(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\s*[=:]\s*["\']?[^\s"\']{6,}'),
    },
    {
        "name":     "IP Address with Port (internal)",
        "severity": "MEDIUM",
        # internal IPs in code sometimes expose infra details
        "regex":    re.compile(r'\b(192\.168|10\.\d+|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+:\d+\b'),
    },
]

# file extensions to skip entirely — binary files, images, etc.
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf',
    '.zip', '.tar', '.gz', '.exe', '.bin', '.dll', '.so',
    '.pyc', '.pyo', '.class', '.jar', '.war',
    '.mp4', '.mp3', '.avi', '.mov',
    '.ttf', '.woff', '.woff2', '.eot',
    '.lock',  # package lock files are noisy and rarely have secrets
}

# folders to skip — these are almost always noisy
SKIP_DIRS = {
    '.git', 'node_modules', 'venv', 'env', '.venv',
    '__pycache__', '.idea', '.vscode', 'dist', 'build',
}

# values that look like secrets but aren't — common placeholders
FALSE_POSITIVES = {
    'your_api_key_here', 'your-api-key', 'xxxxxxxxxxxx',
    'example', 'placeholder', 'changeme', 'your_token',
    'insert_key_here', 'api_key_here', 'secret_here',
    'password123', 'test', 'dummy', 'fake', 'sample',
    'xxxxxxxx', '12345678', 'abcdefgh',
}
