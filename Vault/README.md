# vault

a secrets scanner that finds accidentally committed API keys, passwords, and tokens — in local files or public GitHub repos.

built to understand how real security tools like truffleHog and gitleaks work under the hood.

```
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
 ██║   ██║███████║██║   ██║██║     ██║   
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   

  find what shouldn't have left the vault
```

---

## why this exists

developers accidentally push secrets to GitHub all the time — API keys in config files, passwords in `.env` files, tokens hardcoded in scripts. once it's on a public repo, bots scrape it within minutes and abuse it.

vault scans for these before (or after) they cause damage.

---

## what it does

| module | what it does |
|---|---|
| `patterns.py` | library of 20 regex patterns covering AWS keys, GitHub tokens, JWT, Stripe, database URLs, and more |
| `entropy.py` | calculates Shannon entropy on strings to catch secrets that don't match known patterns |
| `local_scanner.py` | walks through files/folders on your machine and scans each line |
| `github_scanner.py` | fetches file contents from a public GitHub repo via API and scans them |

---

## how detection works — explained simply

vault uses two methods at the same time:

### method 1 — regex pattern matching
regex = a way to describe what a string looks like using a pattern.

for example, AWS access keys always look like this: start with `AKIA`, followed by exactly 16 uppercase letters or digits. so the pattern is:
```
AKIA[0-9A-Z]{16}
```
vault has 20 of these patterns covering the most common secret types. if a line of code matches any pattern, it's flagged.

**what it's good at:** catching known, structured secrets with near-zero false positives.  
**what it misses:** custom tokens or keys that don't follow a known format.

---

### method 2 — Shannon entropy analysis
entropy = a measure of how random a string looks.

the idea comes from information theory. real words and placeholders are predictable (low entropy). actual secrets are random-looking (high entropy).

```
"password123"          → entropy ≈ 3.1  (low — common pattern, not flagged)
"aB3$xK9mN2qR7pL8wZ"  → entropy ≈ 4.8  (high — looks random, flagged)
```

the formula (Shannon entropy):
```
H = -Σ (p × log₂p)
```
where `p` is the probability of each character appearing. the more uniform the character distribution, the higher the entropy.

vault flags anything above **4.5 entropy** that's also long enough and made of base64 or hex characters (the character sets tokens are usually built from).

**what it's good at:** catching unknown or custom secrets that no regex covers.  
**what it misses:** short secrets, or secrets with low randomness.

**using both together means fewer missed findings overall.**

---

## how the github scanner works

1. calls the GitHub API to get a list of every file in the repo
2. fetches each file's content — GitHub returns it as **base64 encoded** text
3. decodes it back to readable text
4. scans it line by line, same as the local scanner

```
GitHub API → file tree → fetch each file → decode base64 → scan lines → flag findings
```

rate limits:
- without a token: 60 API requests/hour (runs out fast on big repos)
- with a GitHub token: 5000 requests/hour

---

## severity levels

| level | meaning | example |
|---|---|---|
| CRITICAL | confirmed real secret format | AWS key, private key, GitHub token, database URL |
| HIGH | very likely a secret | generic API key, JWT token, Slack token |
| MEDIUM | possibly a secret, more noise | hardcoded password, internal IP, email+password combo |

---

## false positive handling

not every long random string is a secret. vault filters out:
- strings shorter than 20 characters
- known placeholder values (`your_api_key_here`, `changeme`, `xxxx...`)
- strings with fewer than 5 unique characters (probably not random)
- URLs
- comment lines and blank lines
- binary files, images, lock files, `__pycache__`, `node_modules`

---

## setup

```bash
git clone https://github.com/shreejarayy/Cybersecurity.git
cd Cybersecurity/Vault

python -m venv venv
venv\Scripts\activate        # windows
source venv/bin/activate     # mac/linux

pip install -r requirements.txt
```

---

## usage

```bash
python main.py
```

it'll ask what you want to scan:

```
What do you want to scan?

  1. Local file or folder
  2. Public GitHub repository
```

for local scan — enter a path like `C:\Projects\myapp` or `/home/user/project`  
for github scan — enter a URL like `https://github.com/owner/repo` or just `owner/repo`

---

## optional — github token

add your token to `config.py` to avoid hitting the rate limit on large repos:

```python
GITHUB_TOKEN = "your_token_here"
```

generate one at: github.com → Settings → Developer settings → Personal access tokens → tick `public_repo`

`config.py` is gitignored so it never gets pushed.

---

## project structure

```
Vault/
├── main.py                  # entry point, interactive CLI
├── config.py                # GitHub token (gitignored)
├── requirements.txt
├── modules/
│   ├── patterns.py          # 20 regex patterns for known secret formats
│   ├── entropy.py           # Shannon entropy engine
│   ├── local_scanner.py     # scans local files and folders
│   └── github_scanner.py    # scans public GitHub repos via API
└── utils/
    └── display.py           # terminal output (rich)
```

---

## what i learned building this

- how regex patterns are used in real security tooling to detect structured secrets
- what Shannon entropy is and why high randomness = likely a secret
- how the GitHub API works — fetching file trees, decoding base64 content, handling rate limits
- why false positive filtering matters — a scanner that cries wolf on everything is useless
- the difference between known-pattern detection and behaviour-based detection (the same distinction used in antivirus and SIEM tools)

---

## dependencies

```
requests
rich
```

---

## legal note

only scan repos and files you own or have permission to scan. vault is a defensive tool — use it to audit your own code before pushing, or as part of a security review you're authorized to conduct.
