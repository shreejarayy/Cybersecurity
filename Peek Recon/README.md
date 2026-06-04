# peek

a passive + active recon toolkit built in Python. point it at a domain and it tells you everything publicly available — DNS records, open ports, subdomains, SSL cert history, geolocation, HTTP headers, and more.

built as a portfolio project to learn how recon actually works under the hood.

```
  ██████╗ ███████╗███████╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝█████╗  █████╗  █████╔╝ 
  ██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗ 
  ██║     ███████╗███████╗██║  ██╗
  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
  
  look before you leap
```

---

## what it does

| module | description |
|---|---|
| DNS Enumeration | queries A, AAAA, MX, NS, TXT, CNAME records |
| WHOIS Lookup | domain registration info, registrar, expiry |
| IP Geolocation | country, city, ISP, ASN via ip-api.com |
| HTTP Headers | full header dump + security header audit |
| Port Scanner | threaded TCP scan on 16 common ports + banner grab |
| Subdomain Brute-force | async wordlist-based subdomain discovery |
| Certificate Transparency | passive subdomain find via crt.sh SSL cert logs |
| Shodan Lookup | pulls existing scan data for the target IP |

---

## setup

```bash
# clone the portfolio repo
git clone https://github.com/shreejarayy/cybersec-portfolio.git
cd cybersec-portfolio/peek

# create and activate virtual environment
python -m venv venv
source venv/bin/activate        # mac/linux
venv\Scripts\activate           # windows

# install dependencies
pip install -r requirements.txt
```

---

## usage

```bash
python main.py
```

the tool prompts you interactively — enter a target domain, pick which modules to run, confirm scope, and it runs.

```
Enter target domain or IP:  scanme.nmap.org

Which modules do you want to run?
(press Enter to run ALL, or type numbers e.g. 1,3,5)

  1. DNS Enumeration
  2. WHOIS Lookup
  3. IP Geolocation
  ...
```

---

## shodan setup (optional)

get a free API key at [shodan.io](https://account.shodan.io) and add it to `config.py`:

```python
SHODAN_API_KEY = "your_key_here"
```

`config.py` is gitignored so your key stays local.

---

## project structure

```
peek/
├── main.py                  # entry point, interactive CLI
├── config.py                # API keys (gitignored)
├── requirements.txt
├── modules/
│   ├── dns_enum.py
│   ├── whois_lookup.py
│   ├── ip_geolocation.py
│   ├── http_headers.py
│   ├── port_scanner.py
│   ├── subdomain_brute.py
│   ├── crt_sh.py
│   └── shodan_lookup.py
└── utils/
    └── display.py           # all terminal output (rich)
```

---

## things i learned building this

- how DNS resolution actually works and what each record type means
- the difference between passive recon (crt.sh, Shodan) and active recon (port scanning, subdomain brute-force)
- why threading matters for I/O-bound tasks like port scanning
- why asyncio is better than threading for firing off hundreds of DNS queries
- how HTTP headers expose server info and what missing security headers mean
- how to build a modular CLI tool in Python that doesn't fall apart when one module fails

---

## legal note

only scan targets you own or have explicit written permission to test.
safe to practice on: `scanme.nmap.org`, `testphp.vulnweb.com`, or your own machines.

---

## dependencies

```
dnspython
python-whois
requests
rich
shodan
```
