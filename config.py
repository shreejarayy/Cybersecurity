# config.py
# put your API keys and global settings here
# don't commit this file to github if it has real keys in it — add it to .gitignore

# get a free key at https://account.shodan.io
SHODAN_API_KEY = ""

# which modules to run by default (can be overridden via CLI flags)
# set to False to skip a module
DEFAULT_MODULES = {
    "dns":       True,
    "whois":     True,
    "geo":       True,
    "headers":   True,
    "ports":     True,
    "subdomains":True,
    "crtsh":     True,
    "shodan":    True,
}

# port scan timeout in seconds — lower = faster but more misses
PORT_TIMEOUT = 0.5
