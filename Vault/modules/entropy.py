# modules/entropy.py
# entropy = a measure of randomness/unpredictability in a string
# the idea: real words and placeholders have LOW entropy (predictable patterns)
# actual secrets (tokens, keys) have HIGH entropy (look random)
#
# this is called Shannon Entropy — same concept used in information theory
# formula: H = -sum(p * log2(p)) for each unique character
#
# example:
#   "aaaaaaaaaa"          → entropy ≈ 0.0  (all same char, totally predictable)
#   "password123"         → entropy ≈ 3.1  (low, common pattern)
#   "aB3$xK9!mN2@qR7#"   → entropy ≈ 4.8  (high, looks random = probably a secret)

import math
import re
from modules.patterns import FALSE_POSITIVES

# strings shorter than this probably aren't secrets
MIN_LENGTH = 20

# entropy threshold — strings above this are flagged as suspicious
# 4.5 is a good balance between catching real secrets and avoiding false positives
# lower = more findings but more noise, higher = fewer findings but might miss things
ENTROPY_THRESHOLD = 4.5

# character sets that secrets are usually made from
BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
HEX_CHARS    = set('0123456789abcdefABCDEF')


def shannon_entropy(s: str) -> float:
    # count how often each character appears
    # then calculate the entropy using the formula above

    if not s:
        return 0.0

    # frequency count for each unique character
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length  = len(s)

    for count in freq.values():
        # probability of this character appearing
        p = count / length
        # add its contribution to total entropy
        entropy -= p * math.log2(p)

    return entropy


def looks_like_secret(token: str) -> bool:
    # runs a few checks to decide if a high-entropy string is worth flagging

    if len(token) < MIN_LENGTH:
        return False

    # skip obvious false positives
    if token.lower() in FALSE_POSITIVES:
        return False

    # skip if it looks like a normal word/sentence (has spaces)
    if ' ' in token:
        return False

    # skip if it's all the same character repeated
    if len(set(token)) < 5:
        return False

    # skip URLs — they're long strings but not secrets
    if token.startswith(('http://', 'https://', 'www.')):
        return False

    return True


def find_high_entropy_strings(line: str) -> list:
    # scans a single line of code for high-entropy strings
    # returns list of (string, entropy_score) tuples

    findings = []

    # look for quoted strings — secrets are almost always in quotes in code
    # also look for strings after = signs
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', line)

    # also grab unquoted values after = like: TOKEN=abc123xyz...
    candidates += re.findall(r'=\s*([A-Za-z0-9+/=_\-]{20,})', line)

    for candidate in candidates:
        if not looks_like_secret(candidate):
            continue

        # check if it's made of base64 or hex chars (common for tokens/keys)
        chars = set(candidate)
        is_base64 = chars.issubset(BASE64_CHARS)
        is_hex    = chars.issubset(HEX_CHARS)

        if not (is_base64 or is_hex):
            continue

        entropy = shannon_entropy(candidate)

        if entropy >= ENTROPY_THRESHOLD:
            findings.append((candidate, round(entropy, 2)))

    return findings
