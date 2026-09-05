"""CVE correlation.

Given a product/version banner, look up matching CVEs from the NVD CVE API v2.0
and return the highest CVSS base score found. Results are cached on disk so we
never hammer the API and so the pipeline works offline once warmed.

Network access to the NVD is optional: if it is unreachable, correlation simply
returns no CVEs and a neutral base score, and the rest of the pipeline continues.
"""
import json
import os
import re
import time

import config

CACHE_PATH = os.environ.get("CVE_CACHE_PATH", "cve_cache.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH) as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    return _cache


def _save_cache():
    try:
        with open(CACHE_PATH, "w") as f:
            json.dump(_cache, f)
    except Exception:
        pass


def _keyword(product: str) -> str:
    """Reduce a banner/product string to a search keyword like 'Apache 2.4.7'."""
    if not product:
        return ""
    m = re.search(r"([A-Za-z][A-Za-z0-9_\-]+)[/ ]([\d]+\.[\d.]+)", product)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    return product.split("(")[0].strip()[:60]


def correlate(product: str, timeout: float = 8.0) -> dict:
    """Return {'keyword','cve_count','max_cvss','cves':[...]} for a product string."""
    kw = _keyword(product)
    result = {"keyword": kw, "cve_count": 0, "max_cvss": 0.0, "cves": []}
    if not kw:
        return result

    cache = _load_cache()
    if kw in cache:
        return cache[kw]

    try:
        import requests
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        params = {"keywordSearch": kw, "resultsPerPage": 20}
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            cves = []
            max_cvss = 0.0
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                score = _extract_cvss(cve)
                if cid:
                    cves.append({"id": cid, "cvss": score})
                    max_cvss = max(max_cvss, score)
            result = {"keyword": kw, "cve_count": len(cves),
                      "max_cvss": max_cvss, "cves": cves[:10]}
    except Exception:
        pass  # offline / rate-limited: return neutral result

    cache[kw] = result
    _save_cache()
    time.sleep(0.2)  # be gentle with the API
    return result


def _extract_cvss(cve: dict) -> float:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except Exception:
                continue
    return 0.0
