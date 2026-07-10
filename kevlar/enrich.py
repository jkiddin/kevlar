"""
Enrich findings with EPSS scores and CISA KEV membership.

Live sources:
  - EPSS:  https://api.first.org/data/v1/epss?cve=CVE-....
  - KEV:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Both are cached to data/cache/ so the pipeline runs offline. Use --refresh to update.
"""

import json
import pathlib

CACHE_DIR = pathlib.Path(__file__).resolve().parent.parent / "data" / "cache"
EPSS_CACHE = CACHE_DIR / "epss_cache.json"
KEV_CACHE = CACHE_DIR / "kev_cache.json"

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def _load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def refresh_caches(cves):
    """Pull live EPSS + KEV data and rewrite the caches. Requires internet."""
    import requests

    epss = _load_json(EPSS_CACHE, {})
    resp = requests.get(EPSS_URL, params={"cve": ",".join(sorted(set(cves)))}, timeout=30)
    resp.raise_for_status()
    for row in resp.json().get("data", []):
        epss[row["cve"]] = float(row["epss"])
    EPSS_CACHE.write_text(json.dumps(epss, indent=2))

    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    kev_cves = sorted({v["cveID"] for v in resp.json().get("vulnerabilities", [])})
    KEV_CACHE.write_text(json.dumps({"cves": kev_cves}, indent=2))
    print(f"[enrich] refreshed caches: {len(epss)} EPSS scores, {len(kev_cves)} KEV entries")

def enrich(findings, refresh=False):
    """Attach epss (float, 0 if unknown) and kev (bool) to each finding dict."""
    if refresh:
        refresh_caches([f["cve"] for f in findings])

    epss = _load_json(EPSS_CACHE, {})
    kev = set(_load_json(KEV_CACHE, {}).get("cves", []))

    for f in findings:
        f["epss"] = float(epss.get(f["cve"], 0.0)) if not str(f["cve"]).startswith("_") else 0.0
        f["kev"] = f["cve"] in kev
    return findings
