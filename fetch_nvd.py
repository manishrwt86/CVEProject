# fetch_nvd.py
import requests
import time
import os
import json
from datetime import datetime, timezone, timedelta

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT_DIR = "data/raw"
os.makedirs(OUT_DIR, exist_ok=True)

# Optional: set to your NVD API key string if you have one
API_KEY = None

def iso_z(dt):
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def fetch_chunk(params, api_key=None):
    headers = {
        "User-Agent": "cve-nlp-script/1.0 (+https://example.local/)",
        "Accept": "application/json"
    }
    if api_key:
        headers['apiKey'] = api_key

    resp = requests.get(BASE, params=params, headers=headers, timeout=30)
    if resp.status_code != 200:
        print("DEBUG: Request URL:", resp.url)
        print("DEBUG: Status code:", resp.status_code)
        body = resp.text
        print("DEBUG: Response body (first 1000 chars):\n", body[:1000])
        resp.raise_for_status()
    return resp.json()

def fetch_all_modified_since(start_dt, end_dt, out_prefix="cves"):
    # start_dt, end_dt are datetime objects (timezone-aware UTC)
    # NVD requires both start and end when filtering by lastMod* dates.
    max_days = 120
    if (end_dt - start_dt).days > max_days:
        raise ValueError(f"Date range too large (> {max_days} days). Use a smaller window.")

    start_index = 0
    results_per_page = 200
    all_count = None
    api_key = API_KEY
    delay_seconds = 6
    saved_files = []

    while True:
        params = {
            "lastModStartDate": iso_z(start_dt),
            "lastModEndDate": iso_z(end_dt),
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }
        print("Requesting chunk startIndex=", start_index, "params:", params)
        data = fetch_chunk(params, api_key=api_key)
        vulnerabilities = data.get("vulnerabilities", [])
        if all_count is None:
            all_count = data.get("totalResults", len(vulnerabilities))
            print(f"Total results (reported): {all_count}")

        fname = f"{out_prefix}_{start_index}_{len(vulnerabilities)}.json"
        fpath = os.path.join(OUT_DIR, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        saved_files.append(fpath)
        print("Saved:", fpath)

        start_index += len(vulnerabilities)
        if start_index >= all_count or len(vulnerabilities) == 0:
            break
        print(f"Sleeping {delay_seconds}s to respect rate limits...")
        time.sleep(delay_seconds)
    return saved_files

if __name__ == "__main__":
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    # NVD docs: max range for date filters is 120 days; we use 7 days here.
    iso_start = iso_z(seven_days_ago)
    iso_end = iso_z(now)
    print("Fetching CVEs modified between", iso_start, "and", iso_end)
    fetch_all_modified_since(seven_days_ago, now)
