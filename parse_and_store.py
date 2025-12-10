# parse_and_store.py
"""
Parse NVD CVE JSON (v2 API) from data/raw/*.json and store into SQLite.

Fixes:
- Reads published/lastModified from either top-level or cve object.
- Finds CPEs using a recursive search for any "cpeMatch" list.
"""

import os
import json
import sqlite3
import datetime

RAW_DIR = "data/raw"
DB_PATH = "data/db/cves.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

CPE23_PREFIX = "cpe:2.3:"
CPE22_PREFIX = "cpe:/"

def parse_cpe_uri(cpe_uri: str):
    """Parse a CPE URI into (part, vendor, product, version)."""
    res = {"raw": cpe_uri, "part": None, "vendor": None, "product": None, "version": None}
    if not cpe_uri:
        return res
    try:
        if cpe_uri.startswith(CPE23_PREFIX):
            parts = cpe_uri[len(CPE23_PREFIX):].split(":")
            if len(parts) >= 4:
                res["part"], res["vendor"], res["product"], res["version"] = parts[0], parts[1], parts[2], parts[3]
        elif cpe_uri.startswith(CPE22_PREFIX):
            parts = cpe_uri[len(CPE22_PREFIX):].split(":")
            if len(parts) >= 3:
                res["part"], res["vendor"], res["product"] = parts[0], parts[1], parts[2]
                if len(parts) >= 4:
                    res["version"] = parts[3]
        else:
            parts = cpe_uri.split(":")
            if len(parts) >= 4:
                res["part"], res["vendor"], res["product"], res["version"] = parts[0], parts[1], parts[2], parts[3]
    except Exception:
        pass

    for k in ("part", "vendor", "product", "version"):
        if res.get(k) in ("", "-", "*"):
            res[k] = None
    if res["vendor"]:
        res["vendor"] = res["vendor"].replace(" ", "_").lower()
    if res["product"]:
        res["product"] = res["product"].replace(" ", "_").lower()
    return res

def init_db(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        summary TEXT,
        publishedDate TEXT,
        lastModifiedDate TEXT,
        cvss_v3_score REAL,
        cvss_v3_vector TEXT,
        inserted_at TEXT,
        json_blob TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cpe_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        cpe TEXT,
        part TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT,
        FOREIGN KEY(cve_id) REFERENCES cves(id)
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vendor ON cpe_map(vendor);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_map(product);")
    conn.commit()

def extract_cve_fields(item: dict):
    """
    Accepts a single "vulnerability" element from NVD v2.
    Extracts CVE ID, summary, dates, CVSS v3, and keeps raw JSON.
    """
    cve_obj = item.get("cve", {}) or {}

    cve_id = cve_obj.get("id") or cve_obj.get("CVE_data_meta", {}).get("ID")

    # description
    summary = ""
    for d in cve_obj.get("descriptions", []):
        if d.get("lang") == "en":
            summary = d.get("value")
            break

    # dates: can be on item or inside cve object
    published = item.get("published") or cve_obj.get("published")
    lastmod = item.get("lastModified") or cve_obj.get("lastModified")

    cvss_v3_score = None
    cvss_v3_vector = None

    metrics = item.get("metrics") or cve_obj.get("metrics") or {}
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssV3", "cvssV3Metrics"):
            val = metrics.get(key)
            if isinstance(val, list) and val:
                e = val[0]
                cvss_data = e.get("cvssData") or e
                cvss_v3_score = cvss_data.get("baseScore") or cvss_v3_score
                cvss_v3_vector = cvss_data.get("vectorString") or cvss_v3_vector
                if cvss_v3_score is not None:
                    break
        # legacy nested form
        if cvss_v3_score is None and metrics.get("baseMetricV3"):
            b = metrics["baseMetricV3"].get("cvssData", {})
            cvss_v3_score = b.get("baseScore")
            cvss_v3_vector = b.get("vectorString")

    return {
        "id": cve_id,
        "summary": summary,
        "publishedDate": published,
        "lastModifiedDate": lastmod,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "raw": item,
    }

def find_cpes_recursive(obj):
    """
    Recursively walk the JSON object and collect CPE URIs from any 'cpeMatch' list.
    This is robust against changes in 'configurations' structure.
    """
    cpes = []
    if isinstance(obj, dict):
        # if this dict has a cpeMatch list, collect from it
        if "cpeMatch" in obj and isinstance(obj["cpeMatch"], list):
            for m in obj["cpeMatch"]:
                if isinstance(m, dict):
                    for key in ("criteria", "cpe23Uri", "cpe22Uri"):
                        if key in m and m[key]:
                            cpes.append(m[key])
        # recurse into values
        for v in obj.values():
            cpes.extend(find_cpes_recursive(v))
    elif isinstance(obj, list):
        for v in obj:
            cpes.extend(find_cpes_recursive(v))
    return cpes

def process_all_files():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    cur = conn.cursor()

    files = [os.path.join(RAW_DIR, f) for f in os.listdir(RAW_DIR) if f.endswith(".json")]
    files.sort()

    inserted = 0
    for fp in files:
        print("Processing", fp)
        with open(fp, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        vulnerabilities = data.get("vulnerabilities") or data.get("CVE_Items") or []
        for item in vulnerabilities:
            parsed = extract_cve_fields(item)
            cve_id = parsed["id"]
            if not cve_id:
                continue

            now = datetime.datetime.utcnow().isoformat()
            # insert or replace CVE row
            cur.execute(
                """
                INSERT OR REPLACE INTO cves
                (id, summary, publishedDate, lastModifiedDate,
                 cvss_v3_score, cvss_v3_vector, inserted_at, json_blob)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    parsed["summary"],
                    parsed["publishedDate"],
                    parsed["lastModifiedDate"],
                    parsed["cvss_v3_score"],
                    parsed["cvss_v3_vector"],
                    now,
                    json.dumps(parsed["raw"]),
                ),
            )

            # First delete old CPEs for this CVE (in case we are updating)
            cur.execute("DELETE FROM cpe_map WHERE cve_id = ?", (cve_id,))

            # Collect CPEs recursively from the raw item
            raw_item = parsed["raw"]
            cpe_uris = find_cpes_recursive(raw_item)
            # dedupe
            seen = set()
            for c in cpe_uris:
                if c in seen:
                    continue
                seen.add(c)
                p = parse_cpe_uri(c)
                cur.execute(
                    """
                    INSERT INTO cpe_map (cve_id, cpe, part, vendor, product, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cve_id, p["raw"], p["part"], p["vendor"], p["product"], p["version"]),
                )

            inserted += 1

        conn.commit()

    conn.close()
    print("Finished. inserted/updated CVE rows:", inserted)

if __name__ == "__main__":
    process_all_files()
