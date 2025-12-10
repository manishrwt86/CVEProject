# server/main.py
import os
import json
import sqlite3
import io
import csv
import torch
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from collections import defaultdict 
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# Compute project root (project_root/server/main.py -> project_root)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Allow overriding DB path via env var if needed
DB_PATH = os.environ.get("CVE_DB_PATH", os.path.join(PROJECT_ROOT, "data", "db", "cves.db"))

app = FastAPI(title="CVE DB API")

# CORS for convenience during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static and templates live inside server/
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(SERVER_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(SERVER_DIR, "templates"))


def get_conn():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"DB not found at {DB_PATH}. Run parse_and_store.py first.")
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
def health():
    return {"status": "ok", "db_exists": os.path.exists(DB_PATH)}


@app.get("/api/cve/{cve_id}")
def get_cve(cve_id: str):
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()
    cur.execute(
        "SELECT id, summary, publishedDate, lastModifiedDate, cvss_v3_score, cvss_v3_vector, json_blob "
        "FROM cves WHERE id = ?",
        (cve_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")

    raw_blob = None
    try:
        raw_blob = json.loads(row["json_blob"]) if row["json_blob"] else None
    except Exception:
        raw_blob = None

    return JSONResponse(
        {
            "id": row["id"],
            "summary": row["summary"],
            "published": row["publishedDate"],
            "lastModified": row["lastModifiedDate"],
            "cvss_v3_score": row["cvss_v3_score"],
            "cvss_v3_vector": row["cvss_v3_vector"],
            "raw": raw_blob,
        }
    )


@app.get("/api/search")
def search_cves(vendor: Optional[str] = None, product: Optional[str] = None, limit: int = 50):
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()

    ids = []
    if vendor:
        cur.execute("SELECT DISTINCT cve_id FROM cpe_map WHERE vendor LIKE ? LIMIT ?", (f"%{vendor}%", limit))
        ids = [r[0] for r in cur.fetchall()]
    elif product:
        cur.execute("SELECT DISTINCT cve_id FROM cpe_map WHERE product LIKE ? LIMIT ?", (f"%{product}%", limit))
        ids = [r[0] for r in cur.fetchall()]
    else:
        cur.execute("SELECT id FROM cves ORDER BY publishedDate DESC LIMIT ?", (limit,))
        ids = [r[0] for r in cur.fetchall()]

    results = []
    for cve_id in ids:
        cur.execute("SELECT id, summary, publishedDate, cvss_v3_score FROM cves WHERE id = ?", (cve_id,))
        r = cur.fetchone()
        if r:
            results.append(
                {
                    "id": r["id"],
                    "summary": r["summary"],
                    "published": r["publishedDate"],
                    "cvss": r["cvss_v3_score"],
                }
            )

    conn.close()
    return JSONResponse(results)


@app.get("/api/top-products")
def top_products(limit: int = 20):
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()
    cur.execute(
        "SELECT vendor, product, COUNT(*) as hits "
        "FROM cpe_map "
        "WHERE product IS NOT NULL "
        "GROUP BY vendor, product "
        "ORDER BY hits DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return JSONResponse([{"vendor": r["vendor"], "product": r["product"], "hits": r["hits"]} for r in rows])


@app.get("/api/recent")
def recent(limit: int = 50):
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()
    cur.execute(
        "SELECT id, summary, publishedDate, cvss_v3_score "
        "FROM cves ORDER BY publishedDate DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return JSONResponse(
        [{"id": r["id"], "summary": r["summary"], "published": r["publishedDate"], "cvss": r["cvss_v3_score"]} for r in rows]
    )


@app.get("/api/stats/summary")
def stats_summary():
    """
    Advanced analysis endpoint:
    - monthly_counts: CVE count per year-month
    - severity_trend: CVE count per (year-month, severity_bucket)
    - top_critical_vendors: vendors with most critical CVEs (cvss >= 9.0)
    """
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()

    # Monthly counts
    cur.execute(
        """
        SELECT substr(publishedDate, 1, 7) AS ym, COUNT(*) AS c
        FROM cves
        WHERE publishedDate IS NOT NULL
        GROUP BY ym
        ORDER BY ym
        """
    )
    rows = cur.fetchall()
    monthly = [{"year_month": r["ym"], "count": r["c"]} for r in rows]

    # Severity buckets per month
    cur.execute(
        """
        SELECT
          substr(publishedDate, 1, 7) AS ym,
          CASE
            WHEN cvss_v3_score IS NULL THEN 'unknown'
            WHEN cvss_v3_score < 4.0 THEN 'low'
            WHEN cvss_v3_score < 7.0 THEN 'medium'
            WHEN cvss_v3_score < 9.0 THEN 'high'
            ELSE 'critical'
          END AS severity_bucket,
          COUNT(*) AS c
        FROM cves
        WHERE publishedDate IS NOT NULL
        GROUP BY ym, severity_bucket
        ORDER BY ym, severity_bucket
        """
    )
    rows = cur.fetchall()
    severity_trend = [
        {"year_month": r["ym"], "severity_bucket": r["severity_bucket"], "count": r["c"]} for r in rows
    ]

    # Top critical vendors
    cur.execute(
        """
        SELECT cpe_map.vendor, COUNT(DISTINCT cpe_map.cve_id) AS critical_cves
        FROM cpe_map
        JOIN cves ON cves.id = cpe_map.cve_id
        WHERE cves.cvss_v3_score >= 9.0
          AND cpe_map.vendor IS NOT NULL
        GROUP BY cpe_map.vendor
        ORDER BY critical_cves DESC
        LIMIT 10
        """
    )
    rows = cur.fetchall()
    top_critical_vendors = [{"vendor": r["vendor"], "critical_cves": r["critical_cves"]} for r in rows]

    conn.close()
    return JSONResponse(
        {
            "monthly_counts": monthly,
            "severity_trend": severity_trend,
            "top_critical_vendors": top_critical_vendors,
        }
    )


@app.get("/api/export/impact")
def export_impact(limit: int = 2000):
    """
    Export impact-oriented CSV:
    cve_id, publishedDate, cvss_v3_score, vendor, product, version
    """
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()
    cur.execute(
        """
        SELECT cves.id AS cve_id,
               cves.publishedDate,
               cves.cvss_v3_score,
               cpe_map.vendor,
               cpe_map.product,
               cpe_map.version
        FROM cves
        LEFT JOIN cpe_map ON cves.id = cpe_map.cve_id
        ORDER BY cves.cvss_v3_score DESC NULLS LAST
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["cve_id", "publishedDate", "cvss_v3_score", "vendor", "product", "version"])
    for r in rows:
        writer.writerow([r["cve_id"], r["publishedDate"], r["cvss_v3_score"], r["vendor"], r["product"], r["version"]])

    output.seek(0)
    headers = {
        "Content-Disposition": 'attachment; filename="impact_export.csv"',
        "Content-Type": "text/csv",
    }
    return StreamingResponse(output, headers=headers, media_type="text/csv")


def parse_attack_vector(vector: str) -> str:
    """
    Parse CVSS v3 vector string to human-readable attack vector.
    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    """
    if not vector:
        return "Unknown"
    try:
        parts = vector.split("/")
        # find part starting with 'AV:'
        for p in parts:
            if p.startswith("AV:"):
                code = p.split(":", 1)[1]
                mapping = {
                    "N": "Network",
                    "A": "Adjacent",
                    "L": "Local",
                    "P": "Physical",
                }
                return mapping.get(code, "Unknown")
    except Exception:
        pass
    return "Unknown"


@app.get("/api/export/attack-vector")
def export_attack_vector(limit: int = 5000):
    """
    Export attack-vector CSV:
    cve_id, publishedDate, cvss_v3_score, attack_vector, cvss_v3_vector
    """
    try:
        conn = get_conn()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id AS cve_id,
               publishedDate,
               cvss_v3_score,
               cvss_v3_vector
        FROM cves
        WHERE cvss_v3_vector IS NOT NULL
        ORDER BY publishedDate DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["cve_id", "publishedDate", "cvss_v3_score", "attack_vector", "cvss_v3_vector"])

    for r in rows:
        av = parse_attack_vector(r["cvss_v3_vector"])
        writer.writerow([r["cve_id"], r["publishedDate"], r["cvss_v3_score"], av, r["cvss_v3_vector"]])

    output.seek(0)
    headers = {
        "Content-Disposition": 'attachment; filename="attack_vector_export.csv"',
        "Content-Type": "text/csv",
    }
    return StreamingResponse(output, headers=headers, media_type="text/csv")




from collections import defaultdict  # at top with other imports
import csv

REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
SEVERITY_CSV_PATH = os.path.join(REPORTS_DIR, "severity_eval.csv")


@app.get("/api/model/severity-summary")
def model_severity_summary(limit: int = 200):
    """
    Read reports/severity_eval.csv and return:
    - table: sample of rows (CVE, CVSS bucket, model bucket, summary)
    - cvss_counts: counts of true_bucket_cvss
    - model_counts: counts of predicted_bucket_model
    """
    if not os.path.exists(SEVERITY_CSV_PATH):
        raise HTTPException(
            status_code=404,
            detail="severity_eval.csv not found. Run severity_eval.py first.",
        )

    table = []
    cvss_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}
    model_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0}

    with open(SEVERITY_CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            true_b = (row.get("true_bucket_cvss") or "unknown").lower()
            pred_b = (row.get("predicted_bucket_model") or "unknown").lower()

            if true_b not in cvss_counts:
                true_b = "unknown"
            if pred_b not in model_counts:
                pred_b = "unknown"

            cvss_counts[true_b] += 1
            model_counts[pred_b] += 1

            table.append(
                {
                    "id": row.get("cve_id"),
                    "cvss_bucket": true_b,
                    "model_bucket": pred_b,
                    "summary": (row.get("summary") or "")[:200],
                }
            )

    return {
        "table": table,
        "cvss_counts": cvss_counts,
        "model_counts": model_counts,
    }


@app.get("/api/model/severity-trend-csv")
def model_severity_trend_csv():
    """
    Compute model-predicted severity trend over time (year-month) from severity_eval.csv.
    Uses:
    - publishedDate
    - predicted_bucket_model
    """
    if not os.path.exists(SEVERITY_CSV_PATH):
        raise HTTPException(
            status_code=404,
            detail="severity_eval.csv not found. Run severity_eval.py first.",
        )

    buckets = defaultdict(lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})

    with open(SEVERITY_CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pub = row.get("publishedDate")
            pred = (row.get("predicted_bucket_model") or "").lower()
            if not pub:
                continue
            ym = pub[:7]  # "YYYY-MM"

            if pred not in ("low", "medium", "high", "critical"):
                continue
            buckets[ym][pred] += 1

    labels = sorted(buckets.keys())
    lows = [buckets[m]["low"] for m in labels]
    meds = [buckets[m]["medium"] for m in labels]
    highs = [buckets[m]["high"] for m in labels]
    crits = [buckets[m]["critical"] for m in labels]

    return {
        "labels": labels,
        "low": lows,
        "medium": meds,
        "high": highs,
        "critical": crits,
    }
