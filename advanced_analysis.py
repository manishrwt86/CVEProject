# advanced_analysis.py
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

# Compute project root from this file location
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")

# Folder for report PNGs
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Folder for web UI PNGs (served by FastAPI)
SERVER_STATIC_DIR = os.path.join(PROJECT_ROOT, "server", "static")
os.makedirs(SERVER_STATIC_DIR, exist_ok=True)

def load_cves():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        """
        SELECT id, summary, publishedDate AS published, cvss_v3_score
        FROM cves
        WHERE publishedDate IS NOT NULL
        """,
        conn,
    )
    conn.close()
    return df

def severity_bucket(score):
    if score is None:
        return "unknown"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s < 4.0:
        return "low"
    elif s < 7.0:
        return "medium"
    elif s < 9.0:
        return "high"
    else:
        return "critical"

def save_both(fig, filename):
    """
    Save the same figure into:
      - reports/<filename>
      - server/static/<filename>
    """
    report_path = os.path.join(REPORTS_DIR, filename)
    static_path = os.path.join(SERVER_STATIC_DIR, filename)
    fig.savefig(report_path, bbox_inches="tight")
    fig.savefig(static_path, bbox_inches="tight")
    print("Saved:", report_path)
    print("Saved:", static_path)

def main():
    print("Using DB:", DB_PATH)
    print("Reports dir:", REPORTS_DIR)
    print("Static dir:", SERVER_STATIC_DIR)

    df = load_cves()
    df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    df = df.dropna(subset=["published"])
    df["year_month"] = df["published"].dt.to_period("M").astype(str)

    # === 1) Monthly CVE counts ===
    monthly = (
        df.groupby("year_month")["id"]
        .count()
        .reset_index(name="cve_count")
        .sort_values("year_month")
    )

    print("=== CVE count per month (last 12 rows) ===")
    print(monthly.tail(12))

    fig1 = plt.figure(figsize=(10, 4))
    ax1 = fig1.add_subplot(111)
    ax1.plot(monthly["year_month"], monthly["cve_count"], marker="o")
    ax1.set_title("CVE count per month")
    ax1.set_xlabel("Year-Month")
    ax1.set_ylabel("Number of CVEs")
    plt.xticks(rotation=90)
    plt.tight_layout()
    save_both(fig1, "cve_monthly_counts.png")
    plt.close(fig1)

    # === 2) Severity trend ===
    df["severity_bucket"] = df["cvss_v3_score"].apply(severity_bucket)

    sev = (
        df.groupby(["year_month", "severity_bucket"])["id"]
        .count()
        .reset_index(name="count")
        .sort_values(["year_month", "severity_bucket"])
    )

    print("\n=== Severity trend (last 24 rows) ===")
    print(sev.tail(24))

    sev_pivot = sev.pivot(
        index="year_month", columns="severity_bucket", values="count"
    ).fillna(0)
    sev_pivot = sev_pivot.sort_index()

    fig2 = plt.figure(figsize=(10, 4))
    ax2 = fig2.add_subplot(111)
    for col in sev_pivot.columns:
        ax2.plot(sev_pivot.index, sev_pivot[col], marker="o", label=col)
    ax2.set_title("CVE severity trend by month")
    ax2.set_xlabel("Year-Month")
    ax2.set_ylabel("Number of CVEs")
    ax2.legend()
    plt.xticks(rotation=90)
    plt.tight_layout()
    save_both(fig2, "cve_severity_trend.png")
    plt.close(fig2)

    # === 3) Top critical vendors ===
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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
    conn.close()

    print("\n=== Top vendors by number of critical CVEs (cvss >= 9.0) ===")
    for vendor, cnt in rows:
        print(f"{vendor:20s}  {cnt}")

if __name__ == "__main__":
    main()
