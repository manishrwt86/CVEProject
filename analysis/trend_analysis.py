# analysis/trend_analysis.py
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

# locate DB: project_root/data/db/cves.db
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(THIS_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")

def load_db():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"DB not found at {DB_PATH}. Run parse_and_store.py first.")
    conn = sqlite3.connect(DB_PATH)
    # get both publishedDate and lastModifiedDate
    df = pd.read_sql_query(
        "SELECT id, publishedDate, lastModifiedDate, cvss_v3_score FROM cves",
        conn
    )
    conn.close()
    return df

def main():
    df = load_db()

    # build a unified date column: use publishedDate, else lastModifiedDate
    df["date_raw"] = df["publishedDate"].fillna(df["lastModifiedDate"])
    df["date"] = pd.to_datetime(df["date_raw"], errors="coerce")

    # drop rows where we still don't have a valid date
    df = df.dropna(subset=["date"])
    if df.empty:
        print("No valid dates found in cves table (publishedDate/lastModifiedDate are empty).")
        print("Trend plots skipped. Other analyses still valid.")
        return

    df["month"] = df["date"].dt.to_period("M")

    monthly_counts = df.groupby("month").size()
    monthly_high = df[df["cvss_v3_score"] >= 7].groupby("month").size()

    print("=== Monthly CVE Count (last 10) ===")
    print(monthly_counts.tail(10))

    print("\n=== High Severity CVEs (last 10 months) ===")
    print(monthly_high.tail(10))

    # Only plot if we have > 0 points
    if not monthly_counts.empty:
        plt.figure()
        monthly_counts.sort_index().plot(kind="line", title="CVE Trend Over Time")
        plt.xlabel("Month")
        plt.ylabel("Number of CVEs")
        plt.tight_layout()
        plt.show()
    else:
        print("No monthly counts to plot for overall CVEs.")

    if not monthly_high.empty:
        plt.figure()
        monthly_high.sort_index().plot(kind="line", title="High Severity CVEs (CVSS ≥ 7)")
        plt.xlabel("Month")
        plt.ylabel("Number of High Severity CVEs")
        plt.tight_layout()
        plt.show()
    else:
        print("No monthly counts to plot for high severity CVEs.")

if __name__ == "__main__":
    main()
