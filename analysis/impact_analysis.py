# analysis/impact_analysis.py
import os
import sqlite3
import pandas as pd

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(THIS_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")

# simple keyword-based impact categories
KEYWORDS = {
    "privilege_escalation": ["privilege escalation", "elevate privileges"],
    "rce": ["remote code execution", "code execution", "rce"],
    "dos": ["denial of service", "denial-of-service", "dos attack"],
    "info_leak": ["information disclosure", "info leak", "data leakage"],
}

def classify_impact(text: str):
    if not text:
        return "unknown"
    t = text.lower()
    for label, keys in KEYWORDS.items():
        for k in keys:
            if k in t:
                return label
    return "other"

def main():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"DB not found at {DB_PATH}. Run parse_and_store.py first.")
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT id, summary FROM cves", conn)
    conn.close()

    df["impact_category"] = df["summary"].apply(classify_impact)

    print("=== Impact Category Counts ===")
    print(df["impact_category"].value_counts())

    # optional: save for report
    out_csv = os.path.join(THIS_DIR, "impact_categories.csv")
    df.to_csv(out_csv, index=False)
    print(f"\nSaved detailed impact classification to {out_csv}")

if __name__ == "__main__":
    main()
