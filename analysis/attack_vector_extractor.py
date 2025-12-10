# analysis/attack_vector_extractor.py
import os
import sqlite3
import pandas as pd
import re

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(THIS_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")

PATTERNS = {
    "network": r"\b(network|remote|over the network)\b",
    "local": r"\b(local user|locally|local access)\b",
    "physical": r"\b(physical access)\b",
    "adjacent": r"\b(adjacent network|same subnet)\b",
}

def extract_vector(text: str):
    if not text:
        return "unknown"
    t = text.lower()
    for label, pattern in PATTERNS.items():
        if re.search(pattern, t):
            return label
    return "unknown"

def main():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"DB not found at {DB_PATH}. Run parse_and_store.py first.")
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT id, summary FROM cves", conn)
    conn.close()

    df["attack_vector"] = df["summary"].apply(extract_vector)

    print("=== Attack Vector Distribution ===")
    print(df["attack_vector"].value_counts())

    # optional: save as CSV
    out_csv = os.path.join(THIS_DIR, "attack_vectors.csv")
    df.to_csv(out_csv, index=False)
    print(f"\nSaved detailed attack vector labels to {out_csv}")

if __name__ == "__main__":
    main()
