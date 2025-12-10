# severity_eval.py
"""
Advanced analysis:
Compare model-predicted severity (from text) with CVSS v3 severity buckets.

Output:
- prints a confusion-style table
- saves detailed rows to reports/severity_eval.csv
"""

import os
import sqlite3
import csv
from collections import Counter

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

LABELS = ["low", "medium", "high", "critical"]
MODEL_NAME = "CIRCL/vulnerability-severity-classification-distilbert-base-uncased"

def cvss_to_bucket(score):
    """
    Map CVSS v3 baseScore to severity bucket.
    """
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

def load_cves(limit=200):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, summary, cvss_v3_score, publishedDate
        FROM cves
        WHERE summary IS NOT NULL AND summary != ''
        ORDER BY publishedDate DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows

def main():
    print("DB:", DB_PATH)
    print("Reports dir:", REPORTS_DIR)
    print("Loading model:", MODEL_NAME)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    rows = load_cves(limit=200)
    if not rows:
        print("No CVEs found. Run parse_and_store.py first.")
        return

    results = []
    confusion = Counter()

    for cve_id, summary, cvss_score, published in rows:
        text = summary if summary else ""
        true_bucket = cvss_to_bucket(cvss_score)

        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=256,
        )
        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]
        pred_idx = int(torch.argmax(probs))
        pred_label = LABELS[pred_idx]

        confusion[(true_bucket, pred_label)] += 1

        results.append(
            {
                "cve_id": cve_id,
                "publishedDate": published,
                "summary": text,
                "cvss_v3_score": cvss_score,
                "true_bucket_cvss": true_bucket,
                "predicted_bucket_model": pred_label,
                "prob_low": float(probs[0]),
                "prob_medium": float(probs[1]),
                "prob_high": float(probs[2]),
                "prob_critical": float(probs[3]),
            }
        )

    # Save CSV
    out_path = os.path.join(REPORTS_DIR, "severity_eval.csv")
    fieldnames = [
        "cve_id",
        "publishedDate",
        "cvss_v3_score",
        "true_bucket_cvss",
        "predicted_bucket_model",
        "prob_low",
        "prob_medium",
        "prob_high",
        "prob_critical",
        "summary",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"\nSaved detailed results to: {out_path}\n")

    # Print confusion-style summary
    buckets = ["unknown", "low", "medium", "high", "critical"]
    print("Confusion table (rows = true CVSS bucket, cols = model prediction):")
    header = ["true\\pred"] + buckets
    print("\t".join(header))
    for tb in buckets:
        row_counts = []
        for pb in buckets:
            row_counts.append(str(confusion.get((tb, pb), 0)))
        print("\t".join([tb] + row_counts))

if __name__ == "__main__":
    main()
