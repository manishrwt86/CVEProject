# severity_model_demo.py
"""
Quick demo: use a pre-trained transformer model to predict severity from CVE summaries.

Model: CIRCL/vulnerability-severity-classification-distilbert-base-uncased
Labels: [low, medium, high, critical]
"""

import os
import sqlite3
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# project root based on this file location
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PROJECT_ROOT, "data", "db", "cves.db")

LABELS = ["low", "medium", "high", "critical"]
MODEL_NAME = "CIRCL/vulnerability-severity-classification-distilbert-base-uncased"

def load_cves(n=10):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # take a few recent CVEs that have non-empty summaries
    cur.execute(
        """
        SELECT id, summary
        FROM cves
        WHERE summary IS NOT NULL AND summary != ''
        ORDER BY publishedDate DESC
        LIMIT ?
        """,
        (n,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows

def main():
    print("Loading model:", MODEL_NAME)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    rows = load_cves(n=10)
    if not rows:
        print("No CVEs found in DB. Run parse_and_store.py first.")
        return

    for cve_id, summary in rows:
        text = summary if summary else ""
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
        prob_list = probs.tolist()

        print("=" * 60)
        print("CVE:", cve_id)
        print("Summary:", text[:200].replace("\n", " "), "..." if len(text) > 200 else "")
        print("Predicted severity:", pred_label)
        print("Raw probabilities [low, medium, high, critical]:")
        print([round(p, 4) for p in prob_list])

if __name__ == "__main__":
    main()
