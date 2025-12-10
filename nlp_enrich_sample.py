# nlp_enrich_sample.py
import sqlite3
import spacy
nlp = spacy.load("en_core_web_sm")
conn = sqlite3.connect("data/db/cves.db")
cur = conn.cursor()
cur.execute("SELECT id, summary FROM cves LIMIT 20")
rows = cur.fetchall()
for cve_id, summary in rows:
    if not summary:
        continue
    doc = nlp(summary)
    ents = [(e.text, e.label_) for e in doc.ents]
    print(cve_id, "| ents:", ents[:8])
conn.close()
