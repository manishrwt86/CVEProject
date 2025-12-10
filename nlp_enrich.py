# nlp_enrich.py
import spacy, json, sqlite3

nlp = spacy.load("en_core_web_sm")

def extract_from_json_blob(json_blob):
    item = json.loads(json_blob)
    # config parsing
    configs = item.get("configurations", {}).get("nodes", [])
    cpes = []
    for n in configs:
        for m in n.get("cpeMatch", []):
            cpes.append(m.get("criteria"))
    # description NER
    cve = item.get("cve", {})
    descs = cve.get("descriptions", [])
    text = ""
    for d in descs:
        if d.get("lang") == "en":
            text = d.get("value")
    ents = []
    if text:
        doc = nlp(text)
        for e in doc.ents:
            ents.append((e.text, e.label_))
    return {"cpes": cpes, "ents": ents}

def enrich_all(limit=100):
    conn = sqlite3.connect("data/db/cves.db")
    cur = conn.cursor()
    cur.execute("SELECT id, json_blob FROM cves LIMIT ?", (limit,))
    rows = cur.fetchall()
    for id_, blob in rows:
        res = extract_from_json_blob(blob)
        print(id_, "->", len(res["cpes"]), "cpes;", "ents sample:", res["ents"][:5])
    conn.close()

if __name__ == "__main__":
    enrich_all()
