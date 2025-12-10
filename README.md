## Project 2 — CVE Database + NLP

1. Create venv:
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
2. Install:
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
3. Fetch CVEs:
   python fetch_nvd.py
4. Parse & store:
   python parse_and_store.py
5. Query DB:
   sqlite3 data\db\cves.db
6. Run sample NLP:
   python nlp_enrich_sample.py

# Project 2 – CVE Database + NLP + FastAPI UI

**Student:** Adnan Akhtar (LCS2022001), Asitiva shrivasta (LCS2022004) ,Manish Rawat (LCS2022028) , Manjeet Kumar(LCS2022029)  
**Course:** NLP Lab – Project 2

## 1. Objective

The goal of this project is to build an automated pipeline that:

1. Downloads CVE vulnerability data from the official NVD API.
2. Parses and normalizes the JSON into a structured database (SQLite).
3. Extracts affected products using CPEs and basic NLP on descriptions.
4. Exposes the data through a small FastAPI web API and a browser UI.

This makes vulnerability data **searchable, filterable and ready for further NLP / ML**.

---

## 2. Project structure

```text
CVE-NLP/
├─ data/
│  ├─ db/           # SQLite database: cves.db
│  └─ raw/          # Raw NVD JSON response chunks
├─ server/          # FastAPI API + UI
│  ├─ main.py
│  ├─ db_access.py
│  ├─ templates/index.html
│  └─ static/app.js
├─ fetch_nvd.py
├─ parse_and_store.py
├─ nlp_enrich_sample.py
├─ advanced_analysis.py
├─ severity_model_demo.py
├─ severity_eval.py
└─ requirements.txt

```

## 2. Example Queries

-- how many CVEs
SELECT COUNT(\*) FROM cves;

-- sample rows
SELECT id, publishedDate, cvss_v3_score, substr(summary,1,80) AS summary
FROM cves
ORDER BY publishedDate DESC
LIMIT 10;

-- top vendors by number of CVEs
SELECT vendor, COUNT(DISTINCT cve_id) AS cves
FROM cpe_map
WHERE vendor IS NOT NULL
GROUP BY vendor
ORDER BY cves DESC
LIMIT 15;
