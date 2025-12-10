FastAPI CVE Browser

1. Ensure your parsed DB exists at `data/db/cves.db` (from parse_and_store.py). If your repo root is different, update the DB_PATH in server/main.py accordingly.

2. Create and activate a venv, then install deps:
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1 # PowerShell on Windows
   pip install -r server/requirements.txt

3. Run the app:
   uvicorn server.main:app --reload --port 8000

4. Open http://127.0.0.1:8000 in the browser to use the UI.

API endpoints:

- GET /api/health
- GET /api/recent?limit=50
- GET /api/cve/{CVE-ID}
- GET /api/search?vendor=...&product=...&limit=50
- GET /api/top-products?limit=20

Notes:

- If your DB path differs, edit server/main.py DB_PATH.
- This is a simple demonstrator; for production wrap with proper logging, auth, and deployment.
