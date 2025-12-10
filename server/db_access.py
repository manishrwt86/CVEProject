# server/db_access.py
import os
import sqlite3

# Compute project root (server/ -> project root)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("CVE_DB_PATH", os.path.join(PROJECT_ROOT, "data", "db", "cves.db"))

def connect():
    """
    Return a sqlite3 connection to the project's CVE DB.
    Raises FileNotFoundError if the DB doesn't exist.
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError("DB not found. Run parse_and_store.py first to create data/db/cves.db")
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
