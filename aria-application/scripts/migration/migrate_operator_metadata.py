#!/usr/bin/env python3
"""Add metadata_json column to operator_messages table (SQLite)."""
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "investigations.db"

if not DB_PATH.exists():
    print(f"Database not found at {DB_PATH}")
    sys.exit(1)

conn = sqlite3.connect(str(DB_PATH))
cursor = conn.cursor()

# Check if column already exists
cursor.execute("PRAGMA table_info(operator_messages)")
columns = {row[1] for row in cursor.fetchall()}

if "metadata_json" in columns:
    print("Column metadata_json already exists.")
else:
    cursor.execute("ALTER TABLE operator_messages ADD COLUMN metadata_json TEXT")
    conn.commit()
    print("Added metadata_json column to operator_messages.")

conn.close()
