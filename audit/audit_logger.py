import sqlite3
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "auth", "users.db")


def log_audit(user, action, filename=None,
              target=None, session_id=None,
              qber=None, status="SUCCESS"):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO audit_logs
        (user, action, filename, target, qkd_session_id, qber, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user,
        action,
        filename,
        target,
        session_id,
        qber,
        status,
        datetime.now().strftime("%d-%b-%Y %I:%M %p")
    ))

    conn.commit()
    conn.close()


def get_audit_logs(user=None):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if user:
        cur.execute("""
            SELECT user, action, filename, target,
                   qkd_session_id, qber, status, timestamp
            FROM audit_logs
            WHERE user=?
            ORDER BY id DESC
        """, (user,))
    else:
        cur.execute("""
            SELECT user, action, filename, target,
                   qkd_session_id, qber, status, timestamp
            FROM audit_logs
            ORDER BY id DESC
        """)

    rows = cur.fetchall()
    conn.close()
    return rows
