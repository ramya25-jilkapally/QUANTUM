import os
import uuid
from datetime import datetime

# ✅ ALWAYS POINT TO PROJECT ROOT
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
SESSION_LOG_FILE = os.path.join(SESSIONS_DIR, "qkd_sessions.log")

os.makedirs(SESSIONS_DIR, exist_ok=True)

# Ensure log file exists
if not os.path.exists(SESSION_LOG_FILE):
    open(SESSION_LOG_FILE, "w").close()


def generate_session_id():
    return f"QKD-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:4]}"


def log_qkd_session(user, operation, filename, qber):
    session_id = generate_session_id()

    with open(SESSION_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.now()} | "
            f"SESSION={session_id} | "
            f"USER={user} | "
            f"OPERATION={operation} | "
            f"FILE={filename} | "
            f"QBER={qber:.4f}\n"
        )

    print("🆔 SESSION LOGGED:", session_id)
    return session_id


def get_last_session_id():
    if not os.path.exists(SESSION_LOG_FILE):
        return "N/A"

    with open(SESSION_LOG_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        return "N/A"

    last_line = lines[-1]

    if "SESSION=" in last_line:
        return last_line.split("SESSION=")[1].split(" |")[0]

    return "N/A"
