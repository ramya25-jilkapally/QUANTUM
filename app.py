import random
from crypto.key_wrap import wrap_key_with_password, unwrap_key_with_password
import shutil
from flask import Flask, render_template, request, send_file, session, redirect, url_for, flash
import os
import io
import sqlite3
from datetime import datetime

from qkd.bb84 import bb84_protocol
from crypto.aes_crypto import qkd_to_aes_key, encrypt_file, decrypt_file
from werkzeug.security import generate_password_hash, check_password_hash
from email_service.mailer import send_email
from sessions.session_manager import log_qkd_session, get_last_session_id

# ✅ AUDIT SYSTEM (ONLY SOURCE)
from audit.audit_logger import log_audit, get_audit_logs

# ================= APP =================
app = Flask(__name__)
app.secret_key = "qvault_secret_key"

print("🔥 QVault server started")

# ================= PATHS =================
# ================= PATHS =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CLOUD_A_PATH = os.path.join(BASE_DIR, "storage", "cloud_A", "encrypted_files")
CLOUD_B_PATH = os.path.join(BASE_DIR, "storage", "cloud_B", "encrypted_files")
LOG_PATH = os.path.join(BASE_DIR, "logs", "qber.log")
DB_PATH = os.path.join(BASE_DIR, "auth", "users.db")

os.makedirs(CLOUD_A_PATH, exist_ok=True)
os.makedirs(CLOUD_B_PATH, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# ================= FILE SIZE LIMIT =================
MIN_FILE_SIZE = 2 * 1024              # 2 KB
MAX_FILE_SIZE = 100 * 1024 * 1024     # 100 MB

# ================= DATABASE INIT =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            user TEXT,
            upload_time TEXT,
            qkd_session_id TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= AUTH HELPERS =================
def register_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, generate_password_hash(password))
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row and check_password_hash(row[0], password)

def generate_otp():
    return str(random.randint(100000, 999999))

# ================= ROUTES =================

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if register_user(request.form["email"], request.form["password"]):
            return redirect(url_for("login"))
        flash("Email already registered", "error")
    return render_template("register.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if authenticate_user(email, password):
            session["user"] = email

            send_email(
                email,
                "QVault Login Alert",
                f"Login successful at {datetime.now()}"
            )

            log_audit(email, "LOGIN", status="SUCCESS")
            return redirect(url_for("dashboard"))

        flash("Invalid login credentials", "error")

    return render_template("login.html")

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    log_audit(session.get("user"), "LOGOUT", status="SUCCESS")
    session.clear()
    return redirect(url_for("login"))

# ---------- UPLOAD ----------
@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")
    eve = request.form.get("eve") == "on"

    if not file or file.filename == "":
        flash("❌ No file selected", "error")
        return redirect(url_for("dashboard"))

    # -------- FILE SIZE CHECK --------
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
        flash("❌ File must be between 2 KB and 100 MB", "error")
        return redirect(url_for("dashboard"))

    # -------- QKD --------
    qkd_key, qber = bb84_protocol(eve=eve)

    session_id = log_qkd_session(
        session["user"],
        "UPLOAD",
        file.filename,
        qber
    )

    # -------- LOG QBER --------
    with open(LOG_PATH, "a") as log:
        log.write(
            f"{datetime.now()} | SESSION={session_id} | USER={session['user']} | ACTION=UPLOAD | QBER={qber}\n"
        )

    # -------- EVE DETECTED --------
    if qber > 0.11:
        flash(f"⚠️ Attack detected — Upload blocked (QBER={qber:.4f})", "error")
        return redirect(url_for("dashboard"))

    # -------- ENCRYPT --------
    aes_key = qkd_to_aes_key(qkd_key)
    encrypted_data = encrypt_file(file.read(), aes_key)

    path = os.path.join(CLOUD_A_PATH, file.filename)

    with open(path, "wb") as f:
        f.write(encrypted_data)

    with open(path + ".key", "wb") as k:
        k.write(aes_key)

    # -------- SAVE DB METADATA --------
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO files (filename, user, upload_time, qkd_session_id) VALUES (?, ?, ?, ?)",
        (
            file.filename,
            session["user"],
            datetime.now().strftime("%d-%b-%Y %I:%M %p"),
            session_id
        )
    )

    conn.commit()
    conn.close()

    # -------- STORE SUCCESS DATA --------
    session["upload_success"] = {
        "filename": file.filename,
        "qber": round(qber, 4),
        "session_id": session_id
    }

    return redirect(url_for("upload_success"))


# ---------- UPLOAD SUCCESS ----------
@app.route("/upload-success")
def upload_success():
    if "user" not in session:
        return redirect(url_for("login"))

    data = session.get("upload_success")

    if not data:
        flash("No recent upload found", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "upload_success.html",
        filename=data["filename"],
        qber=data["qber"],
        session_id=data["session_id"]
    )

# ---------- DOWNLOAD ----------
@app.route("/download", methods=["POST"])
def download():
    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form.get("filename")
    email = request.form.get("email")

    if not filename or not email:
        flash("Missing details", "error")
        return redirect(url_for("dashboard"))

    # -------- VERIFY EMAIL --------
    if email != session["user"]:
        flash("❌ Email verification failed", "error")
        log_audit(session["user"], "DOWNLOAD", filename, status="DENIED")
        return redirect(url_for("dashboard"))

    path = os.path.join(CLOUD_A_PATH, filename)
    key_path = path + ".key"

    if not os.path.exists(path) or not os.path.exists(key_path):
        flash("❌ File not found", "error")
        return redirect(url_for("dashboard"))

    # -------- SEND VERIFICATION EMAIL BEFORE DOWNLOAD --------
    send_email(
        session["user"],
        "QVault Download Verification",
        f"""
Your file download has been verified.

File Name: {filename}
Time: {datetime.now()}

If this was not you, contact administrator immediately.
"""
    )

    # -------- DECRYPT FILE --------
    with open(key_path, "rb") as k:
        aes_key = k.read()

    with open(path, "rb") as f:
        decrypted_data = decrypt_file(f.read(), aes_key)

    # -------- LOG SUCCESS --------
    log_audit(session["user"], "DOWNLOAD", filename, status="SUCCESS")

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )
# ---------- EMAIL SHARE ----------
# ---------- SHARE (EMAIL + CLOUD B COPY) ----------
@app.route("/share", methods=["POST"])
def share():

    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form.get("filename")
    receiver = request.form.get("receiver_email")
    share_password = request.form.get("share_password")

    # Validate inputs
    if not filename or not receiver or not share_password:
        flash("❌ Missing share details", "error")
        return redirect(url_for("dashboard"))

    # Save receiver email for OTP later
    session["share_receiver_email"] = receiver

    src_file = os.path.join(CLOUD_A_PATH, filename)
    src_key = src_file + ".key"

    if not os.path.exists(src_file):
        flash("❌ File not found in Cloud A", "error")
        return redirect(url_for("dashboard"))

    # Destination paths (Cloud B)
    dst_file = os.path.join(CLOUD_B_PATH, filename)
    dst_key = dst_file + ".key"

    try:
        # Copy encrypted file
        with open(src_file, "rb") as f:
            with open(dst_file, "wb") as o:
                o.write(f.read())

        # Wrap AES key with password
        if os.path.exists(src_key):

            with open(src_key, "rb") as kf:
                aes_key = kf.read()

            wrapped_key = wrap_key_with_password(aes_key, share_password)

            with open(dst_key, "wb") as ok:
                ok.write(wrapped_key)

    except Exception as e:
        print("Share error:", e)
        flash("❌ Failed to copy file to Cloud B", "error")
        return redirect(url_for("dashboard"))

    # Get last QKD session ID
    try:
        session_id = get_last_session_id()
    except:
        session_id = "N/A"

    # Create secure share link
    share_link = f"http://localhost:5000/shared-file/{filename}?email={receiver}"

    # Send email notification
    try:
        send_email(
            receiver,
            "QVault – Secure File Shared",
            f"""
A secure encrypted file has been shared with you.

File Name: {filename}
Shared By: {session['user']}
QKD Session ID: {session_id}

Open the file using this secure link:
{share_link}

You will need the share password to open the file.
"""
        )
    except Exception as e:
        print("Email error:", e)

    # Audit log
    try:
        log_audit(session["user"], "SHARE", filename, status="SUCCESS")
    except:
        pass

    flash("📧 File shared successfully + copied to Cloud B", "success")

    return redirect(url_for("dashboard"))

# ---------- DELETE ----------
@app.route("/delete", methods=["POST"])
def delete_file():
    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form["filename"]

    for p in [filename, filename + ".key"]:
        fp = os.path.join(CLOUD_A_PATH, p)
        if os.path.exists(fp):
            os.remove(fp)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM files WHERE filename=? AND user=?",
        (filename, session["user"])
    )
    conn.commit()
    conn.close()

    log_audit(session["user"], "DELETE", filename, status="SUCCESS")
    flash("🗑 File deleted successfully", "success")
    return redirect(url_for("dashboard"))

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]

    # ---- Get encrypted files from DB ----
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT filename, upload_time, qkd_session_id
        FROM files
        WHERE user=?
        ORDER BY id DESC
    """, (user,))
    encrypted_files = cur.fetchall()

    conn.close()

    # ---- Shared files from Cloud B folder ----
    if os.path.exists(CLOUD_B_PATH):
        shared_files = os.listdir(CLOUD_B_PATH)
    else:
        shared_files = []

    # ---- Safe counts ----
    cloud_a_count = len(encrypted_files)
    cloud_b_count = len(shared_files)
    total_files = cloud_a_count + cloud_b_count

    # ---- Last QKD session ----
    try:
        last_session = get_last_session_id()
    except:
        last_session = "N/A"

    # ---- Render clean dashboard ----
    return render_template(
        "dashboard.html",
        user=user,
        encrypted_files=encrypted_files,
        shared_files=shared_files,
        cloud_a_count=cloud_a_count,
        cloud_b_count=cloud_b_count,
        total_files=total_files,
        last_session_id=last_session
    )
    
# ---------- FINAL RESULTS ----------
@app.route("/final-results")
def final_results():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ✅ count real uploads only
    cur.execute("SELECT COUNT(*) FROM files WHERE user=?", (user,))
    encrypted_count = cur.fetchone()[0]

    conn.close()

    shared_count = 0  # email share not stored as files
    total_files = encrypted_count + shared_count

    # -------- QBER --------
    last_qber = None

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = [l for l in f if "QBER=" in l]
            if lines:
                try:
                    last_qber = float(lines[-1].split("QBER=")[1].strip())
                except:
                    last_qber = None

    # -------- STATUS --------
    if last_qber is not None and last_qber > 0.11:
        status = "⚠️ Eavesdropping Detected"
        color = "red"
    elif last_qber is not None:
        status = "✅ Secure Communication"
        color = "green"
    else:
        status = "ℹ️ No QKD Upload Session"
        color = "gray"

    # -------- SESSION ID --------
    last_session_id = get_last_session_id()
    if not last_session_id:
        last_session_id = "N/A"

    return render_template(
        "final_results.html",
        user=user,
        encrypted_count=encrypted_count,
        shared_count=shared_count,
        total_files=total_files,
        last_qber=last_qber if last_qber is not None else "N/A",
        last_session_id=last_session_id,
        status=status,
        color=color
    )

# ---------- AUDIT LOGS ----------
@app.route("/audit-logs")
def audit_logs():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "audit_logs.html",
        logs=get_audit_logs(session["user"]),
        user=session["user"]
    )

# ---------- DOWNLOAD VERIFY PAGE ----------
@app.route("/download-verify", methods=["POST"])
def download_verify():

    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form.get("filename")

    if not filename:
        flash("❌ No file selected", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "download_verify.html",
        filename=filename,
        user=session["user"]
    )

# ---------- ATTACK DETECTION ----------
@app.route("/attack-detection")
def attack_detection():

    if "user" not in session:
        return redirect(url_for("login"))

    last_qber = None

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = [l for l in f if "QBER=" in l]
            if lines:
                try:
                    last_qber = float(lines[-1].split("QBER=")[1])
                except:
                    last_qber = None

    if last_qber is None:
        status = "No QKD sessions yet"
    elif last_qber > 0.11:
        status = "⚠️ Eavesdropping Detected"
    else:
        status = "✅ Secure Communication"

    return render_template(
        "attack_detection.html",
        user=session["user"],
        last_qber=last_qber,
        status=status
    )

@app.route("/delete-shared", methods=["POST"])
def delete_shared():
    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form.get("filename")

    if not filename:
        flash("❌ No filename provided", "error")
        return redirect(url_for("dashboard"))

    file_path = os.path.join(CLOUD_B_PATH, filename)
    key_path = file_path + ".key"

    deleted = False

    if os.path.exists(file_path):
        os.remove(file_path)
        deleted = True

    if os.path.exists(key_path):
        os.remove(key_path)

    if deleted:
        flash(f"🗑 Shared file '{filename}' deleted from Cloud B", "success")
    else:
        flash("❌ Shared file not found", "error")

    return redirect(url_for("dashboard"))

@app.route("/shared-download", methods=["POST"])
def shared_download():

    if "user" not in session:
        return redirect(url_for("login"))

    filename = request.form.get("filename")
    password = request.form.get("password")

    path = os.path.join(CLOUD_B_PATH, filename)
    key_path = path + ".key"

    if not os.path.exists(path):
        flash("File not found", "error")
        return redirect(url_for("dashboard"))

    try:

        with open(key_path, "rb") as k:
            wrapped_key = k.read()

        aes_key = unwrap_key_with_password(wrapped_key, password)

    except:
        flash("❌ Incorrect password", "error")
        return redirect(url_for("dashboard"))

    with open(path, "rb") as f:
        decrypted = decrypt_file(f.read(), aes_key)

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=filename
    )

from urllib.parse import unquote

@app.route("/shared-file/<path:filename>")
def shared_file_page(filename):

    filename = unquote(filename)
    receiver_email = request.args.get("email")

    path = os.path.join(CLOUD_B_PATH, filename)

    print("Shared file request:", path)

    if not os.path.isfile(path):
        return "Shared file not found"

    return render_template(
        "shared_file_password.html",
        filename=filename,
        receiver_email=receiver_email
    )
# 
@app.route("/open-shared-file", methods=["POST"])
def open_shared_file():

    filename = request.form.get("filename")
    password = request.form.get("password")

    if not filename:
        return "Filename missing"

    path = os.path.join(CLOUD_B_PATH, filename)
    key_path = path + ".key"

    print("Looking for file:", path)   # Debug line

    # Check if encrypted file exists
    if not os.path.isfile(path):
        return "File not found"

    # Check if key file exists
    if not os.path.isfile(key_path):
        return "Encryption key not found"

    try:
        with open(key_path, "rb") as k:
            wrapped_key = k.read()

        aes_key = unwrap_key_with_password(wrapped_key, password)

    except Exception as e:
        print("Password error:", e)
        return "Incorrect password"

    # Generate OTP
    otp = str(random.randint(100000, 999999))

    # Store details in session
    session["share_otp"] = otp
    session["otp_filename"] = filename
    session["otp_aes_key"] = aes_key.hex()

    # Get receiver email
    receiver_email = request.form.get("receiver_email")

    if not receiver_email:
        return "Receiver email not found"

    print("Sending OTP to:", receiver_email)   # Debug line

    # Send OTP email
    send_email(
        receiver_email,
        "QVault File Access OTP",
        f"""
Your OTP for opening the shared file is:

OTP: {otp}

This OTP is valid for one verification.
"""
    )

    return render_template("otp_verify.html")
# 
@app.route("/verify-share-otp", methods=["POST"])
def verify_share_otp():

    entered_otp = request.form.get("otp")

    if entered_otp != session.get("share_otp"):
        return "Invalid OTP"

    filename = session.get("otp_filename")
    aes_key = bytes.fromhex(session.get("otp_aes_key"))

    path = os.path.join(CLOUD_B_PATH, filename)

    if not os.path.exists(path):
        return "File not found"

    with open(path, "rb") as f:
        decrypted_data = decrypt_file(f.read(), aes_key)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )
# ================= MAIN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True) 