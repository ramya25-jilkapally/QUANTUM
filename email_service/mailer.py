import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================= SMTP CONFIG =================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# ⚠️ USE YOUR GMAIL ID
SENDER_EMAIL = "jilkapallyramya25@gmail.com"

# ⚠️ USE GMAIL APP PASSWORD (16 characters, no spaces)
SENDER_PASSWORD = "dnkjftsinhusymkm"


def send_email(to_email, subject, message):
    """
    Sends an email using Gmail SMTP with App Password.
    Returns True if successful, False otherwise.
    """

    try:
        print("📧 Sending email to:", to_email)

        # Create email
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(message, "plain"))

        # Connect to SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)

        # Send email
        server.send_message(msg)
        server.quit()

        print("✅ Email sent successfully")
        return True

    except Exception as e:
        print("❌ Email sending failed:", e)
        return False
