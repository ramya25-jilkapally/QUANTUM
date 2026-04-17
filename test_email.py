from email_service.mailer import send_email

result = send_email(
    "jilkapallyramya25@gmail.com",
    "QVault Email Test",
    "✅ This is a test email from QVault.\n\nIf you received this, email alerts are working correctly."
)

print("Email sent result:", result)
