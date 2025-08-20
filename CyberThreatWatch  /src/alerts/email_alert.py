# src/alerts/email_alert.py
import smtplib
from email.mime.text import MIMEText

def send_alert(subject, body, config):
    msg = MIMEText(body)
    msg["Subject"] = f"[CyberThreatWatch] {subject}"
    msg["From"] = config["sender_email"]
    msg["To"] = config["receiver_email"]
    
    with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
        server.starttls()
        server.login(config["sender_email"], config["sender_password"])
        server.send_message(msg)