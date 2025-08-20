import smtplib
from email.mime.text import MIMEText
import streamlit as st
from datetime import datetime

class SecurityNotifier:
    def __init__(self):
        self.smtp_server = st.secrets["SMTP_SERVER"]
        self.smtp_port = st.secrets["SMTP_PORT"]
        self.sender_email = st.secrets["SMTP_USER"]
        self.smtp_password = st.secrets["SMTP_PASSWORD"]
    
    def send_security_alert(self, recipient: str, alert_type: str, context: dict = None):
        """Send templated security alerts"""
        templates = {
            "login_new_device": """
            New login detected:
            - Time: {time}
            - IP: {ip}
            - Device: {device}
            """,
            "password_changed": """
            Your password was changed:
            - Time: {time}
            - IP: {ip}
            """,
            "mfa_enabled": """
            MFA was enabled on your account
            """
        }
        
        message = templates.get(alert_type, "").format(
            time=datetime.now().strftime("%Y-%m-%d %H:%M"),
            ip=context.get('ip', 'Unknown'),
            device=context.get('device', 'Unknown')
        )
        
        msg = MIMEText(message)
        msg['Subject'] = f"Security Alert: {alert_type.replace('_', ' ').title()}"
        msg['From'] = self.sender_email
        msg['To'] = recipient
        
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.smtp_password)
            server.send_message(msg)

    def send_verification_email(self, recipient: str, token: str):
        """Send email verification link"""
        verification_url = f"{st.secrets['APP_URL']}/verify?token={token}"
        body = f"""
        Please verify your email by clicking:
        {verification_url}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = "Verify Your Email"
        msg['From'] = self.sender_email
        msg['To'] = recipient
        
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.smtp_password)
            server.send_message(msg)