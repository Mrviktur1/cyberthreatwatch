import requests
import streamlit as st
from pydantic import BaseModel

class MobileAlert(BaseModel):
    title: str
    message: str
    priority: str = "high"
    data: dict = None

class MobileNotifier:
    def __init__(self):
        self.api_key = st.secrets["PUSHOVER_API_KEY"]
        self.user_key = st.secrets["PUSHOVER_USER_KEY"]
    
    def send_critical_alert(self, message: str):
        """Send high-priority mobile alert"""
        alert = MobileAlert(
            title="🚨 Security Alert",
            message=message,
            priority="emergency",
            data={"sound": "persistent"}
        )
        self._send_push(alert)
    
    def send_security_update(self, message: str):
        """Standard security notification"""
        alert = MobileAlert(
            title="Security Update",
            message=message
        )
        self._send_push(alert)
    
    def _send_push(self, alert: MobileAlert):
        """Send via Pushover API"""
        requests.post(
            "https://api.pushover.net/1/messages.json",
            json={
                "token": self.api_key,
                "user": self.user_key,
                **alert.dict()
            }
        )