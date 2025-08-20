# src/alerts/slack_alert.py
import requests
import json

def send_slack_alert(message, webhook_url):
    payload = {"text": f"🚨 CyberThreatWatch Alert: {message}"}
    requests.post(webhook_url, json=payload)