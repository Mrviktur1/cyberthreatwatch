from datetime import datetime, timedelta
import streamlit as st
from .audit_logger import AuditLogger

class ThreatDetector:
    def __init__(self):
        self.audit = AuditLogger()
        self.rules = {
            "brute_force": {
                "threshold": 5,
                "timeframe": timedelta(minutes=30)
            },
            "geolocation_impossible": {
                "allowed_countries": ["US", "CA", "GB"]  # ISO codes
            }
        }
    
    def analyze_event(self, event_type: str, metadata: dict):
        """Run all detection rules"""
        if event_type == "LOGIN_FAILED":
            self._check_brute_force(metadata['email'])
        
        if event_type == "LOGIN_SUCCESS":
            self._check_impossible_travel(metadata)
    
    def _check_brute_force(self, email: str):
        """Detect rapid failed attempts"""
        recent_failures = self.audit.get_logs(
            event_type="LOGIN_FAILED",
            user_id=email,
            last_hours=0.5  # 30 minutes
        )
        
        if len(recent_failures) >= self.rules["brute_force"]["threshold"]:
            self.audit.log_security_alert("BRUTE_FORCE_ATTEMPT", {
                "email": email,
                "attempts": len(recent_failures)
            })
            # Auto-block the IP
            self._block_ip(recent_failures[0]['ip_address'])
    
    def _check_impossible_travel(self, metadata: dict):
        """Detect logins from distant locations"""
        # Implement with GeoIP lookup
        pass
    
    def _block_ip(self, ip: str):
        """Block IP at firewall level"""
        # Implementation depends on your infrastructure
        pass