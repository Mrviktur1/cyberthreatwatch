import streamlit as st
from datetime import datetime, timedelta
from auth.auth_core import verify_password
from security.audit_logger import AuditLogger

class SecureAuthentication:
    def __init__(self):
        self.audit = AuditLogger()
        self.failed_attempts = {}
        
    def pre_login_checks(self, email: str) -> dict:
        """Security checks before login"""
        checks = {"allowed": True, "message": ""}
        
        if self._is_account_locked(email):
            checks.update({
                "allowed": False,
                "message": "Account locked. Try again later."
            })
            
        return checks
    
    def login(self, email: str, password: str):
        """Enhanced login with security checks"""
        try:
            user = verify_login(email, password)
            if user:
                self._reset_failed_attempts(email)
                return user
                
            self._record_failed_attempt(email)
            return None
            
        except Exception as e:
            self.audit.log_security_alert("LOGIN_ERROR", {"error": str(e)})
            return None
    
    def _verify_password(self, input_pw: str, stored_hash: str) -> bool:
        """Built-in password verification"""
        return verify_password(stored_hash, input_pw)
    
    def _is_account_locked(self, email: str) -> bool:
        """Check login attempt limits"""
        if email in self.failed_attempts:
            last_time, count = self.failed_attempts[email]
            if count > 5 and (datetime.now() - last_time) < timedelta(minutes=30):
                return True
        return False
    
    def _record_failed_attempt(self, email: str):
        """Track failed logins"""
        if email not in self.failed_attempts:
            self.failed_attempts[email] = (datetime.now(), 1)
        else:
            last_time, count = self.failed_attempts[email]
            self.failed_attempts[email] = (datetime.now(), count + 1)
        
        self.audit.log_event("LOGIN_ATTEMPT", 
            metadata={"email": email, "status": "failed"})
    
    def _reset_failed_attempts(self, email: str):
        """Clear failed attempts on success"""
        if email in self.failed_attempts:
            del self.failed_attempts[email]