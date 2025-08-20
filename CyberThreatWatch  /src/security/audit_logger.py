import streamlit as st
from supabase import create_client
from datetime import datetime, timedelta
import json

class AuditLogger:
    def __init__(self):
        self.client = create_client(
            st.secrets["SUPABASE_URL"],
            st.secrets["SUPABASE_KEY"]
        )
    
    def log_event(self, event_type: str, user_id: str = None, metadata: dict = None):
        """Log security events to database"""
        try:
            log_entry = {
                "event_type": event_type,
                "user_id": user_id,
                "ip_address": self._get_client_ip(),
                "user_agent": self._get_user_agent(),
                "metadata": json.dumps(metadata) if metadata else None,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.client.table('audit_logs').insert(log_entry).execute()
        except Exception as e:
            st.error(f"Failed to log event: {str(e)}")
    
    def get_logs(self, last_hours: int = 24, user_id: str = None):
        """Retrieve logs for display"""
        try:
            query = self.client.table('audit_logs') \
                .select('*') \
                .gte('timestamp', 
                    (datetime.utcnow() - timedelta(hours=last_hours)).isoformat())
            
            if user_id:
                query = query.eq('user_id', user_id)
                
            return query.order('timestamp', desc=True).execute().data
        except Exception as e:
            st.error(f"Failed to retrieve logs: {str(e)}")
            return []

    # Convenience methods
    def log_login(self, email: str, success: bool):
        self.log_event(
            "LOGIN_ATTEMPT",
            metadata={
                "email": email,
                "success": success,
                "client": self._get_client_info()
            }
        )
    
    def log_logout(self, email: str):
        self.log_event(
            "USER_LOGOUT",
            metadata={
                "email": email,
                "client": self._get_client_info()
            }
        )
    
    def log_security_alert(self, alert_type: str, details: dict):
        self.log_event(
            f"SECURITY_ALERT_{alert_type}",
            metadata=details
        )
    
    def _get_client_ip(self):
        """Get client IP from request headers"""
        try:
            from streamlit.web.server.websocket_headers import _get_websocket_headers
            headers = _get_websocket_headers()
            return headers.get("X-Forwarded-For", "127.0.0.1")
        except Exception:
            return "127.0.0.1"
    
    def _get_user_agent(self):
        """Get user agent"""
        try:
            return st.experimental_user_agent or "unknown"
        except Exception:
            return "unknown"
    
    def _get_client_info(self):
        return {
            "ip": self._get_client_ip(),
            "user_agent": self._get_user_agent(),
            "session": st.session_state.get('session_id')
        }