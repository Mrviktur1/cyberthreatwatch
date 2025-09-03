import streamlit as st
import pandas as pd
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class AlertsPanel:
    def __init__(self, supabase=None, otx=None):
        self.supabase = supabase
        self.otx = otx

    def fetch_supabase_alerts(self, user_id: str = None) -> List[Dict]:
        """Fetch alerts from Supabase, filtered by user if provided"""
        try:
            if self.supabase:
                query = self.supabase.table("alerts").select("*")
                if user_id:
                    query = query.eq("created_by", user_id)
                response = query.execute()
                if response.data:
                    return response.data
            return []
        except Exception as e:
            logger.error(f"Supabase fetch error: {e}")
            return []

    def insert_alert(self, alert: Dict, user_id: str):
        """Insert a new alert tied to the logged-in user"""
        try:
            if self.supabase:
                alert["created_by"] = user_id
                response = self.supabase.table("alerts").insert(alert).execute()
                if response.data:
                    return response.data
            return None
        except Exception as e:
            logger.error(f"Supabase insert error: {e}")
            return None

    def fetch_otx_iocs(self, query: str) -> List[Dict]:
        """Search OTX for indicators of compromise"""
        try:
            if self.otx:
                results = self.otx.search_pulses(query)
                return [{"pulse_id": r["id"], "name": r["name"]}
                        for r in results.get("results", [])]
            return []
        except Exception as e:
            logger.error(f"OTX search error: {e}")
            return []

    def render(self, alerts_data: List[Dict]):
        """Render alerts table and controls"""
        st.subheader("🚨 Active Alerts")

        if alerts_data:
            df = pd.DataFrame(alerts_data)
            st.dataframe(df)
        else:
            st.info("No alerts found for this user.")

        # Demo insert button (remove later in production)
        if "user" in st.session_state:
            if st.button("➕ Insert Test Alert"):
                new_alert = {
                    "severity": "High",
                    "type": "Test Injection",
                    "source_ip": "10.0.0.123",
                    "description": "Manual test alert"
                }
                self.insert_alert(new_alert, st.session_state["user"]["id"])
                st.success("Test alert inserted. Refresh to see it.")
