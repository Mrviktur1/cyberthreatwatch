import streamlit as st
import pandas as pd
from typing import List, Dict
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertsPanel:
    def __init__(self, supabase=None, otx=None):
        self.supabase = supabase
        self.otx = otx

    # --- Database Functions ---
    def fetch_supabase_alerts(self) -> List[Dict]:
        """Fetch alerts from Supabase if available"""
        try:
            if self.supabase:
                response = self.supabase.table("alerts").select("*").order("timestamp", desc=True).execute()
                if response.data:
                    return response.data
            return []
        except Exception as e:
            logger.error(f"Supabase fetch error: {e}")
            return []

    def insert_alert(self, alert: Dict):
        """Insert a new alert into Supabase"""
        try:
            if self.supabase:
                response = self.supabase.table("alerts").insert(alert).execute()
                if response.data:
                    return response.data
            return None
        except Exception as e:
            logger.error(f"Supabase insert error: {e}")
            return None

    def update_alert(self, alert_id: int, updates: Dict):
        """Update an existing alert"""
        try:
            if self.supabase:
                response = self.supabase.table("alerts").update(updates).eq("id", alert_id).execute()
                return response.data
        except Exception as e:
            logger.error(f"Supabase update error: {e}")
        return None

    def delete_alert(self, alert_id: int):
        """Delete an alert"""
        try:
            if self.supabase:
                self.supabase.table("alerts").delete().eq("id", alert_id).execute()
        except Exception as e:
            logger.error(f"Supabase delete error: {e}")

    # --- UI Functions ---
    def render(self, alerts_data: List[Dict]):
        """Render alerts table and controls"""
        st.subheader("🚨 Active Alerts")

        # --- Fetch Alerts from DB ---
        db_alerts = self.fetch_supabase_alerts()
        alerts_df = pd.DataFrame(db_alerts if db_alerts else alerts_data)

        # --- Filter Controls ---
        st.markdown("#### 🔎 Filters")
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect("Severity", options=alerts_df["severity"].unique(), default=list(alerts_df["severity"].unique()))
        with col2:
            type_filter = st.multiselect("Type", options=alerts_df["type"].unique(), default=list(alerts_df["type"].unique()))

        filtered_df = alerts_df[
            (alerts_df["severity"].isin(severity_filter)) &
            (alerts_df["type"].isin(type_filter))
        ]

        # --- Display Alerts ---
        st.dataframe(filtered_df, use_container_width=True)

        # --- Add New Alert ---
        with st.expander("➕ Add New Alert"):
            col1, col2 = st.columns(2)
            with col1:
                severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                alert_type = st.text_input("Type", "Suspicious Activity")
            with col2:
                source_ip = st.text_input("Source IP", "192.168.1.1")
                description = st.text_area("Description")

            if st.button("Add Alert"):
                new_alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "severity": severity,
                    "type": alert_type,
                    "source_ip": source_ip,
                    "description": description,
                    "status": "Open"
                }
                self.insert_alert(new_alert)
                st.success("✅ Alert added!")
                st.experimental_rerun()

        # --- Manage Alerts ---
        st.markdown("#### 🛠 Manage Alerts")
        for _, row in filtered_df.iterrows():
            with st.expander(f"Alert #{row['id']} - {row['type']}"):
                st.write(f"**Severity:** {row['severity']}")
                st.write(f"**Source IP:** {row['source_ip']}")
                st.write(f"**Description:** {row['description']}")
                st.write(f"**Status:** {row.get('status', 'Open')}")

                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button(f"✅ Resolve {row['id']}", key=f"resolve_{row['id']}"):
                        self.update_alert(row['id'], {"status": "Resolved"})
                        st.experimental_rerun()
                with col2:
                    if st.button(f"📝 Tag {row['id']}", key=f"tag_{row['id']}"):
                        tag = st.text_input("Enter Tag", key=f"tag_input_{row['id']}")
                        if tag:
                            self.update_alert(row['id'], {"tag": tag})
                            st.experimental_rerun()
                with col3:
                    if st.button(f"❌ Delete {row['id']}", key=f"delete_{row['id']}"):
                        self.delete_alert(row['id'])
                        st.experimental_rerun()
