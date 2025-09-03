import streamlit as st
import pandas as pd
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class AlertsPanel:
    def __init__(self, supabase=None, otx=None):
        self.supabase = supabase
        self.otx = otx

    def fetch_supabase_alerts(self) -> List[Dict]:
        """Fetch alerts from Supabase if available"""
        try:
            if self.supabase:
                response = self.supabase.table("alerts").select("*").execute()
                if response.data:
                    return response.data
            return []
        except Exception as e:
            logger.error(f"Supabase fetch error: {e}")
            return []

    def fetch_otx_iocs(self, query: str) -> List[Dict]:
        """Search OTX for indicators of compromise"""
        try:
            if self.otx:
                results = self.otx.search_pulses(query)
                return [
                    {"pulse_id": r["id"], "name": r["name"]}
                    for r in results.get("results", [])
                ]
            return []
        except Exception as e:
            logger.error(f"OTX search error: {e}")
            return []

    def render(self, alerts_data: List[Dict]):
        """Render alerts table and controls"""
        st.subheader("🚨 Active Alerts")

        # --- Fetch Alerts from DB ---
        db_alerts = self.fetch_supabase_alerts()
        alerts_df = pd.DataFrame(db_alerts if db_alerts else alerts_data)

        # --- Filter Controls ---
        st.markdown("#### 🔎 Filters")
        if not alerts_df.empty:
            severity_filter, type_filter = None, None

            col1, col2 = st.columns(2)
            with col1:
                if "severity" in alerts_df.columns:
                    severity_filter = st.multiselect(
                        "Severity",
                        options=alerts_df["severity"].unique(),
                        default=list(alerts_df["severity"].unique())
                    )
            with col2:
                if "type" in alerts_df.columns:
                    type_filter = st.multiselect(
                        "Type",
                        options=alerts_df["type"].unique(),
                        default=list(alerts_df["type"].unique())
                    )

            # Apply filters safely
            filtered_df = alerts_df.copy()
            if severity_filter is not None:
                filtered_df = filtered_df[filtered_df["severity"].isin(severity_filter)]
            if type_filter is not None:
                filtered_df = filtered_df[filtered_df["type"].isin(type_filter)]
        else:
            st.info("⚠️ No alerts available in Supabase yet.")
            filtered_df = alerts_df

        # --- Display Alerts ---
        if not filtered_df.empty:
            st.dataframe(filtered_df, use_container_width=True)
        else:
            st.warning("No alerts match your filters.")
