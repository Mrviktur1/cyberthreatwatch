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
                return [{"pulse_id": r["id"], "name": r["name"]} for r in results.get("results", [])]
            return []
        except Exception as e:
            logger.error(f"OTX search error: {e}")
            return []

    def render(self, alerts_data: List[Dict]):
        """Render alerts table and controls"""
        st.write("### Active Alerts")

        # Pull from Supabase if available
        supabase_alerts = self.fetch_supabase_alerts()
        combined_alerts = alerts_data + supabase_alerts

        if not combined_alerts:
            st.info("✅ No alerts at the moment.")
            return

        df = pd.DataFrame(combined_alerts)
        st.dataframe(df, use_container_width=True)

        # CSV export
        st.download_button(
            "⬇️ Download Alerts CSV",
            df.to_csv(index=False),
            file_name="alerts_export.csv",
            mime="text/csv"
        )

        # OTX search
        st.write("### Threat Intel Lookup")
        query = st.text_input("Search OTX (IP, Domain, Hash)")
        if st.button("Search OTX") and query:
            results = self.fetch_otx_iocs(query)
            if results:
                st.json(results)
            else:
                st.warning("No results found in OTX.")
