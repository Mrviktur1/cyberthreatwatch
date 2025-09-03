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

    def insert_alert(self, alert: Dict) -> bool:
        """Insert a new alert into Supabase"""
        try:
            if self.supabase:
                response = self.supabase.table("alerts").insert(alert).execute()
                if response.data:
                    logger.info(f"Inserted alert into Supabase: {response.data}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Supabase insert error: {e}")
            return False

    def fetch_otx_iocs(self, query: str) -> List[Dict]:
        """Search OTX for indicators of compromise"""
        try:
            if self.otx:
                results = self.otx.search_pulses(query)
                return [
                    {"pulse_id": r.get("id"), "name": r.get("name")}
                    for r in results.get("results", [])
                ]
            return []
        except Exception as e:
            logger.error(f"OTX search error: {e}")
            return []

    def render(self, alerts_data: List[Dict]):
        """Render alerts table and controls"""
        st.write("### 🚨 Active Alerts")

        # --- Fetch Supabase Alerts ---
        supabase_alerts = self.fetch_supabase_alerts()
        all_alerts = alerts_data + supabase_alerts

        if all_alerts:
            df = pd.DataFrame(all_alerts)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No alerts available.")

        # --- Add New Alert ---
        with st.expander("➕ Add New Alert"):
            severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
            alert_type = st.text_input("Type (e.g., Malware, Phishing)")
            source_ip = st.text_input("Source IP")
            description = st.text_area("Description")
            if st.button("Save Alert"):
                new_alert = {
                    "severity": severity,
                    "type": alert_type,
                    "source_ip": source_ip,
                    "description": description,
                    "timestamp": datetime.now().isoformat()
                }
                success = self.insert_alert(new_alert)
                if success:
                    st.success("✅ Alert saved to Supabase!")
                    st.experimental_rerun()
                else:
                    st.error("⚠️ Failed to save alert. Check logs.")

        # --- Search OTX ---
        query = st.text_input("🔎 Search OTX (IP, Domain, Hash)")
        if query:
            otx_results = self.fetch_otx_iocs(query)
            if otx_results:
                st.success(f"Found {len(otx_results)} results in OTX.")
                st.json(otx_results)
            else:
                st.warning("No results found in OTX.")


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
