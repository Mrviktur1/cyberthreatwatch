import streamlit as st
import sys
import os
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
from supabase import create_client, Client
from OTXv2 import OTXv2
from dotenv import load_dotenv
import logging
from PIL import Image
from streamlit_autorefresh import st_autorefresh

# Add the parent directory to Python path to enable absolute imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import the AlertsPanel and OTX collector
from dashboard.components.alerts_panel import AlertsPanel
from dashboard.utils.otx_collector import collect_otx_alerts

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# --- Supabase Client ---
@st.cache_resource
def init_supabase() -> Client:
    try:
        if 'SUPABASE_URL' in st.secrets and 'SUPABASE_KEY' in st.secrets:
            url: str = st.secrets["SUPABASE_URL"]
            key: str = st.secrets["SUPABASE_KEY"]
            return create_client(url, key)
        return None
    except Exception as e:
        logger.error(f"Supabase connection error: {e}")
        return None

supabase = init_supabase()

# --- OTX Client ---
@st.cache_resource
def init_otx():
    try:
        if 'OTX_API_KEY' in st.secrets:
            return OTXv2(st.secrets["OTX_API_KEY"])
        return None
    except Exception as e:
        logger.error(f"OTX init error: {e}")
        return None

otx = init_otx()

# --- Session Data ---
if 'alerts_data' not in st.session_state:
    st.session_state.alerts_data = []

if 'threat_data' not in st.session_state:
    st.session_state.threat_data = []

# --- Main App Config ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# Enable auto-refresh every 60s
st_autorefresh(interval=60 * 1000, key="data_refresh")

class CyberThreatWatch:
    def __init__(self):
        self.logo_path = "assets/CyberThreatWatch.png"
        self.signature_path = "assets/h_Signa....png"
        self.alerts_panel = AlertsPanel(supabase=supabase, otx=otx)

    def load_image(self, path, width=None):
        try:
            if os.path.exists(path):
                image = Image.open(path)
                if width:
                    image = image.resize((width, int(image.height * width / image.width)))
                return image
            return None
        except Exception as e:
            logger.error(f"Error loading image {path}: {e}")
            return None

    def render_header(self):
        col1, col2 = st.columns([1, 3])
        with col1:
            logo_image = self.load_image(self.logo_path, width=100)
            if logo_image:
                st.image(logo_image, width=100)
        with col2:
            st.title("🛡️ CyberThreatWatch")
            st.markdown("Real-time Threat Intelligence Dashboard")
        st.markdown("---")

# --- Navigation ---
page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Search", "Alerts", "Reports", "Threat Detection", "Settings"]
)

app = CyberThreatWatch()
app.render_header()

# --- Dashboard ---
if page == "Dashboard":
    st.subheader("📊 Dashboard Overview")

    if st.button("🔄 Fetch Latest Threats from OTX"):
        collect_otx_alerts(otx, supabase)
        st.success("Fetched latest OTX alerts!")

    if supabase:
        try:
            response = supabase.table("alerts").select("*").execute()
            if response.data:
                df = pd.DataFrame(response.data)

                # Alerts Over Time
                if "timestamp" in df.columns:
                    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
                    time_fig = px.histogram(
                        df, x="timestamp",
                        title="Alerts Over Time"
                    )
                    st.plotly_chart(time_fig, use_container_width=True)

                # Alerts by Severity
                if "severity" in df.columns:
                    severity_fig = px.bar(
                        df["severity"].value_counts().reset_index(),
                        x="index", y="severity",
                        title="Alerts by Severity",
                        labels={"index": "Severity", "severity": "Count"}
                    )
                    st.plotly_chart(severity_fig, use_container_width=True)

                # Top Source IPs
                if "source_ip" in df.columns:
                    top_ips = (
                        df["source_ip"].value_counts().reset_index()
                        .rename(columns={"index": "source_ip", "source_ip": "count"})
                        .head(10)
                    )
                    ip_fig = px.bar(
                        top_ips,
                        x="source_ip", y="count",
                        title="Top 10 Source IPs",
                        labels={"source_ip": "Source IP", "count": "Alert Count"},
                    )
                    st.plotly_chart(ip_fig, use_container_width=True)

                # Top Threat Types
                if "type" in df.columns:
                    top_types = (
                        df["type"].value_counts().reset_index()
                        .rename(columns={"index": "type", "type": "count"})
                        .head(10)
                    )
                    type_fig = px.pie(
                        top_types,
                        names="type", values="count",
                        title="Top Threat Types"
                    )
                    st.plotly_chart(type_fig, use_container_width=True)

            else:
                st.info("✅ Connected to Supabase, but no alerts found.")

        except Exception as e:
            st.error(f"Error fetching data from Supabase: {e}")
    else:
        st.warning("⚠️ Supabase not connected. Please check your credentials.")

# --- Search ---
elif page == "Search":
    st.subheader("🔎 Threat Search")
    query = st.text_input("Enter IP, Domain, or Hash")
    if st.button("Search"):
        st.write(f"Searching threat intelligence for: {query}")
        if otx:
            results = otx.search_pulses(query)
            st.json(results)

# --- Alerts ---
elif page == "Alerts":
    app.alerts_panel.render(st.session_state.alerts_data)

# --- Reports ---
elif page == "Reports":
    st.subheader("📝 Reports")

    if supabase:
        response = supabase.table("alerts").select("*").execute()
        alerts_data = response.data if response.data else []
    else:
        alerts_data = []

    df = pd.DataFrame(alerts_data)

    # CSV download
    st.download_button(
        "⬇️ Download Alerts CSV",
        df.to_csv(index=False),
        file_name="alerts.csv",
        mime="text/csv"
    )

    # Analyst Notes
    st.markdown("### Analyst Notes")
    analyst_notes = st.text_area("Add your observations, insights, or next steps")

    # PDF Report Generator
    if st.button("📄 Generate PDF Report"):
        try:
            from dashboard.utils.report_generator import generate_report

            pdf_path = generate_report(
                alerts=alerts_data,
                notes=analyst_notes,
                analyst_name="Cyber Analyst",
                logo_path=app.logo_path,
                signature_path=app.signature_path
            )

            with open(pdf_path, "rb") as f:
                st.download_button(
                    "⬇️ Download PDF Report",
                    f,
                    file_name="threat_report.pdf",
                    mime="application/pdf"
                )
        except Exception as e:
            st.error(f"Failed to generate PDF report: {e}")

# --- Threat Detection ---
elif page == "Threat Detection":
    st.subheader("⚡ Threat Detection")
    st.info("Detection engine integration coming soon.")

# --- Settings ---
elif page == "Settings":
    st.subheader("⚙️ Settings")
    theme = st.selectbox("Theme", ["Light", "Dark", "System"])
    st.write(f"Theme set to: {theme}")
