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

# Add parent dir to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Local imports
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
        if "SUPABASE_URL" in st.secrets and "SUPABASE_KEY" in st.secrets:
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
        if "OTX_API_KEY" in st.secrets:
            return OTXv2(st.secrets["OTX_API_KEY"])
        return None
    except Exception as e:
        logger.error(f"OTX init error: {e}")
        return None

otx = init_otx()

# --- Session Data ---
if "alerts_data" not in st.session_state:
    st.session_state.alerts_data = []

if "threat_data" not in st.session_state:
    st.session_state.threat_data = []

# --- Main App ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

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
                    image = image.resize(
                        (width, int(image.height * width / image.width))
                    )
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

    # Fetch from OTX
    if st.button("🔄 Fetch Latest Threats from OTX"):
        collect_otx_alerts(otx, supabase)
        st.success("✅ Fetched latest OTX alerts!")
        st.rerun()

    # Fetch fresh alerts from Supabase
    try:
        if supabase:
            response = supabase.table("alerts").select("*").execute()
            alerts = response.data if response.data else []
        else:
            alerts = st.session_state.alerts_data
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        alerts = st.session_state.alerts_data

    # Sync session
    st.session_state.alerts_data = alerts

    # Display dashboard metrics + charts
    if alerts:
        df = pd.DataFrame(alerts)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Alerts", len(df))
        with col2:
            if "severity" in df.columns:
                fig = px.bar(df, x="severity", title="Alerts by Severity")
                st.plotly_chart(fig, use_container_width=True)

        # Timeline chart
        if "timestamp" in df.columns:
            try:
                df["timestamp"] = pd.to_datetime(df["timestamp"])
                timeline_fig = px.histogram(
                    df, x="timestamp", title="Alerts Over Time", nbins=20
                )
                st.plotly_chart(timeline_fig, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not plot timeline: {e}")
    else:
        st.info("⚠️ No alerts available yet. Try fetching from OTX.")

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

    df = pd.DataFrame(st.session_state.alerts_data)

    st.download_button(
        "⬇️ Download Alerts CSV",
        df.to_csv(index=False),
        file_name="alerts.csv",
        mime="text/csv",
    )

    st.markdown("### Analyst Notes")
    analyst_notes = st.text_area("Add your observations, insights, or next steps")

    if st.button("📄 Generate PDF Report"):
        try:
            from dashboard.utils.report_generator import generate_report

            pdf_path = generate_report(
                alerts=st.session_state.alerts_data,
                notes=analyst_notes,
                analyst_name="Cyber Analyst",
                logo_path=app.logo_path,
                signature_path=app.signature_path,
            )

            with open(pdf_path, "rb") as f:
                st.download_button(
                    "⬇️ Download PDF Report",
                    f,
                    file_name="threat_report.pdf",
                    mime="application/pdf",
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


elif page == "Alerts":
    app.alerts_panel.render(st.session_state.alerts_data)

elif page == "Reports":
    st.subheader("📝 Reports")

    if st.session_state.alerts_data:
        df = pd.DataFrame(st.session_state.alerts_data)

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
                alerts=st.session_state.alerts_data,
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

elif page == "Threat Detection":
    st.subheader("⚡ Threat Detection")
    st.info("Detection engine integration coming soon.")

elif page == "Settings":
    st.subheader("⚙️ Settings")
    theme = st.selectbox("Theme", ["Light", "Dark", "System"])
    st.write(f"Theme set to: {theme}")
