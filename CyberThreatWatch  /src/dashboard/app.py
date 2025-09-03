import streamlit as st
import sys
import os
import pandas as pd
import plotly.express as px
from supabase import create_client, Client
from OTXv2 import OTXv2
from dotenv import load_dotenv
import logging
from PIL import Image

# Add the parent directory to Python path to enable absolute imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import the AlertsPanel using absolute import
from dashboard.components.alerts_panel import AlertsPanel

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

    alerts = []
    if supabase:
        try:
            response = supabase.table("alerts").select("*").execute()
            if response.data:
                alerts = response.data
        except Exception as e:
            st.error(f"⚠️ Failed to fetch alerts: {e}")

    total_alerts = len(alerts)
    high_alerts = sum(1 for a in alerts if a.get("severity") == "High")
    critical_alerts = sum(1 for a in alerts if a.get("severity") == "Critical")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Alerts", total_alerts)
    with col2:
        st.metric("High Alerts", high_alerts)
    with col3:
        st.metric("Critical Alerts", critical_alerts)

    if alerts:
        df = pd.DataFrame(alerts)

        # Alerts by Severity
        if "severity" in df.columns:
            fig_severity = px.bar(
                df,
                x="severity",
                title="Alerts by Severity",
                text_auto=True
            )
            st.plotly_chart(fig_severity, width="stretch")

        # Alerts over Time
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            fig_time = px.line(
                df.groupby(df["timestamp"].dt.date).size().reset_index(name="count"),
                x="timestamp", y="count", markers=True,
                title="Alerts Over Time"
            )
            st.plotly_chart(fig_time, width="stretch")
    else:
        st.info("No alerts found in Supabase. Add some in the Alerts panel to see trends here!")

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
    app.alerts_panel.render([])

# --- Reports ---
elif page == "Reports":
    st.subheader("📝 Reports")

    alerts = []
    if supabase:
        try:
            response = supabase.table("alerts").select("*").execute()
            if response.data:
                alerts = response.data
        except Exception as e:
            st.error(f"⚠️ Failed to fetch alerts: {e}")

    df = pd.DataFrame(alerts)

    st.download_button(
        "⬇️ Download Alerts CSV",
        df.to_csv(index=False),
        file_name="alerts.csv",
        mime="text/csv"
    )

    st.markdown("### Analyst Notes")
    analyst_notes = st.text_area("Add your observations, insights, or next steps")

    if st.button("📄 Generate PDF Report"):
        try:
            from dashboard.utils.report_generator import generate_report
            pdf_path = generate_report(
                alerts=alerts,
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
