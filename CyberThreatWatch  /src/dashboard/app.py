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
    st.session_state.alerts_data = [
        {
            "id": 1, "timestamp": datetime.now() - timedelta(hours=2),
            "severity": "High", "type": "Malware Detection",
            "source_ip": "192.168.1.100", "description": "Suspicious executable detected"
        }
    ]

if 'threat_data' not in st.session_state:
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

if page == "Dashboard":
    st.subheader("📊 Dashboard Overview")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Alerts", len(st.session_state.alerts_data))
    with col2:
        fig = px.bar(
            pd.DataFrame(st.session_state.alerts_data),
            x="severity", title="Alerts by Severity"
        )
        st.plotly_chart(fig, width='stretch')  # FIXED: use_container_width=True → width='stretch'

elif page == "Search":
    st.subheader("🔎 Threat Search")
    query = st.text_input("Enter IP, Domain, or Hash")
    if st.button("Search"):
        st.write(f"Searching threat intelligence for: {query}")
        if otx:
            results = otx.search_pulses(query)
            st.json(results)

elif page == "Alerts":
    app.alerts_panel.render(st.session_state.alerts_data)

elif page == "Reports":
    st.subheader("📝 Reports")

    # Convert alerts to dataframe for CSV
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
            # Use absolute import for report generator
            from dashboard.utils.report_generator import generate_report

            pdf_path = generate_report(
                alerts=st.session_state.alerts_data,
                notes=analyst_notes,
                analyst_name="Cyber Analyst",  # You can make this dynamic later
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