import streamlit as st
import sys
import os
import subprocess
import platform
import pandas as pd
import plotly.express as px
from supabase import create_client, Client
from OTXv2 import OTXv2
from dotenv import load_dotenv
import logging
from PIL import Image
from datetime import datetime, timedelta
import time
import json
import hashlib

# Add parent directory for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Custom components and utils
from dashboard.components.alerts_panel import AlertsPanel
from dashboard.components.login import LoginComponent
from dashboard.utils.otx_collector import collect_otx_alerts
from dashboard.utils.geoip_helper import ip_to_location

# Services
from dashboard.services.sensor import start_sensor, stop_sensor, send_logs_to_supabase
from dashboard.services.data_service import data_stream

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# --- Supabase Client helper ---
@st.cache_resource
def init_supabase() -> Client:
    try:
        if "SUPABASE_URL" in st.secrets and "SUPABASE_KEY" in st.secrets:
            url: str = st.secrets["SUPABASE_URL"]
            key: str = st.secrets["SUPABASE_KEY"]
            client = create_client(url, key)
            try:
                client.table("alerts").select("id", count="exact").limit(1).execute()
                logger.info("✅ Supabase connection successful")
            except Exception as e:
                logger.warning(f"Supabase test query warning: {e}")
            return client
        logger.warning("Supabase credentials not found in st.secrets")
        return None
    except Exception as e:
        logger.error(f"Supabase init error: {e}")
        return None

supabase = init_supabase()

# --- OTX client ---
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

# --- Page config ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- Theme ---
st.markdown("""
<style>
:root { --accent1:#00A6FF; --accent2:#00D1B2; --glass: rgba(255,255,255,0.7); }
[data-testid="stAppViewContainer"] { background: linear-gradient(180deg,#f6fbff 0%, #eef9ff 100%); color:#042028; }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#ffffff, #f1fbff); }
h1,h2,h3 { color:#013047; }
.stButton>button { background: linear-gradient(90deg,var(--accent2),var(--accent1)); color:white; border-radius:10px; }
.metric-card { background: linear-gradient(180deg, rgba(255,255,255,0.85), rgba(255,255,255,0.7)); border-radius:10px; padding:8px; }
.logo-small { border-radius:8px; }
</style>
""", unsafe_allow_html=True)

# --- Session defaults ---
defaults = {
    "alerts_data": [],
    "latest_alerts": [],
    "realtime_active": False,
    "last_refresh": time.time(),
    "agent_pid": None,
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# --- Authentication handler ---
login_component = LoginComponent(supabase=supabase)

# Handle verification link (redirected from Supabase)
if "access_token" in st.query_params:
    st.success("✅ Your email has been verified successfully! Redirecting to your dashboard...")
    st.session_state.authenticated = True
    st.rerun()

# If user not authenticated, show login/signup page
login_component.check_authentication()

# If user session expired, log out automatically
if "session_expiry" in st.session_state:
    if datetime.now() > st.session_state.session_expiry:
        st.warning("⚠️ Your session has expired. Please log in again.")
        for key in ["authenticated", "user_id", "user_email", "user_name", "account_type", "organization", "session_expiry"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

# --- Main Dashboard ---
class CyberThreatWatch:
    def __init__(self):
        self.logo_path = os.path.join("assets", "CyberThreatWatch.png")
        self.signature_path = os.path.join("assets", "h_Signature.png")
        try:
            self.alerts_panel = AlertsPanel(supabase=supabase, otx=otx)
        except Exception as e:
            logger.warning(f"AlertsPanel init error: {e}")
            self.alerts_panel = None

    def load_image(self, path, width=None):
        try:
            if path and os.path.exists(path):
                img = Image.open(path)
                if width:
                    img = img.resize((width, int(img.height * width / img.width)))
                return img
        except Exception as e:
            logger.error(f"Image load error ({path}): {e}")
        return None

    def render_header(self):
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            logo = self.load_image(self.logo_path, width=96)
            if logo:
                st.image(logo, width=96)
            else:
                st.markdown("### 🛡️")
        with col2:
            st.title("CyberThreatWatch")
            user_name = st.session_state.get("user_name", "Analyst")
            st.markdown(f"Real-time Threat Intelligence · Welcome, **{user_name}**")
        with col3:
            st.markdown("🔐")
        st.markdown("---")

    def render_dashboard(self):
        st.sidebar.header("🧭 Navigation")
        options = ["Dashboard", "Active Alerts", "Sensor", "Account Settings"]
        choice = st.sidebar.radio("Select View", options)

        if choice == "Dashboard":
            st.subheader("📊 Threat Overview")
            st.write("Monitoring ongoing threats and system integrity in real time...")

        elif choice == "Active Alerts":
            if self.alerts_panel:
                self.alerts_panel.render()
            else:
                st.error("⚠️ Alert panel could not be loaded.")

        elif choice == "Sensor":
            st.subheader("🛰️ Network Sensor Control")
            if not st.session_state.realtime_active:
                if st.button("▶️ Start Monitoring"):
                    start_sensor()
                    st.session_state.realtime_active = True
                    st.success("✅ Monitoring started.")
            else:
                if st.button("⏹ Stop Monitoring"):
                    stop_sensor()
                    st.session_state.realtime_active = False
                    st.info("🛑 Monitoring stopped.")

        elif choice == "Account Settings":
            st.subheader("⚙️ Account Information")
            st.write(f"**Name:** {st.session_state.get('user_name')}")
            st.write(f"**Email:** {st.session_state.get('user_email')}")
            st.write(f"**Account Type:** {st.session_state.get('account_type')}")
            st.write(f"**Organization:** {st.session_state.get('organization')}")

# --- Instantiate and render dashboard ---
app = CyberThreatWatch()
app.render_header()
app.render_dashboard()

# Logout section (sidebar)
login_component.render_logout_section()
