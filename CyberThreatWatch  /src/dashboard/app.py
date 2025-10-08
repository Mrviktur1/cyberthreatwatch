# src/dashboard/app.py
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
from functools import lru_cache
from datetime import datetime, timedelta
import time

# Add parent directory for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import custom components
from dashboard.components.alerts_panel import AlertsPanel
from dashboard.components.login import LoginComponent
from dashboard.utils.otx_collector import collect_otx_alerts
from dashboard.utils.geoip_helper import ip_to_location
from dashboard.services.sensor import start_sensor, stop_sensor
from dashboard.services.data_service import data_stream

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# --- Supabase Client ---
@st.cache_resource
def init_supabase() -> Client:
    try:
        url, key = st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"]
        client = create_client(url, key)
        logger.info("✅ Supabase connected.")
        return client
    except Exception as e:
        logger.error(f"Supabase init error: {e}")
        return None

supabase = init_supabase()

# --- OTX Client ---
@st.cache_resource
def init_otx():
    try:
        if "OTX_API_KEY" in st.secrets:
            return OTXv2(st.secrets["OTX_API_KEY"])
    except Exception as e:
        logger.error(f"OTX init error: {e}")
    return None

otx = init_otx()

# --- Session defaults ---
for key, val in {
    "alerts_data": [],
    "realtime_active": False,
    "latest_alerts": [],
    "last_refresh": time.time()
}.items():
    st.session_state.setdefault(key, val)

# --- Page Config ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🔰")

# --- 5D UI Styling ---
st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background: radial-gradient(circle at 10% 10%, #020617 0%, #00040a 80%);
    color: #E6F7FF;
    font-family: "Inter", sans-serif;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#0b1120 0%, #05080f 100%);
    color: #bde8ff;
    border-right: 1px solid rgba(255,255,255,0.05);
}
h1, h2, h3 {
    color: #aaf5ff;
    text-shadow: 0 0 12px rgba(0,255,255,0.18);
}
.metric-card {
    background: rgba(255,255,255,0.04);
    border-radius: 14px;
    padding: 10px;
    box-shadow: inset 0 0 20px rgba(0,255,255,0.05);
    backdrop-filter: blur(6px);
}
.stButton>button {
    background: linear-gradient(90deg,#00ffd5,#007bff);
    color: white;
    border-radius:10px;
    border:none;
    padding:8px 14px;
    transition: all 0.2s ease-in-out;
}
.stButton>button:hover { transform: scale(1.04); }
</style>
""", unsafe_allow_html=True)

# --- Auth ---
login = LoginComponent()
login.check_authentication()

# --- Header ---
class CyberThreatWatch:
    def __init__(self):
        self.logo_path = "assets/CyberThreatWatch.png"
        self.signature_path = "assets/h_Signature.png"
        try:
            self.alerts_panel = AlertsPanel(supabase=supabase, otx=otx)
        except Exception as e:
            logger.warning(f"AlertsPanel init failed: {e}")
            self.alerts_panel = None

    def load_image(self, path, width=None):
        try:
            if os.path.exists(path):
                img = Image.open(path)
                if width:
                    img = img.resize((width, int(img.height * width / img.width)))
                return img
        except Exception as e:
            logger.error(f"Image load error: {e}")
        return None

    def render_header(self):
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            logo = self.load_image(self.logo_path, width=90)
            if logo:
                st.image(logo, width=90)
        with col2:
            st.title("CyberThreatWatch Dashboard")
            st.markdown(f"**Real-time Threat Intelligence Monitoring** — Welcome, *{st.session_state.get('user_name', 'User')}*")
        with col3:
            sig = self.load_image(self.signature_path, width=100)
            if sig:
                st.image(sig, width=100)
        st.markdown("---")

app = CyberThreatWatch()
app.render_header()

# --- Sidebar Navigation ---
login.render_logout_section()
st.sidebar.markdown("## Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Alerts", "Reports", "Settings"], label_visibility="collapsed")

# --- Sidebar Sensor + Refresh Control ---
st.sidebar.subheader("🧠 Local Sensor Control")
if st.sidebar.toggle("Enable Local Sensor", value=False):
    start_sensor()
else:
    stop_sensor()

sensor_interval = st.sidebar.slider("Sensor Upload Interval (secs)", 30, 300, 60)
refresh_rate = st.sidebar.slider("Dashboard Refresh Interval", 5, 60, 15)

st.sidebar.markdown("---")
st.sidebar.write("Realtime Status:")
if st.session_state.get("realtime_active"):
    st.sidebar.success("🟢 Active")
else:
    st.sidebar.info("🔴 Idle")

# --- Real-time wiring ---
def update_dashboard_from_stream(data):
    st.session_state["latest_alerts"] = data
    st.experimental_rerun()

if not st.session_state["realtime_active"]:
    data_stream.start_realtime(interval=refresh_rate)
    data_stream.subscribe(update_dashboard_from_stream)
    st.session_state["realtime_active"] = True

# --- Helper functions ---
@lru_cache(maxsize=2000)
def cached_ip_lookup(ip):
    try: return ip_to_location(ip)
    except: return None

def high_threat_detected(alerts):
    for a in alerts or []:
        if isinstance(a, dict) and a.get("severity", "").lower() == "high":
            return True
    return False

# --- Auto Refresh ---
if time.time() - st.session_state["last_refresh"] > refresh_rate:
    st.session_state["last_refresh"] = time.time()
    st.experimental_rerun()

# --- Main Pages ---
if page == "Dashboard":
    st.subheader("📊 Dashboard Overview")

    col1, col2, col3 = st.columns([1.5, 1, 1])
    with col1:
        if st.button("🔄 Fetch OTX Threats", use_container_width=True):
            try:
                new_alerts = collect_otx_alerts(otx, supabase)
                st.success(f"Fetched {len(new_alerts)} new alerts!")
            except Exception as e:
                st.error(f"Fetch failed: {e}")
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        total_alerts = len(st.session_state.get("latest_alerts", []))
        st.metric("Total Alerts", total_alerts)
        st.markdown('</div>', unsafe_allow_html=True)
    with col3:
        if high_threat_detected(st.session_state.get("latest_alerts", [])):
            st.markdown("""
            <div style='text-align:center;'>
                <div style='width:28px;height:28px;border-radius:50%;background:#ff4d4d;
                    animation:pulse 1.5s infinite; margin:auto; box-shadow: 0 0 20px #ff4d4d88;'></div>
            </div>
            <style>@keyframes pulse{0%{box-shadow:0 0 4px #ff4d4d;}50%{box-shadow:0 0 28px #ff4d4d;}100%{box-shadow:0 0 4px #ff4d4d;}}</style>
            """, unsafe_allow_html=True)
            st.error("High-severity threat detected!")
        else:
            st.success("System stable — no critical threats.")

    df = pd.DataFrame(st.session_state.get("latest_alerts", []))
    if not df.empty:
        st.dataframe(df.head(30), use_container_width=True)
    else:
        st.info("No alert data found. Waiting for sensor or Supabase feed...")

elif page == "Alerts":
    st.subheader("🔍 Detailed Alerts Feed")
    df = pd.DataFrame(st.session_state.get("latest_alerts", []))
    if not df.empty:
        st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)
    else:
        st.info("No alerts available yet.")

elif page == "Reports":
    st.subheader("🧾 Reports & Export")
    df = pd.DataFrame(st.session_state.get("latest_alerts", []))
    if not df.empty:
        st.download_button("⬇️ Export CSV", df.to_csv(index=False), "alerts.csv")
    else:
        st.info("No alerts to export.")

elif page == "Settings":
    st.subheader("⚙️ Settings")
    st.write("Adjust system and sensor configurations here.")
    st.write("Sensor interval:", sensor_interval, "seconds")
    st.write("Dashboard refresh:", refresh_rate, "seconds")

# --- Footer ---
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:gray;font-size:13px;'>"
    "CyberThreatWatch v1.0 • © 2025 Enemmoh Victor Okechukwu"
    "</div>", unsafe_allow_html=True)
