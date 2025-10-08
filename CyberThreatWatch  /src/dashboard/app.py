# src/dashboard/app.py
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
from functools import lru_cache
from datetime import datetime, timedelta
import time
import json

# Add parent directory for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import custom components (from your repo)
from dashboard.components.alerts_panel import AlertsPanel
from dashboard.components.login import LoginComponent
from dashboard.utils.otx_collector import collect_otx_alerts
from dashboard.utils.geoip_helper import ip_to_location

# Import services
from dashboard.services.sensor import start_sensor, stop_sensor, send_logs_to_supabase
from dashboard.services.data_service import data_stream

# Logging setup
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
                # basic test query
                result = client.table("alerts").select("id", count="exact").limit(1).execute()
                logger.info("✅ Supabase connection successful")
            except Exception as query_error:
                logger.warning(f"Supabase test query warning: {query_error}")
            return client
        logger.warning("Supabase credentials not found in secrets")
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

# --- Session defaults ---
if "alerts_data" not in st.session_state:
    # default demo row so UI is not empty
    st.session_state.alerts_data = [
        {
            "id": 1,
            "timestamp": datetime.now() - timedelta(hours=2),
            "severity": "High",
            "type": "Malware Detection",
            "source_ip": "192.168.1.100",
            "message": "Suspicious executable detected",
            "country": "Unknown",
            "lat": 0,
            "lon": 0
        }
    ]

if "latest_alerts" not in st.session_state:
    st.session_state["latest_alerts"] = []

if "realtime_active" not in st.session_state:
    st.session_state["realtime_active"] = False

if "last_refresh" not in st.session_state:
    st.session_state["last_refresh"] = time.time()

if "agent_pid" not in st.session_state:
    st.session_state["agent_pid"] = None

# --- Page setup ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- 5D-ish visual theme (lighter than previous dark) ---
st.markdown(
    """
    <style>
    :root {
        --accent1: #00A6FF; /* teal-blue accent */
        --accent2: #00D1B2;
        --card-bg: rgba(255,255,255,0.06);
        --glass-border: rgba(255,255,255,0.08);
    }
    body, [data-testid="stAppViewContainer"] {
        background: linear-gradient(180deg,#f6fbff 0%, #eef9ff 100%);
        color: #042028;
        font-family: Inter, "Segoe UI", Roboto, sans-serif;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg,#ffffff, #f1fbff);
        border-right: 1px solid rgba(4,32,40,0.04);
    }
    h1,h2,h3 { color: #013047; }
    .stButton>button {
        background: linear-gradient(90deg,var(--accent2), var(--accent1));
        color: white;
        border-radius: 10px;
        border: none;
        padding: 6px 10px;
        box-shadow: 0 8px 22px rgba(0,160,255,0.12);
    }
    .metric-card {
        background: linear-gradient(180deg, rgba(255,255,255,0.7), rgba(255,255,255,0.55));
        border-radius:12px;
        padding:10px;
        border: 1px solid var(--glass-border);
        box-shadow: 0 4px 18px rgba(1,48,71,0.06);
    }
    .logo-small { border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,0.06); }
    </style>
    """,
    unsafe_allow_html=True
)

# Optional Lottie animation for header (if available)
try:
    from streamlit_lottie import st_lottie
    import requests

    def load_lottie_url(url):
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
        return None

    lottie_small = load_lottie_url("https://assets8.lottiefiles.com/packages/lf20_vf2twv.json")
except Exception:
    st_lottie = None
    lottie_small = None

# --- Authentication ---
login_component = LoginComponent()
login_component.check_authentication()

# --- App class for header & images ---
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
                st.image(logo, width=96, use_column_width=False, output_format="PNG", caption=None)
            else:
                # fallback small badge using emoji
                st.markdown("### 🛡️")
        with col2:
            st.title("CyberThreatWatch")
            user_name = st.session_state.get("user_name", "Analyst")
            st.markdown(f"Real-time Threat Intelligence · Welcome, **{user_name}**")
        with col3:
            if lottie_small and st_lottie:
                try:
                    st_lottie(lottie_small, height=80, key="lottie_hdr")
                except Exception:
                    if st.session_state.get("user_picture"):
                        st.image(st.session_state.user_picture, width=48)
                    else:
                        st.markdown("🔐")
            else:
                if st.session_state.get("user_picture"):
                    st.image(st.session_state.user_picture, width=48)
                else:
                    st.markdown("🔐")

        st.markdown("---")

# show user info & logout
login_component.render_logout_section()

# Sidebar controls
st.sidebar.markdown("## 🧭 Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "Search", "Alerts", "Reports", "Threat Detection", "Settings"],
    label_visibility="collapsed"
)

# Local sensor controls in sidebar
st.sidebar.markdown("## 🧠 Local Sensor")
sensor_toggle = st.sidebar.toggle("Enable Local Sensor", value=False)
if sensor_toggle:
    try:
        start_sensor()
        st.sidebar.success("Sensor service requested to start")
    except Exception as e:
        logger.error(f"start_sensor error: {e}")
        st.sidebar.error("Failed to start sensor (see logs)")
else:
    try:
        stop_sensor()
    except Exception as e:
        logger.error(f"stop_sensor error: {e}")

# Refresh interval control
refresh_seconds = st.sidebar.slider("Refresh interval (sec)", min_value=5, max_value=120, value=15, step=5)

# -----------------------------
# Agent installer helpers (writes a small agent to user's home dir)
# -----------------------------
AGENT_DIR = os.path.join(os.path.expanduser("~"), ".cyberthreatwatch")
AGENT_FILE = os.path.join(AGENT_DIR, "agent.py")
AGENT_PID_FILE = os.path.join(AGENT_DIR, "agent.pid")

def write_agent_file(source: str):
    os.makedirs(AGENT_DIR, exist_ok=True)
    with open(AGENT_FILE, "w", encoding="utf-8") as f:
        f.write(source)
    # make executable on unix
    try:
        if platform.system().lower() != "windows":
            os.chmod(AGENT_FILE, 0o755)
    except Exception:
        pass

def start_agent(detach: bool = True, interval: int = 60, env: dict = None):
    """
    Start the agent script as a detached background process (best-effort).
    Returns subprocess.Popen or raises.
    """
    if not os.path.exists(AGENT_FILE):
        raise FileNotFoundError("Agent file not found; install first.")

    cmd = [sys.executable, AGENT_FILE, str(interval)]
    # set environment
    proc_env = os.environ.copy()
    if env:
        proc_env.update({k: v for k,v in env.items() if v})
    # platform-specific detach
    if platform.system().lower() == "windows":
        # CREATE_NO_WINDOW to detach GUI
        CREATE_NO_WINDOW = 0x08000000
        p = subprocess.Popen(cmd, env=proc_env, creationflags=CREATE_NO_WINDOW)
    else:
        p = subprocess.Popen(cmd, env=proc_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setpgrp)
    # write pid
    try:
        with open(AGENT_PID_FILE, "w") as pf:
            pf.write(str(p.pid))
    except Exception:
        pass
    st.session_state["agent_pid"] = p.pid
    return p

def stop_agent():
    """Stop agent if running (best-effort)."""
    pid = None
    try:
        if os.path.exists(AGENT_PID_FILE):
            with open(AGENT_PID_FILE, "r") as pf:
                pid = int(pf.read().strip())
    except Exception:
        pid = st.session_state.get("agent_pid")
    if not pid:
        return False
    try:
        if platform.system().lower() == "windows":
            subprocess.call(["taskkill", "/F", "/PID", str(pid)])
        else:
            os.kill(pid, 15)
        try:
            os.remove(AGENT_PID_FILE)
        except Exception:
            pass
        st.session_state["agent_pid"] = None
        return True
    except Exception as e:
        logger.error(f"Failed to stop agent pid {pid}: {e}")
        return False

def agent_status():
    pid = None
    try:
        if os.path.exists(AGENT_PID_FILE):
            with open(AGENT_PID_FILE, "r") as pf:
                pid = int(pf.read().strip())
    except Exception:
        pid = st.session_state.get("agent_pid")
    if not pid:
        return {"running": False, "pid": None}
    # check
    try:
        os.kill(pid, 0)
        return {"running": True, "pid": pid}
    except Exception:
        return {"running": False, "pid": pid}

# Sidebar: installer UI
st.sidebar.markdown("## 🧩 Local Agent Installer")
st.sidebar.write("Install a lightweight agent to read local logs and push to Supabase (local machines only).")

if st.sidebar.button("⚙️ Write agent to this machine"):
    # agent template: reads logs by calling send_logs_to_supabase or basic read
    agent_template = f"""#!/usr/bin/env python3
import time, os, sys
from datetime import datetime
# This agent periodically calls the app's public upload endpoint (if exists)
# or writes logs to stdout as an example. Adjust as needed.

def read_and_send():
    # Simple local log mock - replace with production log collection
    try:
        import platform
        node = platform.node()
        now = datetime.utcnow().isoformat()
        msg = f"agent-log from {{node}} at {{now}}"
        # In production: call Supabase REST or your endpoint with stored credentials
        print(msg)
    except Exception as e:
        print('agent error:', e)

if __name__ == '__main__':
    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    while True:
        read_and_send()
        time.sleep(interval)
"""
    try:
        write_agent_file(agent_template)
        st.success(f"Agent template written to {AGENT_FILE}")
    except Exception as e:
        st.error(f"Failed to write agent: {e}")

if st.sidebar.button("▶️ Start agent (local)"):
    try:
        env = {"SUPABASE_URL": st.secrets.get("SUPABASE_URL"), "SUPABASE_KEY": st.secrets.get("SUPABASE_KEY")}
        p = start_agent(detach=True, interval=st.sidebar.number_input("Agent interval (s)", min_value=10, max_value=3600, value=60), env=env)
        st.success(f"Agent started (pid {p.pid}) — local only")
    except Exception as e:
        st.error(f"Start agent failed: {e}")

if st.sidebar.button("⛔ Stop agent"):
    ok = stop_agent()
    if ok:
        st.success("Agent stopped")
    else:
        st.warning("Agent not running or could not be stopped")

st.sidebar.write("Agent status:", agent_status())

# Instantiate app and render header
app = CyberThreatWatch()
app.render_header()

# -------------------------
# Realtime wiring (subscribe to your data_stream)
# -------------------------
def update_dashboard_from_stream(data):
    try:
        st.session_state["latest_alerts"] = data or []
        # keep alerts_data for backward compatibility
        if data:
            st.session_state["alerts_data"] = data
        # try triggering UI refresh
        try:
            st.experimental_rerun()
        except Exception:
            st.rerun()
    except Exception as e:
        logger.error(f"update_dashboard_from_stream error: {e}")

if not st.session_state.get("realtime_active"):
    try:
        data_stream.start_realtime()
        data_stream.subscribe(update_dashboard_from_stream)
        st.session_state["realtime_active"] = True
        logger.info("Realtime data_stream started")
    except Exception as e:
        logger.error(f"Realtime start/subscribe error: {e}")
        st.sidebar.error("Realtime stream failed to start - check logs")

# GeoIP cache
@lru_cache(maxsize=5000)
def cached_ip_lookup(ip):
    try:
        return ip_to_location(ip)
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None

# helper: emergency indicator
def emergency_indicator(alerts):
    try:
        for a in alerts or []:
            sev = (a.get("severity") or "").lower() if isinstance(a, dict) else ""
            if sev == "high":
                return True
    except Exception:
        pass
    return False

# helper: fetch recent alerts directly (fallback)
def fetch_recent_alerts_from_supabase(limit=100):
    if not supabase:
        return []
    try:
        res = supabase.table("alerts").select("*").order("timestamp", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"Supabase fetch error: {e}")
        return []

# Auto refresh using refresh_seconds
now = time.time()
if now - st.session_state.get("last_refresh", 0) > refresh_seconds:
    st.session_state["last_refresh"] = now
    try:
        st.experimental_rerun()
    except Exception:
        st.rerun()

# -------------------------
# Pages
# -------------------------
if page == "Dashboard":
    st.subheader("📊 Dashboard Overview")

    # top controls
    top_col1, top_col2, top_col3 = st.columns([1.5, 1, 1])
    with top_col1:
        if st.button("🔄 Fetch OTX Threats", use_container_width=True):
            if otx and supabase:
                try:
                    new_alerts = collect_otx_alerts(otx, supabase)
                    st.success(f"Fetched {len(new_alerts) if new_alerts else 0} new alerts")
                except Exception as e:
                    st.error(f"OTX fetch error: {e}")
            else:
                st.warning("OTX or Supabase not configured")

    with top_col2:
        total_alerts = len(st.session_state.get("alerts_data", []))
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Alerts", total_alerts)
        st.markdown('</div>', unsafe_allow_html=True)

    with top_col3:
        high_present = emergency_indicator(st.session_state.get("alerts_data", []))
        st.markdown("### ⚠️ Emergency")
        if high_present:
            st.markdown("<div style='color: #b00020; font-weight:700;'>High severity detected — check Alerts</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style='color: #0a6; font-weight:700;'>All clear</div>", unsafe_allow_html=True)

    # assemble dataframe
    alerts_list = st.session_state.get("alerts_data", []) or fetch_recent_alerts_from_supabase(limit=50)
    df = pd.DataFrame(alerts_list) if alerts_list else pd.DataFrame()

    if not df.empty:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # charts row
        c1, c2 = st.columns(2)
        with c1:
            try:
                if "severity" in df.columns and not df["severity"].empty:
                    sev_counts = df["severity"].value_counts().reset_index()
                    sev_counts.columns = ["severity", "count"]
                    fig = px.bar(sev_counts, x="severity", y="count", title="Alerts by Severity")
                    st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                logger.error(f"Severity chart: {e}")
        with c2:
            try:
                if "source_ip" in df.columns and not df["source_ip"].empty:
                    top_ips = df["source_ip"].value_counts().head(10).reset_index()
                    top_ips.columns = ["source_ip", "count"]
                    fig = px.bar(top_ips, x="source_ip", y="count", title="Top Source IPs")
                    st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                logger.error(f"Top IPs chart: {e}")

        # time series
        try:
            if "timestamp" in df.columns and not df["timestamp"].empty:
                df_time = df.set_index("timestamp").resample("H").size().reset_index(name="count")
                fig = px.line(df_time, x="timestamp", y="count", title="Alerts Over Time (Hourly)")
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            logger.error(f"Time series: {e}")

        # Geo map
        st.subheader("🌍 Global Threat Map")
        geo_data = []
        for ip in df["source_ip"].dropna().unique() if "source_ip" in df.columns else []:
            loc = cached_ip_lookup(ip)
            if loc and loc.get("lat") and loc.get("lon"):
                geo_data.append({"ip": ip, "lat": loc["lat"], "lon": loc["lon"], "country": loc.get("country"), "city": loc.get("city")})
        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            map_fig = px.scatter_mapbox(
                geo_df, lat="lat", lon="lon", hover_name="ip", hover_data=["country", "city"],
                zoom=1, height=420, title="Threat Origins Worldwide"
            )
            map_fig.update_layout(mapbox_style="carto-positron", margin={"r": 0, "t": 30, "l": 0, "b": 0})
            st.plotly_chart(map_fig, use_container_width=True)
        else:
            st.info("No GeoIP data available for mapping (no location lookups resolved).")

    else:
        st.info("No alert data available. Start local sensor or fetch from OTX/Supabase.")

    # Live Supabase peek
    if supabase:
        try:
            st.subheader("📡 Live Supabase Data")
            response = supabase.table("alerts").select("*").limit(100).execute()
            if response.data:
                live_df = pd.DataFrame(response.data)
                st.metric("Live Alerts in Database", len(live_df))
                with st.expander("View Recent Alerts from Database"):
                    st.dataframe(live_df.head(10), use_container_width=True)
            else:
                st.info("No alerts found in Supabase database.")
        except Exception as e:
            st.error(f"Error fetching Supabase data: {e}")

# Alerts page (table view)
elif page == "Alerts":
    st.subheader("🔎 Alerts")
    alerts_list = st.session_state.get("alerts_data", []) or fetch_recent_alerts_from_supabase(limit=200)
    if alerts_list:
        df = pd.DataFrame(alerts_list)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        st.dataframe(df.sort_values("timestamp", ascending=False).head(500), use_container_width=True)
    else:
        st.info("No alerts collected yet. Start local sensor or fetch from OTX/Supabase.")

# Reports
elif page == "Reports":
    st.subheader("📝 Threat Intelligence Reports")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📊 Data Export")
        df = pd.DataFrame(st.session_state.get("alerts_data", []) or [])
        st.download_button(
            "⬇️ Download Alerts CSV",
            df.to_csv(index=False),
            file_name=f"threat_alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    with col2:
        st.markdown("### 📄 PDF Report")
        st.markdown("Generate comprehensive threat report")
    st.markdown("---")
    notes = st.text_area("Analyst notes", placeholder="Write notes...", height=150)
    if st.button("📄 Generate PDF report"):
        with st.spinner("Generating..."):
            try:
                from dashboard.utils.report_generator import generate_report
                pdf_path = generate_report(
                    alerts=st.session_state.get("alerts_data", []),
                    notes=notes,
                    analyst_name=st.session_state.get("user_name", "Analyst"),
                    logo_path=app.logo_path,
                    signature_path=app.signature_path
                )
                with open(pdf_path, "rb") as f:
                    st.download_button("⬇️ Download PDF", f, file_name=os.path.basename(pdf_path), mime="application/pdf")
            except Exception as e:
                st.error(f"Report generation failed: {e}")

# Settings
elif page == "Settings":
    st.subheader("⚙️ Settings")
    st.markdown("Configure app behaviour")
    st.write("Current refresh (sec):", refresh_seconds)
    st.checkbox("Enable OTX collection", value=True)
    st.markdown("Add more integration toggles here.")

# Footer
st.markdown("---")
st.markdown("<div style='text-align:center; color:#4b636e;'>CyberThreatWatch • Real-time Threat Intelligence Dashboard</div>", unsafe_allow_html=True)
