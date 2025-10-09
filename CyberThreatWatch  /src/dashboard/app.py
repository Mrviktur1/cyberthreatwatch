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

# Load .env if present
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
                result = client.table("alerts").select("id", count="exact").limit(1).execute()
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

# --- Session defaults ---
if "alerts_data" not in st.session_state:
    st.session_state.alerts_data = []
if "latest_alerts" not in st.session_state:
    st.session_state.latest_alerts = []
if "realtime_active" not in st.session_state:
    st.session_state.realtime_active = False
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
if "agent_pid" not in st.session_state:
    st.session_state.agent_pid = None

# --- Page config ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- Visual theme (lighter professional) ---
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

# Optional header animation (if installed)
try:
    from streamlit_lottie import st_lottie
    import requests
    def load_lottie(url):
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
        return None
    lottie_small = load_lottie("https://assets8.lottiefiles.com/packages/lf20_vf2twv.json")
except Exception:
    st_lottie = None
    lottie_small = None

# --- Auth component ---
login_component = LoginComponent()
login_component.check_authentication()

# App helper for header and images
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

# Display logout section
login_component.render_logout_section()

# Sidebar UI controls
st.sidebar.markdown("## 🧭 Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Search", "Alerts", "Reports", "Threat Detection", "Settings"], label_visibility="collapsed")

# Local sensor controls
st.sidebar.markdown("## 🧠 Local Sensor")
sensor_toggle = st.sidebar.toggle("Enable Local Sensor", value=False)
if sensor_toggle:
    try:
        start_sensor()
        st.sidebar.success("Sensor requested to start")
    except Exception as e:
        st.sidebar.error("Failed to start sensor")
else:
    try:
        stop_sensor()
    except Exception:
        pass

# Refresh interval
refresh_seconds = st.sidebar.slider("Refresh interval (sec)", 5, 120, 15, step=5)

# ------------------------
# Agent installer UI & helpers
# ------------------------
AGENT_DIR = os.path.join(os.path.expanduser("~"), ".cyberthreatwatch")
AGENT_FILE = os.path.join(AGENT_DIR, "cyberthreatwatch_agent_installer.py")
AGENT_PID_FILE = os.path.join(AGENT_DIR, "agent.pid")
CONSENT_LOCAL_FILE = os.path.join(AGENT_DIR, "consent.json")

def write_agent_file(source: str):
    os.makedirs(AGENT_DIR, exist_ok=True)
    with open(AGENT_FILE, "w", encoding="utf-8") as f:
        f.write(source)
    try:
        if platform.system().lower() != "windows":
            os.chmod(AGENT_FILE, 0o755)
    except Exception:
        pass

def start_agent(detach=True, interval=60, env=None):
    if not os.path.exists(AGENT_FILE):
        raise FileNotFoundError("Agent not installed. Please write agent first.")
    cmd = [sys.executable, AGENT_FILE, "--interval", str(interval)]
    proc_env = os.environ.copy()
    if env:
        proc_env.update({k: v for k, v in env.items() if v})
    if platform.system().lower() == "windows":
        CREATE_NO_WINDOW = 0x08000000
        p = subprocess.Popen(cmd, env=proc_env, creationflags=CREATE_NO_WINDOW)
    else:
        p = subprocess.Popen(cmd, env=proc_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setpgrp)
    # write PID file
    try:
        with open(AGENT_PID_FILE, "w") as pf:
            pf.write(str(p.pid))
    except Exception:
        pass
    st.session_state["agent_pid"] = p.pid
    return p

def stop_agent():
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
    try:
        os.kill(pid, 0)
        return {"running": True, "pid": pid}
    except Exception:
        return {"running": False, "pid": pid}

# Consent helpers
def save_local_consent(record: dict):
    os.makedirs(AGENT_DIR, exist_ok=True)
    # append to local consent file
    try:
        existing = []
        if os.path.exists(CONSENT_LOCAL_FILE):
            with open(CONSENT_LOCAL_FILE, "r") as f:
                existing = json.load(f)
        existing.append(record)
        with open(CONSENT_LOCAL_FILE, "w") as f:
            json.dump(existing, f)
    except Exception as e:
        logger.error(f"Failed to write local consent: {e}")

def upload_consent_to_supabase(record: dict):
    if not supabase:
        logger.warning("Supabase not configured; consent will be kept local only.")
        return False
    try:
        # Save to a consents table (create table in Supabase: consents)
        res = supabase.table("consents").insert(record).execute()
        if getattr(res, "error", None):
            logger.error(f"Supabase consent insert error: {res.error}")
            return False
        return True
    except Exception as e:
        logger.error(f"Consent upload failed: {e}")
        return False

# Sidebar - Installer UI
st.sidebar.markdown("## 🧩 Local Agent Installer")
st.sidebar.markdown("---")
st.sidebar.write("This agent collects security-related system logs and uploads them to your private CyberThreatWatch dashboard.")
st.sidebar.write("Consent is required. A record will be saved to the server for audit purposes (so CyberThreatWatch can prove consent if needed).")

# Show legal text immediately and ask for decision
st.sidebar.markdown("**Legal Consent**")
st.sidebar.markdown(
    "By clicking **I AGREE** you consent to install a local agent that will collect security-related "
    "system logs from this machine and upload them to your CyberThreatWatch project. The logs are tied "
    "to your user account in the dashboard. If you do not agree, the agent will not be installed."
)

col_a, col_b = st.sidebar.columns([1,1])
agree_clicked = False
decline_clicked = False

with col_a:
    if st.button("I AGREE ✅", use_container_width=True):
        agree_clicked = True
with col_b:
    if st.button("I DO NOT AGREE ❌", use_container_width=True):
        decline_clicked = True

if decline_clicked:
    st.sidebar.warning("You chose not to install the agent. You can install later from this panel.")
    # show cancel button / nothing else

if agree_clicked:
    # Build consent record
    user_email = st.session_state.get("user_email", "unknown")
    user_name = st.session_state.get("user_name", "unknown")
    machine = platform.node()
    consent = {
        "user_email": user_email,
        "user_name": user_name,
        "machine": machine,
        "timestamp": datetime.utcnow().isoformat(),
        "agent_version": "1.0",
        "notes": "Consented via dashboard installer UI"
    }
    # Save local copy
    save_local_consent(consent)
    # Upload to Supabase for audits
    uploaded = upload_consent_to_supabase(consent)
    if uploaded:
        st.sidebar.success("Consent recorded to server (audit). Proceeding to install.")
    else:
        st.sidebar.info("Consent recorded locally. Proceeding to install.")

    # Write agent file (use the installer script content — below we include a short agent template that downloads the real agent)
    # For simplicity we will write the full agent code (the long agent script saved earlier) to AGENT_FILE.
    # For maintainability you may pull the trusted agent from your repo or signed URL.
    try:
        # Read agent source bundled with the dashboard repo (tools folder) if present
        repo_agent_path = os.path.join(os.path.dirname(__file__), "..", "tools", "cyberthreatwatch_agent_installer.py")
        if os.path.exists(repo_agent_path):
            with open(repo_agent_path, "r", encoding="utf-8") as f:
                agent_source = f.read()
        else:
            # minimal safe agent stub: it will call send_logs_to_supabase by invoking a local helper (this is fallback)
            agent_source = f"""#!/usr/bin/env python3
import time, os, sys, json, platform
from datetime import datetime
# Minimal agent stub: prints a test line every interval. Replace with the production agent.
interval = int(sys.argv[1]) if len(sys.argv) > 1 else 60
while True:
    print('CyberThreatWatch local agent running on', platform.node(), 'at', datetime.utcnow().isoformat())
    time.sleep(interval)
"""
        write_agent_file(agent_source)
        st.sidebar.success("Agent installer written to machine.")
    except Exception as e:
        st.sidebar.error(f"Failed to write agent: {e}")

    # Ask user to start agent now
    if st.sidebar.button("▶️ Start agent now (local)"):
        try:
            env = {"SUPABASE_URL": st.secrets.get("SUPABASE_URL"), "SUPABASE_KEY": st.secrets.get("SUPABASE_KEY")}
            interval_val = st.sidebar.number_input("Agent interval (s)", min_value=10, max_value=3600, value=60, key="agent_interval")
            proc = start_agent(detach=True, interval=interval_val, env=env)
            st.sidebar.success(f"Agent started (pid {proc.pid})")
        except Exception as e:
            st.sidebar.error(f"Failed to start agent: {e}")

# Agent management quick controls
if st.sidebar.button("⛔ Stop agent (local)"):
    ok = stop_agent()
    if ok:
        st.sidebar.success("Agent stopped")
    else:
        st.sidebar.warning("Agent not running or could not be stopped")

st.sidebar.write("Agent status:", agent_status())

# -------------------------
# Instantiate app and header
# -------------------------
app = CyberThreatWatch()
app.render_header()

# -------------------------
# Realtime data wiring
# -------------------------
def update_dashboard_from_stream(data):
    try:
        st.session_state["latest_alerts"] = data or []
        if data:
            st.session_state["alerts_data"] = data
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

@lru_cache(maxsize=5000)
def cached_ip_lookup(ip):
    try:
        return ip_to_location(ip)
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None

def emergency_indicator(alerts):
    try:
        for a in alerts or []:
            sev = (a.get("severity") or "").lower() if isinstance(a, dict) else ""
            if sev in ("high", "critical"):
                return True
    except Exception:
        pass
    return False

def fetch_recent_alerts_from_supabase(limit=100):
    if not supabase:
        return []
    try:
        res = supabase.table("alerts").select("*").order("timestamp", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"Supabase fetch error: {e}")
        return []

# Auto-refresh by refresh_seconds
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

    col_a, col_b, col_c = st.columns([1.4, 1, 1])
    with col_a:
        if st.button("🔄 Fetch OTX Threats", use_container_width=True):
            if otx and supabase:
                try:
                    new_alerts = collect_otx_alerts(otx, supabase)
                    st.success(f"Fetched {len(new_alerts) if new_alerts else 0} new alerts")
                except Exception as e:
                    st.error(f"OTX fetch error: {e}")
            else:
                st.warning("OTX or Supabase not configured")
        if st.button("Clear GeoIP cache", use_container_width=True):
            try:
                cached_ip_lookup.cache_clear()
                st.success("GeoIP cache cleared")
            except Exception:
                pass

    with col_b:
        total_alerts = len(st.session_state.get("alerts_data", []) or fetch_recent_alerts_from_supabase(limit=50))
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Alerts", total_alerts)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_c:
        high = emergency_indicator(st.session_state.get("alerts_data", []) or [])
        st.markdown("### ⚠️ Emergency")
        if high:
            st.markdown("<div style='color:#b00020; font-weight:700;'>High severity detected — check Alerts</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style='color:#0a6; font-weight:700;'>All clear</div>", unsafe_allow_html=True)

    alerts_list = st.session_state.get("alerts_data", []) or fetch_recent_alerts_from_supabase(limit=50)
    df = pd.DataFrame(alerts_list) if alerts_list else pd.DataFrame()

    if not df.empty:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

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

        try:
            if "timestamp" in df.columns and not df["timestamp"].empty:
                df_time = df.set_index("timestamp").resample("H").size().reset_index(name="count")
                fig = px.line(df_time, x="timestamp", y="count", title="Alerts Over Time (Hourly)")
                st.plotly_chart(fig, use_container_width=True)
        except Exception as e:
            logger.error(f"Time series: {e}")

        st.subheader("🌍 Global Threat Map")
        geo_data = []
        for ip in df["source_ip"].dropna().unique() if "source_ip" in df.columns else []:
            loc = cached_ip_lookup(ip)
            if loc and loc.get("lat") and loc.get("lon"):
                geo_data.append({"ip": ip, "lat": loc["lat"], "lon": loc["lon"], "country": loc.get("country"), "city": loc.get("city")})
        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            map_fig = px.scatter_mapbox(geo_df, lat="lat", lon="lon", hover_name="ip", hover_data=["country","city"], zoom=1, height=420)
            map_fig.update_layout(mapbox_style="carto-positron", margin={"r":0,"t":30,"l":0,"b":0})
            st.plotly_chart(map_fig, use_container_width=True)
        else:
            st.info("No GeoIP data available for mapping (no resolved locations).")
    else:
        st.info("No alert data available. Start local sensor or fetch OTX/Supabase.")

    if supabase:
        try:
            st.subheader("📡 Live Supabase Data")
            resp = supabase.table("alerts").select("*").limit(100).execute()
            if resp.data:
                live_df = pd.DataFrame(resp.data)
                st.metric("Live Alerts in Database", len(live_df))
                with st.expander("View Recent Alerts from Database"):
                    st.dataframe(live_df.head(10), use_column_width=True)
            else:
                st.info("No alerts found in Supabase database.")
        except Exception as e:
            st.error(f"Error fetching Supabase data: {e}")

# Alerts page
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

# Reports page
elif page == "Reports":
    st.subheader("📝 Threat Intelligence Reports")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📊 Data Export")
        df = pd.DataFrame(st.session_state.get("alerts_data", []) or [])
        st.download_button("⬇️ Download Alerts CSV", df.to_csv(index=False), file_name=f"threat_alerts_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
    with col2:
        st.markdown("### 📄 PDF Report")
        st.markdown("Generate comprehensive threat report")
    st.markdown("---")
    notes = st.text_area("Analyst notes", placeholder="Write notes...", height=150)
    if st.button("📄 Generate PDF report"):
        with st.spinner("Generating..."):
            try:
                from dashboard.utils.report_generator import generate_report
                pdf_path = generate_report(alerts=st.session_state.get("alerts_data", []), notes=notes, analyst_name=st.session_state.get("user_name","Analyst"), logo_path=app.logo_path, signature_path=app.signature_path)
                with open(pdf_path, "rb") as f:
                    st.download_button("⬇️ Download PDF", f, file_name=os.path.basename(pdf_path), mime="application/pdf")
            except Exception as e:
                st.error(f"Report generation failed: {e}")

# Settings page
elif page == "Settings":
    st.subheader("⚙️ Settings")
    st.write("Refresh (sec):", refresh_seconds)
    st.checkbox("Enable OTX collection", value=True)
    st.markdown("More settings coming soon.")

# Small consent audit view (admin)
if st.sidebar.checkbox("Show consent audit (admin)", value=False):
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Consent audit**")
    if supabase:
        try:
            cons = supabase.table("consents").select("*").order("timestamp", desc=True).limit(200).execute()
            rows = cons.data or []
            st.sidebar.write(f"Found {len(rows)} consent records")
            if rows:
                st.sidebar.dataframe(pd.DataFrame(rows).head(20))
        except Exception as e:
            st.sidebar.error(f"Failed to load consents: {e}")
    else:
        st.sidebar.info("Supabase not configured; only local consent file available.")
        if os.path.exists(CONSENT_LOCAL_FILE):
            try:
                with open(CONSENT_LOCAL_FILE, "r") as f:
                    local_cons = json.load(f)
                st.sidebar.write(f"Local consent records: {len(local_cons)}")
                if local_cons:
                    st.sidebar.dataframe(pd.DataFrame(local_cons).head(20))
            except Exception as e:
                st.sidebar.error(f"Failed to read local consent: {e}")

# Footer
st.markdown("---")
st.markdown('<div style="text-align:center; color:#4b636e;">CyberThreatWatch • Real-time Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
