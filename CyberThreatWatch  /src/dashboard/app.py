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

# Add parent directory for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import custom components
from dashboard.components.alerts_panel import AlertsPanel
from dashboard.components.login import LoginComponent
from dashboard.utils.otx_collector import collect_otx_alerts
from dashboard.utils.geoip_helper import ip_to_location

# Logging setup
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

            client = create_client(url, key)
            try:
                result = client.table("alerts").select("id", count="exact").limit(1).execute()
                logger.info("Supabase connection successful")
            except Exception as query_error:
                logger.warning(f"Supabase query test failed (may be normal): {query_error}")

            return client
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
    st.session_state.alerts_data = [
        {
            "id": 1,
            "timestamp": datetime.now() - timedelta(hours=2),
            "severity": "High",
            "type": "Malware Detection",
            "source_ip": "192.168.1.100",
            "description": "Suspicious executable detected",
            "country": "Unknown",
            "lat": 0,
            "lon": 0
        }
    ]

if "threat_data" not in st.session_state:
    st.session_state.threat_data = []

# --- Main Config ---
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- Initialize Login Component ---
login_component = LoginComponent()

# --- 🔐 Authentication Flow ---
login_component.check_authentication()


class CyberThreatWatch:
    def __init__(self):
        self.logo_path = "assets/CyberThreatWatch.png"
        self.signature_path = "assets/h_Signature.png"

        try:
            self.alerts_panel = AlertsPanel(supabase=supabase, otx=otx)
        except Exception as e:
            logger.warning(f"AlertsPanel initialization failed: {e}")
            self.alerts_panel = None

    def load_image(self, path, width=None):
        try:
            if os.path.exists(path):
                img = Image.open(path)
                if width:
                    img = img.resize((width, int(img.height * width / img.width)))
                return img
            return None
        except Exception as e:
            logger.error(f"Image load error ({path}): {e}")
            return None

    def render_header(self):
        col1, col2, col3 = st.columns([1, 3, 1])
        with col1:
            logo = self.load_image(self.logo_path, width=100)
            if logo:
                st.image(logo, width=100)
        with col2:
            st.title("🛡️ CyberThreatWatch")
            user_name = st.session_state.get("user_name", "User")
            st.markdown(f"Real-time Threat Intelligence Dashboard · Welcome, **{user_name}**!")
        with col3:
            if st.session_state.get("user_picture"):
                st.image(st.session_state.user_picture, width=50)
            else:
                st.markdown(f"🔐 *Authenticated*")

        st.markdown("---")


# --- Display User Info and Logout in Sidebar ---
login_component.render_logout_section()

# --- Sidebar Navigation ---
st.sidebar.markdown("## 🧭 Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Dashboard", "Search", "Alerts", "Reports", "Threat Detection", "Settings"],
    label_visibility="collapsed"
)

# Initialize main app
app = CyberThreatWatch()
app.render_header()


# ----------------------------------------------------------------
# 🧠 LOCAL SENSOR + REAL-TIME STREAM INTEGRATION
# ----------------------------------------------------------------
from dashboard.services.sensor import start_sensor, stop_sensor
from dashboard.services.data_service import data_stream

st.sidebar.subheader("🧠 Local Sensor")
if st.sidebar.toggle("Enable Local Sensor"):
    start_sensor()
else:
    stop_sensor()

# --- Real-time auto-update using Supabase + Streamlit rerun ---
if "latest_alerts" not in st.session_state:
    st.session_state["latest_alerts"] = []

def update_dashboard(data):
    """Update session state and rerun the dashboard when new data arrives."""
    st.session_state["latest_alerts"] = data
    st.experimental_rerun()

if not st.session_state.get("realtime_active"):
    try:
        data_stream.start_realtime()
        data_stream.subscribe(update_dashboard)
        st.session_state["realtime_active"] = True
        st.sidebar.success("✅ Real-time data stream active")
    except Exception as e:
        st.sidebar.error(f"⚠️ Real-time stream error: {e}")
# ----------------------------------------------------------------


# --- GeoIP cache ---
@lru_cache(maxsize=5000)
def cached_ip_lookup(ip):
    try:
        return ip_to_location(ip)
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None


# --- Pages ---
if page == "Dashboard":
    st.subheader("📊 Dashboard Overview")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔄 Fetch OTX Threats", use_container_width=True):
            if otx and supabase:
                try:
                    new_alerts = collect_otx_alerts(otx, supabase)
                    st.success(f"Fetched {len(new_alerts) if new_alerts else 0} new alerts!")
                except Exception as e:
                    st.error(f"Failed to fetch OTX alerts: {e}")
            else:
                st.warning("OTX or Supabase not configured")

    with col2:
        total_alerts = len(st.session_state.alerts_data)
        st.metric("Total Alerts", total_alerts)

    with col3:
        if st.button("Clear Cache", use_container_width=True):
            cached_ip_lookup.cache_clear()
            st.success("GeoIP cache cleared!")

    if st.session_state.alerts_data:
        df = pd.DataFrame(st.session_state.alerts_data)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        with metric_col1:
            st.metric("High Severity", len(df[df["severity"] == "High"]) if "severity" in df.columns else 0)
        with metric_col2:
            st.metric("Unique IPs", df["source_ip"].nunique() if "source_ip" in df.columns else 0)
        with metric_col3:
            st.metric("Countries", df["country"].nunique() if "country" in df.columns else 0)
        with metric_col4:
            latest_alert = df["timestamp"].max() if "timestamp" in df.columns else "N/A"
            st.metric("Latest Alert", latest_alert.strftime("%H:%M") if not isinstance(latest_alert, str) else latest_alert)

        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            if "severity" in df.columns and not df["severity"].empty:
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["severity", "count"]
                fig_sev = px.bar(sev_counts, x="severity", y="count", title="Alerts by Severity", color="severity")
                st.plotly_chart(fig_sev, use_container_width=True)
        with chart_col2:
            if "type" in df.columns and not df["type"].empty:
                type_counts = df["type"].value_counts().head(10).reset_index()
                type_counts.columns = ["type", "count"]
                fig_type = px.pie(type_counts, names="type", values="count", title="Top Threat Types")
                st.plotly_chart(fig_type, use_container_width=True)

        chart_col3, chart_col4 = st.columns(2)
        with chart_col3:
            if "timestamp" in df.columns and not df["timestamp"].empty:
                df_daily = df.set_index("timestamp").resample("H").size().reset_index()
                df_daily.columns = ["timestamp", "count"]
                fig_time = px.line(df_daily, x="timestamp", y="count", title="Alerts Over Time (Hourly)")
                st.plotly_chart(fig_time, use_container_width=True)
        with chart_col4:
            if "source_ip" in df.columns and not df["source_ip"].empty:
                top_ips = df["source_ip"].value_counts().head(10).reset_index()
                top_ips.columns = ["source_ip", "count"]
                fig_ips = px.bar(top_ips, x="source_ip", y="count", title="Top 10 Source IPs")
                st.plotly_chart(fig_ips, use_container_width=True)

        st.subheader("🌍 Global Threat Map")
        geo_data = []
        for ip in df["source_ip"].dropna().unique() if "source_ip" in df.columns else []:
            loc = cached_ip_lookup(ip)
            if loc and loc.get("lat") and loc.get("lon"):
                geo_data.append(loc)

        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            map_fig = px.scatter_mapbox(
                geo_df, lat="lat", lon="lon", hover_name="ip", hover_data=["country", "city"],
                zoom=1, height=400, title="Threat Origins Worldwide"
            )
            map_fig.update_layout(mapbox_style="carto-positron", margin={"r": 0, "t": 30, "l": 0, "b": 0})
            st.plotly_chart(map_fig, use_container_width=True)
        else:
            st.info("No GeoIP data available for mapping.")
    else:
        st.info("No alert data available. Fetch threats from OTX or check your Supabase connection.")

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

elif page == "Reports":
    st.subheader("📝 Threat Intelligence Reports")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 📊 Data Export")
        df = pd.DataFrame(st.session_state.alerts_data or [])
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
    st.markdown("### 📋 Analyst Notes")
    notes = st.text_area("Add your observations, insights, or next steps",
                         placeholder="Document key findings, IoCs, and recommended actions...", height=150)

    if st.button("📄 Generate Comprehensive PDF Report", use_container_width=True):
        with st.spinner("Generating PDF report..."):
            try:
                from dashboard.utils.report_generator import generate_report
                pdf_path = generate_report(
                    alerts=st.session_state.alerts_data,
                    notes=notes,
                    analyst_name=st.session_state.user_name,
                    logo_path=app.logo_path,
                    signature_path=app.signature_path
                )
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        "⬇️ Download PDF Report",
                        f,
                        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "CyberThreatWatch v1.0 • Real-time Threat Intelligence Dashboard"
    "</div>", unsafe_allow_html=True
)
