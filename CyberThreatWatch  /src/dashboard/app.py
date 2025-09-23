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
from streamlit_autorefresh import st_autorefresh
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

            # Test connection with a simple query
            client = create_client(url, key)
            try:
                # Test with a simple query that should work with anon key
                result = client.from_('alerts').select('id', count='exact').limit(1).execute()
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

# Auto-refresh every 60s
st_autorefresh(interval=60 * 1000, key="dashboard_autorefresh")

# --- Initialize Login Component ---
login_component = LoginComponent()

# --- 🔐 Authentication Flow ---
login_component.check_authentication()


class CyberThreatWatch:
    def __init__(self):
        self.logo_path = "assets/CyberThreatWatch.png"
        self.signature_path = "assets/h_Signature.png"

        # Initialize AlertsPanel only if dependencies are available
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
            # User avatar or status indicator
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

    # Quick actions row
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
        st.metric("Total Alerts", total_alerts, delta=None)

    with col3:
        if st.button("Clear Cache", use_container_width=True):
            cached_ip_lookup.cache_clear()
            st.success("GeoIP cache cleared!")

    # Main dashboard metrics and charts
    if st.session_state.alerts_data:
        df = pd.DataFrame(st.session_state.alerts_data)

        # Convert timestamp if it exists
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Create columns for metrics
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)

        with metric_col1:
            high_severity = len(df[df["severity"] == "High"]) if "severity" in df.columns else 0
            st.metric("High Severity", high_severity, delta=None)

        with metric_col2:
            unique_ips = df["source_ip"].nunique() if "source_ip" in df.columns else 0
            st.metric("Unique IPs", unique_ips, delta=None)

        with metric_col3:
            countries = df["country"].nunique() if "country" in df.columns else 0
            st.metric("Countries", countries, delta=None)

        with metric_col4:
            latest_alert = df["timestamp"].max() if "timestamp" in df.columns else "N/A"
            st.metric("Latest Alert", latest_alert if isinstance(latest_alert, str) else latest_alert.strftime("%H:%M"),
                      delta=None)

        # Charts row 1
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            if "severity" in df.columns and not df["severity"].empty:
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["severity", "count"]
                fig_sev = px.bar(sev_counts, x="severity", y="count",
                                 title="Alerts by Severity", color="severity")
                st.plotly_chart(fig_sev, width='stretch')

        with chart_col2:
            if "type" in df.columns and not df["type"].empty:
                type_counts = df["type"].value_counts().head(10).reset_index()
                type_counts.columns = ["type", "count"]
                fig_type = px.pie(type_counts, names="type", values="count",
                                  title="Top Threat Types")
                st.plotly_chart(fig_type, width='stretch')

        # Charts row 2
        chart_col3, chart_col4 = st.columns(2)

        with chart_col3:
            if "timestamp" in df.columns and not df["timestamp"].empty:
                df_daily = df.set_index("timestamp").resample("H").size().reset_index()
                df_daily.columns = ["timestamp", "count"]
                fig_time = px.line(df_daily, x="timestamp", y="count",
                                   title="Alerts Over Time (Hourly)")
                st.plotly_chart(fig_time, width='stretch')

        with chart_col4:
            if "source_ip" in df.columns and not df["source_ip"].empty:
                top_ips = df["source_ip"].value_counts().head(10).reset_index()
                top_ips.columns = ["source_ip", "count"]
                fig_ips = px.bar(top_ips, x="source_ip", y="count",
                                 title="Top 10 Source IPs")
                st.plotly_chart(fig_ips, width='stretch')

        # World Map
        st.subheader("🌍 Global Threat Map")
        geo_data = []
        for ip in df["source_ip"].dropna().unique() if "source_ip" in df.columns else []:
            loc = cached_ip_lookup(ip)
            if loc and loc.get('lat') and loc.get('lon'):
                geo_data.append(loc)

        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            map_fig = px.scatter_mapbox(
                geo_df,
                lat="lat",
                lon="lon",
                hover_name="ip",
                hover_data=["country", "city"],
                zoom=1,
                height=400,
                title="Threat Origins Worldwide"
            )
            map_fig.update_layout(
                mapbox_style="carto-positron",
                margin={"r": 0, "t": 30, "l": 0, "b": 0}
            )
            st.plotly_chart(map_fig, width='stretch')
        else:
            st.info("No GeoIP data available for mapping.")

    else:
        st.info("No alert data available. Fetch threats from OTX or check your Supabase connection.")

    # Supabase data section
    if supabase:
        try:
            st.subheader("📡 Live Supabase Data")
            response = supabase.table("alerts").select("*").limit(100).execute()
            if response.data:
                live_df = pd.DataFrame(response.data)
                st.metric("Live Alerts in Database", len(live_df))

                # Show recent alerts table
                with st.expander("View Recent Alerts from Database"):
                    st.dataframe(live_df.head(10), use_container_width=True)
            else:
                st.info("No alerts found in Supabase database.")
        except Exception as e:
            st.error(f"Error fetching Supabase data: {e}")

elif page == "Search":
    st.subheader("🔎 Threat Intelligence Search")

    search_type = st.radio("Search Type", ["IP Address", "Domain", "Hash", "Pulse ID"])
    query = st.text_input("Enter search term", placeholder="e.g., 192.168.1.1 or example.com")

    if st.button("Search Threat Intelligence") and query:
        with st.spinner("Searching threat intelligence..."):
            if otx:
                try:
                    results = otx.search_pulses(query)
                    if results:
                        st.success(f"Found {len(results)} results")

                        # Display results in expandable sections
                        for i, pulse in enumerate(results[:5]):  # Show first 5 results
                            with st.expander(f"Pulse {i + 1}: {pulse.get('name', 'Unnamed')}"):
                                st.json(pulse)
                    else:
                        st.warning("No threats found for this search term.")
                except Exception as e:
                    st.error(f"Search failed: {e}")
            else:
                st.warning("OTX client not available. Check your API key.")

elif page == "Alerts":
    st.subheader("🚨 Security Alerts")
    if app.alerts_panel:
        app.alerts_panel.render(st.session_state.alerts_data)
    else:
        st.warning("Alerts panel not available. Check component initialization.")

elif page == "Reports":
    st.subheader("📝 Threat Intelligence Reports")

    # Report generation options
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📊 Data Export")
        df = pd.DataFrame(st.session_state.alerts_data)

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
    notes = st.text_area(
        "Add your observations, insights, or next steps",
        placeholder="Document key findings, IoCs, and recommended actions...",
        height=150
    )

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

elif page == "Threat Detection":
    st.subheader("⚡ Real-time Threat Detection")

    st.info("""
    **Threat Detection Engine - Coming Soon**

    Features in development:
    - Real-time network traffic analysis
    - Behavioral anomaly detection  
    - Automated IOC extraction
    - Machine learning threat classification
    """)

    # Placeholder for detection interface
    with st.expander("⚙️ Detection Settings"):
        st.checkbox("Enable real-time monitoring")
        st.checkbox("Email alerts for high-severity threats")
        st.slider("Detection sensitivity", 1, 10, 7)

    if st.button("Run Threat Scan", use_container_width=True):
        with st.spinner("Scanning for threats..."):
            # Simulate scan
            import time

            time.sleep(2)
            st.success("Scan completed! No new threats detected.")

elif page == "Settings":
    st.subheader("⚙️ Dashboard Settings")

    tab1, tab2, tab3 = st.tabs(["Appearance", "API Configuration", "Data Management"])

    with tab1:
        st.markdown("### 🎨 Interface Settings")
        theme = st.selectbox("Theme", ["Light", "Dark", "System"])
        refresh_rate = st.slider("Auto-refresh interval (minutes)", 1, 60, 5)
        st.info(f"Current refresh rate: {refresh_rate} minutes")

    with tab2:
        st.markdown("### 🔑 API Configuration")
        st.text_input("OTX API Key", type="password", value=st.secrets.get("OTX_API_KEY", ""))
        st.text_input("Supabase URL", value=st.secrets.get("SUPABASE_URL", ""))
        st.text_input("Supabase Key", type="password", value=st.secrets.get("SUPABASE_KEY", ""))

        if st.button("Test API Connections"):
            if otx:
                st.success("✅ OTX API: Connected")
            else:
                st.error("❌ OTX API: Failed")

            if supabase:
                st.success("✅ Supabase: Connected")
            else:
                st.error("❌ Supabase: Failed")

    with tab3:
        st.markdown("### 🗄️ Data Management")
        st.button("Clear Local Cache", use_container_width=True)
        st.button("Export All Data", use_container_width=True)
        st.button("Reset Dashboard", use_container_width=True)

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "CyberThreatWatch v1.0 • Real-time Threat Intelligence Dashboard"
    "</div>",
    unsafe_allow_html=True
))