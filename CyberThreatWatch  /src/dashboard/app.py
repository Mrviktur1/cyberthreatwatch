import streamlit as st
import sys
import os
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
from supabase import create_client, Client
import requests
from OTXv2 import OTXv2
import OTXv2
from dotenv import load_dotenv
import json
from typing import Dict, List, Optional, Any
import logging
from PIL import Image

# Add the src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import your detection functions from the correct location
try:
    from dashboard.components.detection import ioc_match, brute_force, looks_like_phishing, impossible_travel, dns_tunnel_detection, honeytoken_access, run_all_detections
    DETECTIONS_AVAILABLE = True
    logger.info("Successfully imported detection functions from dashboard.components.detection")
except ImportError as e:
    logger.warning(f"Detection functions import error: {e}")
    # Fallback: try to import from detections.py in same directory
    try:
        from detections import ioc_match, brute_force, looks_like_phishing, impossible_travel, dns_tunnel_detection, honeytoken_access, run_all_detections
        DETECTIONS_AVAILABLE = True
        logger.info("Successfully imported detection functions from local detections.py")
    except ImportError:
        logger.warning("Detection functions not available. Please ensure detection.py exists.")
        DETECTIONS_AVAILABLE = False

# Import auth component
try:
    from components import auth
    AUTH_AVAILABLE = True
except ImportError:
    logger.warning("Auth component not found. Using fallback authentication.")
    AUTH_AVAILABLE = False

# --- Supabase Client ---
@st.cache_resource
def init_supabase() -> Client:
    """Initialize Supabase connection"""
    try:
        if 'SUPABASE_URL' in st.secrets and 'SUPABASE_KEY' in st.secrets:
            url: str = st.secrets["SUPABASE_URL"]
            key: str = st.secrets["SUPABASE_KEY"]
            supabase_client = create_client(url, key)
            logger.info("Supabase connected successfully")
            return supabase_client
        else:
            logger.warning("Supabase secrets not found in Streamlit secrets")
            return None
    except Exception as e:
        logger.error(f"Supabase connection error: {e}")
        return None

# Initialize Supabase
supabase = init_supabase()

# --- Fallback Auth Functions ---
def fallback_login(email: str, password: str):
    """Fallback login for testing"""
    if email == "admin@cyberthreatwatch.com" and password == "admin123":
        st.session_state["user"] = {"email": email, "role": "admin"}
        st.session_state.authenticated = True
        st.success("✅ Login successful (fallback)")
        st.rerun()
    else:
        st.error("❌ Invalid credentials")

def fallback_signup(email: str, password: str):
    """Fallback signup for testing"""
    st.info("📧 Signup would send verification email in production")

def fallback_login_with_google():
    """Fallback Google login"""
    st.info("🔐 Google OAuth would redirect in production")

def fallback_reset_password(email: str):
    """Fallback password reset"""
    st.info("📧 Password reset email would be sent in production")

def fallback_logout():
    """Fallback logout"""
    st.session_state.pop("user", None)
    st.session_state.authenticated = False
    st.success("👋 Logged out successfully!")
    st.rerun()

# Set page config
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- Session check ---
if "user" not in st.session_state:
    # User not logged in → show login/signup page
    st.title("🔐 CyberThreatWatch Login Portal")

    menu = st.sidebar.radio(
        "Authentication",
        ["Login", "Signup", "Google Login", "Reset Password"]
    )

    if menu == "Login":
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if AUTH_AVAILABLE:
                auth.login(email, password)
            else:
                fallback_login(email, password)

    elif menu == "Signup":
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Sign Up"):
            if AUTH_AVAILABLE:
                auth.signup(email, password)
            else:
                fallback_signup(email, password)

    elif menu == "Google Login":
        if AUTH_AVAILABLE:
            auth.login_with_google()
        else:
            fallback_login_with_google()

    elif menu == "Reset Password":
        email = st.text_input("Enter your email")
        if st.button("Send Reset Link"):
            if AUTH_AVAILABLE:
                auth.reset_password(email)
            else:
                fallback_reset_password(email)

else:
    # User logged in → show main app
    st.sidebar.success(f"👋 Welcome {st.session_state['user'].email if hasattr(st.session_state['user'], 'email') else st.session_state['user']['email']}")

    if st.sidebar.button("Logout"):
        if AUTH_AVAILABLE:
            auth.logout()
        else:
            fallback_logout()
        st.rerun()

    # --- MAIN DASHBOARD ---
    class CyberThreatWatch:
        def __init__(self):
            # Set the correct paths to your assets folder
            self.logo_path = "assets/CyberThreatWatch.png"
            self.signature_path = "assets/h_Signa....png"
            
            # Initialize session state variables if not exists
            if 'alerts_data' not in st.session_state:
                st.session_state.alerts_data = []
            if 'threat_data' not in st.session_state:
                st.session_state.threat_data = []
            if 'detections' not in st.session_state:
                st.session_state.detections = []
            if 'detection_available' not in st.session_state:
                st.session_state.detection_available = DETECTIONS_AVAILABLE
            if 'detection_method' not in st.session_state:
                st.session_state.detection_method = "comprehensive"
            
            # Load sample data if not loaded
            if not st.session_state.alerts_data:
                self.load_sample_data()
            
            # Initialize geoip lookup
            self.geoip_lookup = self.simple_geoip_lookup
        
        def simple_geoip_lookup(self, ip):
            """Simple placeholder for geoip lookup"""
            geoip_mock_data = {
                "192.168.1.100": (40.7128, -74.0060),
                "10.0.0.50": (34.0522, -118.2437),
                "172.16.0.25": (51.5074, -0.1278),
            }
            return geoip_mock_data.get(ip, None)
        
        def load_image(self, path, width=None):
            """Safely load image with error handling"""
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
            """Render header"""
            col1, col2 = st.columns([1, 3])
            
            with col1:
                signature_image = self.load_image(self.signature_path, width=100)
                if signature_image:
                    st.image(signature_image, width=100)
                else:
                    logo_image = self.load_image(self.logo_path, width=100)
                    if logo_image:
                        st.image(logo_image, width=100)
            
            with col2:
                st.title("🛡️ CyberThreatWatch")
                st.markdown("Real-time Threat Intelligence Dashboard")
            
            st.markdown("---")
        
        def run_threat_detection(self):
            """Run threat detection algorithms"""
            if not supabase:
                st.error("❌ Supabase not connected. Please check your configuration.")
                return []
            
            if not st.session_state.detection_available:
                st.error("❌ Detection functions not available.")
                return []
            
            try:
                # Load events + IOCs
                with st.spinner("Loading events and IOCs from Supabase..."):
                    events_result = supabase.table("events").select("*").execute()
                    iocs_result = supabase.table("iocs").select("*").execute()
                    
                    events = events_result.data
                    iocs = iocs_result.data
                    
                    logger.info(f"Loaded {len(events)} events and {len(iocs)} IOCs")
                
                # Run detections based on selected method
                if st.session_state.detection_method.lower() == "comprehensive":
                    return self.run_comprehensive_detections(events, iocs)
                else:
                    return self.run_basic_detections(events, iocs)
                
            except Exception as e:
                logger.error(f"Threat detection error: {e}")
                st.error(f"Error running threat detection: {str(e)}")
                return []
        
        def run_basic_detections(self, events, iocs):
            """Run basic detection rules"""
            detections = []

            # IOC matching
            for e in events:
                result = ioc_match(e, iocs)
                if result:
                    detections.append(result)

            # Brute force rule
            brute_force_detections = brute_force(events)
            detections.extend(brute_force_detections)

            # Simple phishing heuristic
            for e in events:
                if e.get("domain") and looks_like_phishing(e["domain"]):
                    detections.append({
                        "title": "Suspicious Domain",
                        "event_id": e.get("id", "unknown"),
                        "severity": "medium",
                        "domain": e["domain"],
                        "timestamp": e.get("timestamp", datetime.now().isoformat()),
                        "description": "Domain matches phishing patterns"
                    })
            
            return detections
        
        def run_comprehensive_detections(self, events, iocs):
            """Run comprehensive detection rules"""
            all_detections = []

            # Use the run_all_detections function if available
            try:
                if 'run_all_detections' in globals():
                    all_detections = run_all_detections(events, iocs, self.geoip_lookup)
                    return all_detections
            except Exception as e:
                logger.warning(f"run_all_detections failed: {e}")
            
            # Fallback: run individual detection rules
            for e in events:
                result = ioc_match(e, iocs)
                if result:
                    all_detections.append(result)

            all_detections.extend(brute_force(events))

            # Other detection methods...
            for e in events:
                if e.get("domain") and looks_like_phishing(e["domain"]):
                    all_detections.append({
                        "title": "Suspicious Phishing Domain",
                        "event_id": e.get("id", "unknown"),
                        "severity": "medium",
                        "domain": e["domain"],
                        "timestamp": e.get("timestamp", datetime.now().isoformat()),
                        "description": "Domain matches phishing patterns",
                        "rule_id": "PHISH-001",
                        "technique": "T1566"
                    })
            
            return all_detections
        
        def render_threat_detection_page(self):
            """Render threat detection page"""
            st.header("🛡️ Real-time Threat Detection")
            
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.info("Run automated threat detection against your Supabase data.")
            
            with col2:
                detection_method = st.selectbox(
                    "Method", 
                    ["Basic", "Comprehensive"],
                    key="detection_method_select"
                )
                st.session_state.detection_method = detection_method.lower()
            
            with col3:
                if st.button("🔄 Run Detection", type="primary", use_container_width=True):
                    with st.spinner("Running threat detection..."):
                        st.session_state.detections = self.run_threat_detection()
            
            if st.session_state.detections:
                st.subheader(f"📋 Detection Results ({len(st.session_state.detections)} findings)")
                # Display detection results...
            else:
                st.info("👆 No detections found. Click 'Run Detection' to analyze your data.")
        
        def load_sample_data(self):
            """Load sample data for demonstration"""
            sample_alerts = [
                {
                    "id": 1, "timestamp": datetime.now() - timedelta(hours=2),
                    "severity": "High", "type": "Malware Detection",
                    "source_ip": "192.168.1.100", "description": "Suspicious executable detected"
                }
            ]
            
            sample_threats = [
                {
                    "indicator": "malicious-domain.com", "type": "domain",
                    "threat_score": 85, "first_seen": datetime.now() - timedelta(days=30),
                    "last_seen": datetime.now()
                }
            ]
            
            st.session_state.alerts_data = sample_alerts
            st.session_state.threat_data = sample_threats

    # --- Page Navigation ---
    page = st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Search", "Alerts", "Reports", "Threat Detection", "Settings"]
    )

    # Initialize the app
    app = CyberThreatWatch()
    app.render_header()

    if page == "Dashboard":
        st.subheader("📊 Dashboard")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", len(st.session_state.alerts_data))
        with col2:
            st.metric("Active Threats", len(st.session_state.threat_data))
        with col3:
            st.metric("Detections", len(st.session_state.detections))
        with col4:
            st.metric("System Status", "🟢 Online")
        
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Recent Alerts")
            for alert in st.session_state.alerts_data[:3]:
                st.write(f"**{alert.get('type')}** - {alert.get('source_ip')}")
        
        with col2:
            st.subheader("Latest Detections")
            for detection in st.session_state.detections[:3]:
                st.write(f"**{detection.get('title', 'Unknown')}**")

    elif page == "Search":
        st.subheader("🔍 Search Logs & Events")
        search_term = st.text_input("Search threats, alerts, or indicators")
        if search_term:
            st.write(f"Search functionality would search for: {search_term}")

    elif page == "Alerts":
        st.subheader("🚨 Alerts")
        if st.session_state.alerts_data:
            for alert in st.session_state.alerts_data:
                with st.expander(f"{alert.get('type')} - {alert.get('severity')}"):
                    st.json(alert)
        else:
            st.info("No alerts available")

    elif page == "Reports":
        st.subheader("📑 Reports")
        st.write("Report generation functionality would be here...")

    elif page == "Threat Detection":
        app.render_threat_detection_page()

    elif page == "Settings":
        st.subheader("⚙️ Settings")
        with st.form("settings_form"):
            st.subheader("User Preferences")
            timezone = st.selectbox("Timezone", ["UTC", "EST", "PST", "CET"])
            refresh_rate = st.slider("Refresh rate (min)", 1, 60, 5)
            
            st.subheader("API Configuration")
            otx_key = st.text_input("OTX API Key", type="password")
            supabase_url = st.text_input("Supabase URL")
            supabase_key = st.text_input("Supabase Key", type="password")
            
            if st.form_submit_button("💾 Save Settings"):
                st.success("Settings saved successfully!")