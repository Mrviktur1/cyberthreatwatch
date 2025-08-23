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

# Import the AlertsPanel
from alerts_panel import AlertsPanel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import your detection functions from the correct location
try:
    from threat_intelligence.correlation.detection import (
        ioc_match, brute_force, looks_like_phishing,
        impossible_travel, dns_tunnel_detection, honeytoken_access, run_all_detections
    )

    DETECTIONS_AVAILABLE = True
    logger.info("Successfully imported detection functions from threat_intelligence.correlation.detection")
except ImportError as e:
    logger.warning(f"Detection functions import error: {e}")
    try:
        from detections import (
            ioc_match, brute_force, looks_like_phishing,
            impossible_travel, dns_tunnel_detection, honeytoken_access, run_all_detections
        )

        DETECTIONS_AVAILABLE = True
        logger.info("Successfully imported detection functions from local detections.py")
    except ImportError:
        logger.warning("Detection functions not available. Please ensure detection.py exists.")
        DETECTIONS_AVAILABLE = False

# Import auth component
try:
    import auth

    AUTH_AVAILABLE = True
except ImportError:
    logger.warning("Auth component not found. Using fallback authentication.")
    AUTH_AVAILABLE = False


# --- Supabase Client ---
@st.cache_resource
def init_supabase() -> Client:
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


supabase = init_supabase()


# --- Fallback Auth Functions ---
def fallback_login(email: str, password: str):
    if email == "admin@cyberthreatwatch.com" and password == "admin123":
        st.session_state["user"] = {"email": email, "role": "admin"}
        st.session_state.authenticated = True
        st.success("✅ Login successful (fallback)")
        st.rerun()
    else:
        st.error("❌ Invalid credentials")


def fallback_signup(email: str, password: str):
    st.info("📧 Signup would send verification email in production")


def fallback_login_with_google():
    st.info("🔐 Google OAuth would redirect in production")


def fallback_reset_password(email: str):
    st.info("📧 Password reset email would be sent in production")


def fallback_logout():
    st.session_state.pop("user", None)
    st.session_state.authenticated = False
    st.success("👋 Logged out successfully!")
    st.rerun()


# Set page config
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# --- Session check ---
if "user" not in st.session_state:
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
    st.sidebar.success(f"👋 Welcome {st.session_state['user'].get('email')}")

    if st.sidebar.button("Logout"):
        if AUTH_AVAILABLE:
            auth.logout()
        else:
            fallback_logout()
        st.rerun()


    class CyberThreatWatch:
        def __init__(self):
            self.logo_path = "assets/CyberThreatWatch.png"
            self.signature_path = "assets/h_Signa....png"

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

            if not st.session_state.alerts_data:
                self.load_sample_data()

            self.geoip_lookup = self.simple_geoip_lookup
            self.alerts_panel = AlertsPanel()

        def simple_geoip_lookup(self, ip):
            geoip_mock_data = {
                "192.168.1.100": (40.7128, -74.0060),
                "10.0.0.50": (34.0522, -118.2437),
                "172.16.0.25": (51.5074, -0.1278),
            }
            return geoip_mock_data.get(ip, None)

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

        # ... keep detection logic (unchanged) ...

        def load_sample_data(self):
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

    app = CyberThreatWatch()
    app.render_header()

    if page == "Alerts":
        st.subheader("🚨 Alerts")
        st.components.v1.html(app.alerts_panel.layout().to_html(), height=600, scrolling=True)
