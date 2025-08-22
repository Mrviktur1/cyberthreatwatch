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
import time
import urllib.parse

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
    except ImportError:
        logger.warning("Detection functions not available. Please ensure detection.py exists.")
        DETECTIONS_AVAILABLE = False

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

# --- Authentication Functions ---
def signup(email: str, password: str, captcha_token: str = None):
    """Sign up new user with CAPTCHA support"""
    try:
        # Prepare signup data
        signup_data = {"email": email, "password": password}
        
        # Add CAPTCHA token if provided
        if captcha_token:
            signup_data["options"] = {"captchaToken": captcha_token}
        
        response = supabase.auth.sign_up(signup_data)
        
        if response.user:
            st.session_state.login_attempts = 0
            st.success("✅ Signup successful! Please check your email to confirm.")
            return True
        else:
            st.error("❌ Signup failed. Try again.")
            return False
    except Exception as e:
        error_msg = str(e).lower()
        
        if "captcha" in error_msg:
            st.error("🔒 CAPTCHA verification required. Please complete the verification.")
            st.session_state.requires_captcha = True
            st.session_state.signup_email = email
            st.session_state.signup_password = password
        else:
            st.error(f"Error: {e}")
        return False

def login(email: str, password: str, captcha_token: str = None):
    """Login existing user with CAPTCHA support"""
    try:
        # Check rate limiting
        current_time = time.time()
        if (current_time - st.session_state.get('last_attempt_time', 0)) < 2:
            st.error("⚠️ Too many attempts. Please wait a moment.")
            return False
            
        # Prepare login data
        login_data = {"email": email, "password": password}
        
        # Add CAPTCHA token if provided
        if captcha_token:
            login_data["options"] = {"captchaToken": captcha_token}
        
        response = supabase.auth.sign_in_with_password(login_data)
        
        if response.user:
            st.session_state.user = response.user
            st.session_state.login_attempts = 0
            st.session_state.requires_captcha = False
            st.success(f"✅ Welcome {response.user.email}")
            return True
        else:
            st.session_state.login_attempts = st.session_state.get('login_attempts', 0) + 1
            st.session_state.last_attempt_time = current_time
            st.error("❌ Invalid credentials.")
            return False
    except Exception as e:
        st.session_state.login_attempts = st.session_state.get('login_attempts', 0) + 1
        st.session_state.last_attempt_time = time.time()
        error_msg = str(e).lower()
        
        if "captcha" in error_msg:
            st.error("🔒 CAPTCHA verification required. Please complete the verification.")
            st.session_state.requires_captcha = True
            st.session_state.login_email = email
            st.session_state.login_password = password
        else:
            st.error(f"Error: {e}")
        return False

def handle_captcha_verification(auth_type="login"):
    """Handle CAPTCHA verification process - FIXED VERSION"""
    st.warning("🔒 CAPTCHA verification required")
    
    # Use a form for the CAPTCHA verification
    with st.form("captcha_verification_form"):
        st.write("Please complete the CAPTCHA verification")
        
        # Simple CAPTCHA implementation
        captcha_code = st.text_input("Enter the CAPTCHA code shown below:", 
                                   placeholder="Enter code")
        
        # Display a simple CAPTCHA
        st.markdown("""
        <div style='background-color: #f0f0f0; padding: 10px; border-radius: 5px; 
                    text-align: center; font-family: monospace; font-size: 20px; 
                    letter-spacing: 5px; margin: 10px 0;'>
        ABC123
        </div>
        <p><small>Enter <strong>ABC123</strong> to verify</small></p>
        """, unsafe_allow_html=True)
        
        # Use form_submit_button instead of regular button
        verify_submit = st.form_submit_button("Verify CAPTCHA")
        
        if verify_submit:
            if captcha_code == "ABC123":  # Simple mock verification
                st.session_state.requires_captcha = False
                
                # Retry the auth operation with the mock token
                if auth_type == "login":
                    success = login(st.session_state.login_email, 
                                  st.session_state.login_password, 
                                  "mock_captcha_token_123")
                    if success:
                        st.rerun()
                else:
                    success = signup(st.session_state.signup_email, 
                                   st.session_state.signup_password, 
                                   "mock_captcha_token_123")
                    if success:
                        st.rerun()
            else:
                st.error("Invalid CAPTCHA code. Please try again.")

def reset_password(email: str):
    """Trigger Supabase password reset"""
    try:
        supabase.auth.reset_password_for_email(email)
        st.success("📧 Password reset email sent. Check your inbox.")
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def logout():
    """Logout user"""
    try:
        supabase.auth.sign_out()
        st.session_state.user = None
        st.session_state.requires_captcha = False
        st.success("👋 Logged out successfully!")
        return True
    except Exception as e:
        st.error(f"Error during logout: {e}")
        return False

def is_authenticated():
    """Check if user is authenticated"""
    if st.session_state.get("user"):
        return True
    
    try:
        if supabase:
            session = supabase.auth.get_session()
            if session and session.user:
                st.session_state.user = session.user
                return True
    except:
        pass
    
    return False

# Set page config
st.set_page_config(page_title="CyberThreatWatch", layout="wide", page_icon="🛡️")

# Initialize session state for authentication
if "user" not in st.session_state:
    st.session_state.user = None
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "last_attempt_time" not in st.session_state:
    st.session_state.last_attempt_time = 0
if "show_signup" not in st.session_state:
    st.session_state.show_signup = False
if "show_reset" not in st.session_state:
    st.session_state.show_reset = False
if "requires_captcha" not in st.session_state:
    st.session_state.requires_captcha = False

# --- Authentication UI ---
def show_login_form():
    """Display login form"""
    st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
    }
    .stTextInput input, .stTextInput input:focus {
        background-color: #1E293B;
        color: white;
        border: 1px solid #334155;
    }
    .css-1y4p8pa {
        background-color: #0E1117;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Try to load logo
    logo_paths = ["assets/CyberThreatWatch.png", "assets/h_Signa....png"]
    logo_image = None
    for path in logo_paths:
        try:
            if os.path.exists(path):
                logo_image = Image.open(path)
                break
        except:
            pass
    
    if logo_image:
        st.image(logo_image, width=150)
    
    st.markdown("<h1 style='text-align: center; color: #FF4B4B;'>CyberThreatWatch</h1>", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center; margin-bottom: 2rem;'>Login Portal</h2>", unsafe_allow_html=True)
    
    # Handle CAPTCHA requirement
    if st.session_state.get('requires_captcha', False):
        handle_captcha_verification("login")
        return
    
    with st.form("login_form"):
        email = st.text_input("Email", placeholder="Enter your email", value="timukeenemmoh@gmail.com")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit = st.form_submit_button("Login", use_container_width=True)
        
        if submit:
            if email and password:
                if supabase:
                    login(email, password)
                else:
                    # Fallback for testing
                    if email == "admin@cyberthreatwatch.com" and password == "admin123":
                        st.session_state.user = {"email": email, "role": "admin"}
                        st.success("✅ Login successful (fallback)")
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials")
            else:
                st.error("Please enter both email and password")
    
    # Additional options
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sign Up", use_container_width=True):
            st.session_state.show_signup = True
            st.session_state.requires_captcha = False
            st.rerun()
    with col2:
        if st.button("Reset Password", use_container_width=True):
            st.session_state.show_reset = True
            st.session_state.requires_captcha = False
            st.rerun()

def show_signup_form():
    """Display signup form - FIXED VERSION"""
    st.markdown("<h2 style='text-align: center; margin-bottom: 2rem;'>Create Account</h2>", unsafe_allow_html=True)
    
    # Handle CAPTCHA requirement
    if st.session_state.get('requires_captcha', False):
        handle_captcha_verification("signup")
        return
    
    # Use a form for signup
    with st.form("signup_form"):
        email = st.text_input("Email", placeholder="Enter your email", value="TINUKEENEMOH@GMAIL.COM")
        password = st.text_input("Password", type="password", placeholder="Create a password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
        
        # Use form_submit_button instead of regular button
        submit = st.form_submit_button("Sign Up", use_container_width=True)
        
        if submit:
            if email and password and confirm_password:
                if password == confirm_password:
                    if supabase:
                        signup(email, password)
                    else:
                        st.info("📧 Signup would send verification email in production")
                else:
                    st.error("Passwords do not match")
            else:
                st.error("Please fill all fields")
    
    # Back button outside the form
    if st.button("Back to Login"):
        st.session_state.show_signup = False
        st.session_state.requires_captcha = False
        st.rerun()

def show_reset_form():
    """Display password reset form"""
    st.markdown("<h2 style='text-align: center; margin-bottom: 2rem;'>Reset Password</h2>", unsafe_allow_html=True)
    
    email = st.text_input("Email", placeholder="Enter your email")
    if st.button("Send Reset Link", use_container_width=True):
        if email:
            if supabase:
                reset_password(email)
            else:
                st.info("📧 Password reset email would be sent in production")
        else:
            st.error("Please enter your email")
    
    if st.button("Back to Login"):
        st.session_state.show_reset = False
        st.rerun()

# --- MAIN APPLICATION ---
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

# --- Main Application Logic ---
if not is_authenticated():
    # Show authentication interface
    if st.session_state.show_signup:
        show_signup_form()
    elif st.session_state.show_reset:
        show_reset_form()
    else:
        show_login_form()
else:
    # User is authenticated - show main dashboard
    user_email = st.session_state.user.email if hasattr(st.session_state.user, 'email') else st.session_state.user.get('email', 'User')
    st.sidebar.success(f"👋 Welcome {user_email}")

    if st.sidebar.button("Logout"):
        logout()
        st.rerun()

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