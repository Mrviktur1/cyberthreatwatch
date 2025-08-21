import streamlit as st
import sys
import os
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
from streamlit_authenticator import Authenticate
import supabase
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
    from dashboard.components.detection import ioc_match, brute_force, looks_like_phishing
    DETECTIONS_AVAILABLE = True
    logger.info("Successfully imported detection functions from dashboard.components.detection")
except ImportError as e:
    logger.warning(f"Detection functions import error: {e}")
    # Fallback: try to import from detections.py in same directory
    try:
        from detections import ioc_match, brute_force, looks_like_phishing
        DETECTIONS_AVAILABLE = True
        logger.info("Successfully imported detection functions from local detections.py")
    except ImportError:
        logger.warning("Detection functions not available. Please ensure detection.py exists.")
        DETECTIONS_AVAILABLE = False

class CyberThreatWatch:
    def __init__(self):
        self.setup_page_config()
        self.initialize_session_state()
        self.setup_authentication()
        # Set the correct paths to your assets folder
        self.logo_path = "assets/CyberThreatWatch.png"
        self.signature_path = "assets/h_Signa....png"  # Adjust based on actual filename
        
        # Initialize Supabase connection
        self.supabase = None
        self.init_supabase()
        
    def setup_page_config(self):
        """Configure Streamlit page settings"""
        st.set_page_config(
            page_title="CyberThreatWatch",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded",
        )
        
    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'username' not in st.session_state:
            st.session_state.username = None
        if 'user_role' not in st.session_state:
            st.session_state.user_role = None
        if 'alerts_data' not in st.session_state:
            st.session_state.alerts_data = []
        if 'threat_data' not in st.session_state:
            st.session_state.threat_data = []
        if 'selected_time_range' not in st.session_state:
            st.session_state.selected_time_range = "24h"
        if 'auth_init' not in st.session_state:
            st.session_state.auth_init = False
        if 'detections' not in st.session_state:
            st.session_state.detections = []
        if 'supabase_connected' not in st.session_state:
            st.session_state.supabase_connected = False
        if 'detection_available' not in st.session_state:
            st.session_state.detection_available = DETECTIONS_AVAILABLE
    
    def init_supabase(self):
        """Initialize Supabase connection"""
        try:
            if 'supabase' in st.secrets:
                url = st.secrets["supabase"]["url"]
                key = st.secrets["supabase"]["key"]
                self.supabase = create_client(url, key)
                st.session_state.supabase_connected = True
                logger.info("Supabase connected successfully")
            else:
                logger.warning("Supabase secrets not found in Streamlit secrets")
        except Exception as e:
            logger.error(f"Supabase connection error: {e}")
            st.session_state.supabase_connected = False
    
    def setup_authentication(self):
        """Setup authentication configuration"""
        if st.session_state.get('auth_init'):
            return
            
        self.config = {
            'credentials': {
                'usernames': {
                    'admin': {
                        'email': 'admin@cyberthreatwatch.com',
                        'name': 'Administrator',
                        'password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW'
                    },
                    'analyst': {
                        'email': 'analyst@cyberthreatwatch.com', 
                        'name': 'Security Analyst',
                        'password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW'
                    }
                }
            },
            'cookie': {
                'name': 'cyberthreatwatch_auth',
                'key': 'random_signature_key_12345',
                'expiry_days': 1
            },
            'preauthorized': {
                'emails': ['admin@cyberthreatwatch.com', 'analyst@cyberthreatwatch.com']
            }
        }
        
        try:
            self.authenticator = Authenticate(
                self.config['credentials'],
                self.config['cookie']['name'],
                self.config['cookie']['key'],
                self.config['cookie']['expiry_days'],
                self.config['preauthorized']
            )
            st.session_state.auth_init = True
        except Exception as e:
            logger.error(f"Auth setup error: {e}")
    
    def load_image(self, path, width=None):
        """Safely load image with error handling"""
        try:
            if os.path.exists(path):
                image = Image.open(path)
                if width:
                    image = image.resize((width, int(image.height * width / image.width)))
                return image
            else:
                return None
        except Exception as e:
            logger.error(f"Error loading image {path}: {e}")
            return None
    
    def login_section(self):
        """Render login section - ONLY this should show when not authenticated"""
        st.sidebar.empty()
        
        # Simple login page without any assets
        st.title("🔒 CyberThreatWatch Login")
        st.write("Please login to access the threat intelligence dashboard")
        
        # Custom login form
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit_button = st.form_submit_button("Login")
            
            if submit_button:
                if self.validate_login(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.user_role = 'admin' if username == 'admin' else 'analyst'
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
        
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📝 Sign Up"):
                st.info("Please contact your administrator for account creation")
                
        with col2:
            if st.button("🔑 Forgot Password"):
                st.info("Please contact your administrator for password reset")
    
    def validate_login(self, username, password):
        """Simple login validation"""
        valid_users = {
            'admin': 'admin123',
            'analyst': 'admin123'
        }
        return username in valid_users and password == valid_users[username]
    
    def render_sidebar(self):
        """Render sidebar only when authenticated"""
        st.sidebar.empty()
        
        # Display logo if found
        logo_image = self.load_image(self.logo_path)
        if logo_image:
            try:
                st.sidebar.image(logo_image, use_container_width=True)
            except Exception as e:
                st.sidebar.title("🛡️ CyberThreatWatch")
                logger.warning(f"Could not display logo: {e}")
        else:
            st.sidebar.title("🛡️ CyberThreatWatch")
        
        st.sidebar.markdown("---")
        
        # Navigation
        pages = {
            "📊 Dashboard": "Dashboard",
            "🚨 Alerts": "Alerts", 
            "📋 Reports": "Reports",
            "🔍 Search": "Search",
            "🛡️ Threat Detection": "Threat Detection",
            "⚙️ Settings": "Settings"
        }
        
        selected = st.sidebar.radio("Navigation", list(pages.keys()))
        st.sidebar.markdown("---")
        
        st.sidebar.write(f"👤 **User:** {st.session_state.username}")
        st.sidebar.write(f"🎯 **Role:** {st.session_state.user_role}")
        
        # Show detection system status
        if st.session_state.detection_available:
            st.sidebar.success("✅ Detection System: Online")
        else:
            st.sidebar.error("❌ Detection System: Offline")
        
        st.sidebar.markdown("---")
        
        time_range = st.sidebar.selectbox(
            "Time Range", ["1h", "6h", "12h", "24h", "7d", "30d"], index=3
        )
        st.session_state.selected_time_range = time_range
        st.sidebar.markdown("---")
        
        return pages[selected]
    
    def render_header(self):
        """Render header only when authenticated"""
        col1, col2 = st.columns([1, 3])
        
        with col1:
            # Try to load signature image
            signature_image = self.load_image(self.signature_path, width=100)
            if signature_image:
                try:
                    st.image(signature_image, width=100)
                except Exception as e:
                    logger.warning(f"Could not display signature: {e}")
                    # Fallback to logo if signature fails
                    logo_image = self.load_image(self.logo_path, width=100)
                    if logo_image:
                        st.image(logo_image, width=100)
        
        with col2:
            st.title("🛡️ CyberThreatWatch")
            st.markdown("Real-time Threat Intelligence Dashboard")
        
        st.markdown("---")
    
    def run_threat_detection(self):
        """Run threat detection algorithms"""
        if not st.session_state.supabase_connected or not self.supabase:
            st.error("❌ Supabase not connected. Please check your configuration.")
            return []
        
        if not st.session_state.detection_available:
            st.error("❌ Detection functions not available. Please ensure detection.py exists in dashboard/components/")
            return []
        
        try:
            # 1) Load events + IOCs
            with st.spinner("Loading events and IOCs from Supabase..."):
                events_result = self.supabase.table("events").select("*").execute()
                iocs_result = self.supabase.table("iocs").select("*").execute()
                
                events = events_result.data
                iocs = iocs_result.data
                
                logger.info(f"Loaded {len(events)} events and {len(iocs)} IOCs")
            
            # 2) Run detections
            detections = []

            # IOC matching
            for e in events:
                hits = ioc_match(e, iocs)
                if hits:
                    detections.append({
                        "title": "IOC Match Detected",
                        "event_id": e.get("id", "unknown"),
                        "hits": hits,
                        "severity": "critical",
                        "timestamp": e.get("timestamp", datetime.now().isoformat()),
                        "source_ip": e.get("source_ip", "N/A"),
                        "description": f"Matched {len(hits)} IOCs"
                    })

            # Brute force rule
            brute_force_detections = brute_force(events)
            for detection in brute_force_detections:
                detection["severity"] = "high"
                detection["title"] = "Brute Force Attempt"
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
            
            logger.info(f"Completed threat detection with {len(detections)} findings")
            return detections
            
        except Exception as e:
            logger.error(f"Threat detection error: {e}")
            st.error(f"Error running threat detection: {str(e)}")
            return []
    
    def render_threat_detection_page(self):
        """Render threat detection page"""
        st.header("🛡️ Real-time Threat Detection")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.info("Run automated threat detection against your Supabase data. Detects IOC matches, brute force attempts, and phishing domains.")
        
        with col2:
            if st.button("🔄 Run Detection", type="primary", use_container_width=True):
                with st.spinner("Running comprehensive threat detection..."):
                    st.session_state.detections = self.run_threat_detection()
        
        # Show connection status
        col1, col2 = st.columns(2)
        with col1:
            if st.session_state.supabase_connected:
                st.success("✅ Supabase: Connected")
            else:
                st.error("❌ Supabase: Disconnected")
        
        with col2:
            if st.session_state.detection_available:
                st.success("✅ Detection Engine: Ready")
            else:
                st.error("❌ Detection Engine: Unavailable")
        
        st.markdown("---")
        
        if st.session_state.detections:
            st.subheader(f"📋 Detection Results ({len(st.session_state.detections)} findings)")
            
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_detections = sorted(st.session_state.detections, 
                                     key=lambda x: severity_order.get(x["severity"], 4))
            
            for d in sorted_detections:
                severity_color = {
                    "critical": "🔴",
                    "high": "🟠", 
                    "medium": "🟡",
                    "low": "🟢"
                }.get(d["severity"], "⚪")
                
                with st.expander(f"{severity_color} {d['title']} - {d['severity'].upper()}", expanded=True):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Event ID:** `{d['event_id']}`")
                        st.write(f"**Timestamp:** {d.get('timestamp', 'N/A')}")
                        if 'source_ip' in d:
                            st.write(f"**Source IP:** `{d['source_ip']}`")
                        if 'domain' in d:
                            st.write(f"**Domain:** `{d['domain']}`")
                    
                    with col2:
                        if 'hits' in d and d['hits']:
                            st.write("**IOC Matches:**")
                            for hit in d['hits']:
                                st.write(f"• {hit}")
                        if 'description' in d:
                            st.write(f"**Description:** {d['description']}")
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button("📋 View Details", key=f"view_{d['event_id']}"):
                            st.write(f"Detailed analysis for event {d['event_id']}")
                    with col2:
                        if st.button("✅ Mark Resolved", key=f"resolve_{d['event_id']}"):
                            st.success(f"Detection {d['event_id']} marked as resolved")
                    with col3:
                        if st.button("🚫 Block Source", key=f"block_{d['event_id']}"):
                            st.warning(f"Source for {d['event_id']} has been blocked")
        else:
            st.info("👆 No detections found. Click 'Run Detection' to analyze your Supabase data for threats.")
    
    def render_dashboard_page(self):
        """Render main dashboard page"""
        st.header("📊 Security Dashboard")
        
        # Include threat detection stats on dashboard
        total_detections = len(st.session_state.detections)
        critical_detections = sum(1 for d in st.session_state.detections if d.get('severity') == 'critical')
        high_detections = sum(1 for d in st.session_state.detections if d.get('severity') == 'high')
        
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total Alerts", len(st.session_state.alerts_data))
        with col2:
            high_severity = sum(1 for a in st.session_state.alerts_data if a.get('severity') == 'High')
            st.metric("High Severity", high_severity)
        with col3:
            st.metric("Active Threats", len(st.session_state.threat_data))
        with col4:
            st.metric("Threat Detections", total_detections, 
                     delta=f"{critical_detections} critical" if critical_detections else None)
        with col5:
            st.metric("System Status", "🟢 Online")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Recent Alerts")
            if st.session_state.alerts_data:
                for alert in st.session_state.alerts_data[:3]:
                    severity_color = "🔴" if alert.get('severity') == 'High' else "🟡" if alert.get('severity') == 'Medium' else "🟢"
                    st.write(f"{severity_color} **{alert.get('type')}** - {alert.get('source_ip')}")
            else:
                st.info("No alerts data")
        
        with col2:
            st.subheader("Latest Detections")
            if st.session_state.detections:
                for detection in st.session_state.detections[:3]:
                    severity_color = "🔴" if detection.get('severity') == 'critical' else "🟠" if detection.get('severity') == 'high' else "🟡"
                    detection_type = detection.get('title', 'Unknown')
                    source_info = detection.get('source_ip', detection.get('domain', 'N/A'))
                    st.write(f"{severity_color} **{detection_type}** - {source_info}")
            else:
                st.info("No threat detections yet. Run detection from the Threat Detection page.")
    
    def render_alerts_page(self):
        """Render alerts page"""
        st.header("🚨 Alerts")
        
        if st.session_state.alerts_data:
            for alert in st.session_state.alerts_data:
                with st.expander(f"{alert.get('type')} - {alert.get('severity')}"):
                    st.json(alert)
        else:
            st.info("No alerts available")
    
    def render_reports_page(self):
        """Render reports page"""
        st.header("📋 Reports")
        
        # Include detection reports
        if st.session_state.detections:
            st.subheader("Threat Detection Report")
            st.write(f"Total detections: {len(st.session_state.detections)}")
            
            # Create a simple report
            detection_df = pd.DataFrame(st.session_state.detections)
            if not detection_df.empty:
                st.dataframe(detection_df[['title', 'severity', 'timestamp']])
        else:
            st.info("No detection data available for reports. Run threat detection first.")
    
    def render_search_page(self):
        """Render search page"""
        st.header("🔍 Search")
        search_term = st.text_input("Search threats, alerts, detections, or indicators")
        if search_term:
            # Search across all data sources
            all_data = (st.session_state.alerts_data + 
                       st.session_state.threat_data + 
                       st.session_state.detections)
            
            results = [
                item for item in all_data
                if search_term.lower() in str(item).lower()
            ]
            st.write(f"Found {len(results)} results for '{search_term}'")
            
            if results:
                for result in results:
                    with st.expander(f"Result: {result.get('title', 'Unknown')}"):
                        st.json(result)
    
    def render_settings_page(self):
        """Render settings page"""
        st.header("⚙️ Settings")
        
        with st.form("settings_form"):
            st.subheader("User Preferences")
            timezone = st.selectbox("Timezone", ["UTC", "EST", "PST", "CET"])
            refresh_rate = st.slider("Refresh rate (min)", 1, 60, 5)
            
            st.subheader("API Configuration")
            otx_key = st.text_input("OTX API Key", type="password")
            supabase_url = st.text_input("Supabase URL")
            supabase_key = st.text_input("Supabase Key", type="password")
            
            st.subheader("Threat Detection")
            auto_detect = st.checkbox("Enable automatic threat detection", value=True)
            detection_interval = st.slider("Detection interval (min)", 1, 60, 15)
            
            if st.form_submit_button("💾 Save Settings"):
                st.success("Settings saved successfully!")
    
    def load_sample_data(self):
        """Load sample data for demonstration"""
        sample_alerts = [
            {
                "id": 1, "timestamp": datetime.now() - timedelta(hours=2),
                "severity": "High", "type": "Malware Detection",
                "source_ip": "192.168.1.100", "description": "Suspicious executable detected"
            },
            {
                "id": 2, "timestamp": datetime.now() - timedelta(hours=5),
                "severity": "Medium", "type": "Port Scan",
                "source_ip": "10.0.0.50", "description": "Multiple connection attempts detected"
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
        st.session_state.detections = []  # Initialize empty detections
    
    def main_application(self):
        """Main application logic - only called when authenticated"""
        self.render_header()
        selected_page = self.render_sidebar()
        
        if selected_page == "Dashboard":
            self.render_dashboard_page()
        elif selected_page == "Alerts":
            self.render_alerts_page()
        elif selected_page == "Reports":
            self.render_reports_page()
        elif selected_page == "Search":
            self.render_search_page()
        elif selected_page == "Threat Detection":
            self.render_threat_detection_page()
        elif selected_page == "Settings":
            self.render_settings_page()
        
        if st.sidebar.button("🚪 Logout", type="primary"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.user_role = None
            st.session_state.detections = []
            st.rerun()
    
    def run(self):
        """Main application runner"""
        try:
            if not st.session_state.get('alerts_data'):
                self.load_sample_data()
            
            if not st.session_state.get('auth_init'):
                self.setup_authentication()
            
            if not st.session_state.authenticated:
                st.sidebar.empty()
                self.login_section()
                return
            else:
                self.main_application()
                
        except Exception as e:
            logger.error(f"Application error: {e}")
            st.error("An unexpected error occurred. Please try refreshing the page.")
            if st.button("Reset Application"):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()

# Run the application
if __name__ == "__main__":
    app = CyberThreatWatch()
    app.run()