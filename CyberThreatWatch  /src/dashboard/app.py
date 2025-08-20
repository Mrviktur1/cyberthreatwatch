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

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import your components using absolute paths
from dashboard.components.sidebar import Sidebar
from dashboard.components.header import Header
from dashboard.components.dashboard_cards import DashboardCards
from dashboard.components.threat_intel import ThreatIntelPanel
from dashboard.components.geo_map import GeoMapVisualization
from dashboard.components.timeline import TimelineVisualization

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class CyberThreatWatch:
    def __init__(self):
        self.setup_page_config()
        self.initialize_session_state()
        self.setup_authentication()
        
    def setup_page_config(self):
        """Configure Streamlit page settings"""
        st.set_page_config(
            page_title="CyberThreatWatch",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded",
        )
        
        # Custom CSS
        st.markdown("""
            <style>
            .main { padding: 2rem; }
            .stButton>button { width: 100%; }
            .metric-card { 
                background-color: #f0f2f6; 
                padding: 1rem; 
                border-radius: 0.5rem; 
                border-left: 4px solid #ff4b4b;
            }
            </style>
        """, unsafe_allow_html=True)
    
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
    
    def setup_authentication(self):
        """Setup authentication configuration"""
        self.config = {
            'credentials': {
                'usernames': {
                    os.getenv('ADMIN_USERNAME', 'admin'): {
                        'email': os.getenv('ADMIN_EMAIL', 'admin@example.com'),
                        'name': 'Administrator',
                        'password': os.getenv('ADMIN_PASSWORD', 'admin123')
                    }
                }
            },
            'cookie': {
                'name': 'cyberthreatwatch_auth',
                'key': os.getenv('COOKIE_KEY', 'random_signature_key'),
                'expiry_days': 1
            },
            'preauthorized': {
                'emails': [os.getenv('PREAUTHORIZED_EMAILS', '').split(',')]
            }
        }
        
        self.authenticator = Authenticate(
            self.config['credentials'],
            self.config['cookie']['name'],
            self.config['cookie']['key'],
            self.config['cookie']['expiry_days'],
            self.config['preauthorized']
        )
    
    def initialize_clients(self):
        """Initialize external API clients"""
        try:
            # Supabase client
            supabase_url = os.getenv('SUPABASE_URL')
            supabase_key = os.getenv('SUPABASE_KEY')
            if supabase_url and supabase_key:
                self.supabase: Client = create_client(supabase_url, supabase_key)
            
            # OTX client
            otx_key = os.getenv('OTX_API_KEY')
            if otx_key:
                self.otx = OTXv2(otx_key)
                
        except Exception as e:
            logger.error(f"Error initializing clients: {e}")
            st.error("Failed to initialize external services. Some features may be limited.")
    
    def login_section(self):
        """Render login section"""
        st.title("🔒 CyberThreatWatch Login")
        st.write("Please login to access the threat intelligence dashboard")
        
        try:
            name, authentication_status, username = self.authenticator.login('Login', 'main')
            
            if authentication_status:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.user_role = 'admin'  # Default role
                st.rerun()
                
            elif authentication_status is False:
                st.error('Username/password is incorrect')
                
            elif authentication_status is None:
                st.warning('Please enter your username and password')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            st.error("Authentication service temporarily unavailable")
    
    def main_dashboard(self):
        """Render main dashboard"""
        # Initialize clients
        self.initialize_clients()
        
        # Header
        Header().render()
        
        # Sidebar
        selected_page = Sidebar().render()
        
        # Main content based on selected page
        if selected_page == "Dashboard":
            self.render_dashboard_page()
        elif selected_page == "Alerts":
            self.render_alerts_page()
        elif selected_page == "Reports":
            self.render_reports_page()
        elif selected_page == "Search":
            self.render_search_page()
        elif selected_page == "Settings":
            self.render_settings_page()
        
        # Logout button in sidebar
        if st.sidebar.button("🚪 Logout"):
            self.authenticator.logout('Logout', 'main')
            st.session_state.authenticated = False
            st.rerun()
    
    def render_dashboard_page(self):
        """Render main dashboard page"""
        st.header("📊 Security Dashboard")
        
        # Dashboard cards
        DashboardCards().render()
        
        # Two-column layout
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat intelligence panel
            ThreatIntelPanel().render()
            
        with col2:
            # Geo map visualization
            GeoMapVisualization().render()
        
        # Timeline visualization (full width)
        TimelineVisualization().render()
    
    def render_alerts_page(self):
        """Render alerts page"""
        try:
            # Use absolute import
            from dashboard.pages.alerts import render_alerts_page
            render_alerts_page()
        except ImportError as e:
            st.error("Alerts module not available")
            logger.error(f"Alerts page import error: {e}")
    
    def render_reports_page(self):
        """Render reports page"""
        try:
            # Use absolute import
            from dashboard.pages.reports import render_reports_page
            render_reports_page()
        except ImportError as e:
            st.error("Reports module not available")
            logger.error(f"Reports page import error: {e}")
    
    def render_search_page(self):
        """Render search page"""
        try:
            # Use absolute import
            from dashboard.pages.search import render_search_page
            render_search_page()
        except ImportError as e:
            st.error("Search module not available")
            logger.error(f"Search page import error: {e}")
    
    def render_settings_page(self):
        """Render settings page"""
        st.header("⚙️ Settings")
        
        st.subheader("User Preferences")
        timezone = st.selectbox("Timezone", ["UTC", "EST", "PST", "CET"])
        refresh_rate = st.slider("Data refresh rate (minutes)", 1, 60, 5)
        
        if st.button("Save Preferences"):
            st.success("Preferences saved successfully!")
        
        st.subheader("API Configuration")
        with st.form("api_config"):
            otx_key = st.text_input("OTX API Key", type="password")
            supabase_url = st.text_input("Supabase URL")
            supabase_key = st.text_input("Supabase Key", type="password")
            
            if st.form_submit_button("Save API Configuration"):
                st.success("API configuration saved!")
    
    def load_sample_data(self):
        """Load sample data for demonstration"""
        # Sample alerts data
        sample_alerts = [
            {
                "id": 1,
                "timestamp": datetime.now() - timedelta(hours=2),
                "severity": "High",
                "type": "Malware Detection",
                "source_ip": "192.168.1.100",
                "description": "Suspicious executable detected"
            },
            {
                "id": 2,
                "timestamp": datetime.now() - timedelta(hours=5),
                "severity": "Medium",
                "type": "Port Scan",
                "source_ip": "10.0.0.50",
                "description": "Multiple connection attempts detected"
            }
        ]
        
        # Sample threat data
        sample_threats = [
            {
                "indicator": "malicious-domain.com",
                "type": "domain",
                "threat_score": 85,
                "first_seen": datetime.now() - timedelta(days=30),
                "last_seen": datetime.now()
            }
        ]
        
        st.session_state.alerts_data = sample_alerts
        st.session_state.threat_data = sample_threats
    
    def run(self):
        """Main application runner"""
        try:
            if not st.session_state.authenticated:
                self.login_section()
            else:
                self.main_dashboard()
                
        except Exception as e:
            logger.error(f"Application error: {e}")
            st.error("An unexpected error occurred. Please try refreshing the page.")
            if st.button("Reset Application"):
                st.session_state.clear()
                st.rerun()

# Run the application
if __name__ == "__main__":
    app = CyberThreatWatch()
    
    # Load sample data for demonstration
    if not st.session_state.get('alerts_data'):
        app.load_sample_data()
    
    app.run()