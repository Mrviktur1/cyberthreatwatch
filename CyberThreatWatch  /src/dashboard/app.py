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
        """Render login section - ONLY this should show when not authenticated"""
        # Clear anything that might be in sidebar/main area
        st.sidebar.empty()
        
        # Main login content
        st.title("🔒 CyberThreatWatch Login")
        st.write("Please login to access the threat intelligence dashboard")
        
        try:
            name, authentication_status, username = self.authenticator.login('Login', 'main')
            
            if authentication_status:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.user_role = 'admin'
                st.rerun()
                
            elif authentication_status is False:
                st.error('Username/password is incorrect')
                
            elif authentication_status is None:
                st.warning('Please enter your username and password')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            st.error("Authentication service temporarily unavailable")
    
    def render_sidebar(self):
        """Render sidebar only when authenticated"""
        st.sidebar.title("🛡️ CyberThreatWatch")
        st.sidebar.markdown("---")
        
        # Navigation
        pages = {
            "📊 Dashboard": "Dashboard",
            "🚨 Alerts": "Alerts", 
            "📋 Reports": "Reports",
            "🔍 Search": "Search",
            "⚙️ Settings": "Settings"
        }
        
        selected = st.sidebar.radio("Navigation", list(pages.keys()))
        st.sidebar.markdown("---")
        
        # User info
        st.sidebar.write(f"👤 **User:** {st.session_state.username}")
        st.sidebar.write(f"🎯 **Role:** {st.session_state.user_role}")
        st.sidebar.markdown("---")
        
        # Time range filter
        time_range = st.sidebar.selectbox(
            "Time Range",
            ["1h", "6h", "12h", "24h", "7d", "30d"],
            index=3
        )
        st.session_state.selected_time_range = time_range
        
        return pages[selected]
    
    def render_header(self):
        """Render header only when authenticated"""
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.title("🛡️ CyberThreatWatch")
            st.markdown("Real-time Threat Intelligence Dashboard")
        st.markdown("---")
    
    def render_dashboard_page(self):
        """Render main dashboard page"""
        st.header("📊 Security Dashboard")
        
        # Simple metrics as fallback
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", len(st.session_state.alerts_data))
        with col2:
            st.metric("High Severity", sum(1 for a in st.session_state.alerts_data if a.get('severity') == 'High'))
        with col3:
            st.metric("Active Threats", len(st.session_state.threat_data))
        with col4:
            st.metric("System Status", "🟢 Online")
        
        st.markdown("---")
        
        # Simple data displays
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Recent Alerts")
            if st.session_state.alerts_data:
                for alert in st.session_state.alerts_data[:5]:
                    st.write(f"**{alert.get('type')}** - {alert.get('severity')}")
            else:
                st.info("No alerts data")
        
        with col2:
            st.subheader("Active Threats")
            if st.session_state.threat_data:
                for threat in st.session_state.threat_data:
                    st.write(f"**{threat.get('indicator')}** - Score: {threat.get('threat_score')}")
            else:
                st.info("No threat data")
    
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
        st.info("Reports functionality will be available soon")
    
    def render_search_page(self):
        """Render search page"""
        st.header("🔍 Search")
        search_term = st.text_input("Search threats, alerts, or indicators")
        if search_term:
            st.write(f"Search results for: {search_term}")
            # Simple search implementation
            results = [
                item for item in st.session_state.alerts_data + st.session_state.threat_data
                if search_term.lower() in str(item).lower()
            ]
            st.write(f"Found {len(results)} results")
    
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
            
            if st.form_submit_button("💾 Save Settings"):
                st.success("Settings saved successfully!")
    
    def load_sample_data(self):
        """Load sample data for demonstration"""
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
    
    def main_application(self):
        """Main application logic - only called when authenticated"""
        # Initialize clients
        self.initialize_clients()
        
        # Render header and sidebar
        self.render_header()
        selected_page = self.render_sidebar()
        
        # Render selected page
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
        
        # Logout button
        if st.sidebar.button("🚪 Logout"):
            self.authenticator.logout('Logout', 'main')
            st.session_state.authenticated = False
            st.session_state.clear()
            st.rerun()
    
    def run(self):
        """Main application runner"""
        try:
            # Load sample data if not loaded
            if not st.session_state.get('alerts_data'):
                self.load_sample_data()
            
            # Check authentication
            if not st.session_state.authenticated:
                self.login_section()
            else:
                self.main_application()
                
        except Exception as e:
            logger.error(f"Application error: {e}")
            st.error("An unexpected error occurred. Please try refreshing the page.")
            if st.button("Reset Application"):
                st.session_state.clear()
                st.rerun()

# Run the application
if __name__ == "__main__":
    app = CyberThreatWatch()
    app.run()