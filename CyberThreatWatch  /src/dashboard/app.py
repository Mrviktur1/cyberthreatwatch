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
        if 'auth_init' not in st.session_state:
            st.session_state.auth_init = False
    
    def setup_authentication(self):
        """Setup authentication configuration"""
        # Only initialize once
        if st.session_state.get('auth_init'):
            return
            
        self.config = {
            'credentials': {
                'usernames': {
                    'admin': {
                        'email': 'admin@cyberthreatwatch.com',
                        'name': 'Administrator',
                        'password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW'  # admin123
                    },
                    'analyst': {
                        'email': 'analyst@cyberthreatwatch.com', 
                        'name': 'Security Analyst',
                        'password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW'  # admin123
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
            st.error("Authentication setup failed")
    
    def login_section(self):
        """Render login section - ONLY this should show when not authenticated"""
        # Clear sidebar and main area completely
        st.sidebar.empty()
        
        # Use a custom login form instead of the authenticator widget
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
        
        # Additional options
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📝 Sign Up"):
                st.info("Please contact your administrator for account creation")
                
        with col2:
            if st.button("🔑 Forgot Password"):
                st.info("Please contact your administrator for password reset")
        
        # Google sign-in placeholder
        st.markdown("---")
        st.write("Or sign in with:")
        if st.button("Google 🅖", use_container_width=True):
            st.info("Google sign-in will be available soon")
    
    def validate_login(self, username, password):
        """Simple login validation"""
        valid_users = {
            'admin': 'admin123',
            'analyst': 'admin123'
        }
        return username in valid_users and password == valid_users[username]
    
    def render_sidebar(self):
        """Render sidebar only when authenticated"""
        # Clear sidebar first
        st.sidebar.empty()
        
        # Now build authenticated sidebar with your logo
        try:
            # Try to display your logo - only if authenticated!
            logo_path = "logo.png"  # Change this to your actual logo path
            if os.path.exists(logo_path):
                st.sidebar.image(logo_path, use_container_width=True)
            else:
                st.sidebar.title("🛡️ CyberThreatWatch")
        except:
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
        st.sidebar.markdown("---")
        
        return pages[selected]
    
    def render_header(self):
        """Render header only when authenticated"""
        # Try to display your signature/logo in header
        try:
            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                signature_path = "signature.png"  # Change to your signature path
                if os.path.exists(signature_path):
                    st.image(signature_path, width=100)
            with col2:
                st.title("🛡️ CyberThreatWatch")
                st.markdown("Real-time Threat Intelligence Dashboard")
            with col3:
                # Additional logo or empty space
                pass
        except:
            # Fallback if images don't load
            st.title("🛡️ CyberThreatWatch")
            st.markdown("Real-time Threat Intelligence Dashboard")
        
        st.markdown("---")
    
    def render_dashboard_page(self):
        """Render main dashboard page"""
        st.header("📊 Security Dashboard")
        
        # Simple metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", len(st.session_state.alerts_data))
        with col2:
            high_severity = sum(1 for a in st.session_state.alerts_data if a.get('severity') == 'High')
            st.metric("High Severity", high_severity)
        with col3:
            st.metric("Active Threats", len(st.session_state.threat_data))
        with col4:
            st.metric("System Status", "🟢 Online")
        
        st.markdown("---")
        
        # Data displays
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
            st.subheader("Active Threats")
            if st.session_state.threat_data:
                for threat in st.session_state.threat_data:
                    score = threat.get('threat_score', 0)
                    score_emoji = "🔴" if score > 80 else "🟡" if score > 50 else "🟢"
                    st.write(f"{score_emoji} **{threat.get('indicator')}** - Score: {score}/100")
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
        if st.sidebar.button("🚪 Logout", type="primary"):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.user_role = None
            st.rerun()
    
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
    
    def run(self):
        """Main application runner"""
        try:
            # Load sample data if not loaded
            if not st.session_state.get('alerts_data'):
                self.load_sample_data()
            
            # Setup authentication if not done
            if not st.session_state.get('auth_init'):
                self.setup_authentication()
            
            # Check authentication - THIS IS THE KEY FIX
            if not st.session_state.authenticated:
                # Clear everything and show only login
                st.sidebar.empty()
                self.login_section()
                # STOP execution here - don't render anything else
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