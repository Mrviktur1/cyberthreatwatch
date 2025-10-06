import streamlit as st
import logging
from datetime import datetime, timedelta

# ✅ Import hCaptcha component
from dashboard.components.captcha_component import st_hcaptcha
from dashboard.components import auth  # your new auth.py

# Configure logging
logger = logging.getLogger(__name__)


class LoginComponent:
    def __init__(self):
        self.auth_service = None
        # Try to import AuthService if available
        try:
            from dashboard.services.auth_service import AuthService
            self.auth_service = AuthService()
        except ImportError:
            logger.warning("AuthService not available, using simplified auth")
        except Exception as e:
            logger.error(f"Error initializing AuthService: {e}")

    def render_login_page(self):
        st.title("🔐 CyberThreatWatch Login")
        st.markdown("---")

        tab1, tab2 = st.tabs(["🔐 Email Login", "🚀 Quick Access"])
        with tab1:
            self._render_email_login()
        with tab2:
            self._render_quick_access()

        st.markdown("---")
        self._render_security_info()

    def _render_email_login(self):
        st.subheader("Email Authentication")
        st.markdown("Secure login with magic link sent to your email")

        email = st.text_input(
            "📧 Enter your email address",
            placeholder="your.email@example.com",
            key="email_login_input"
        )

        # ✅ hCaptcha verification
        st.markdown("### Human Verification")
        captcha_token = st_hcaptcha(site_key=st.secrets.get("HCAPTCHA_SITE_KEY", ""))

        col1, col2 = st.columns([1, 2])
        with col1:
            if st.button("📧 Send Magic Link", use_container_width=True):
                if not captcha_token:
                    st.warning("⚠️ Please complete the CAPTCHA first.")
                elif self._validate_email(email):
                    auth.send_magic_link(email=email)  # use updated auth.py
                else:
                    st.warning("Please enter a valid email address")

        with col2:
            if st.button("🔄 Check for Magic Link", use_container_width=True):
                st.info("If you've received a magic link, it should authenticate automatically.")
                st.rerun()

    def _render_quick_access(self):
        st.subheader("Quick Access")
        st.info("Development mode - simplified authentication")

        demo_email = st.selectbox(
            "Choose demo user or enter custom email:",
            [
                "analyst@cyberthreatwatch.com",
                "admin@cyberthreatwatch.com",
                "security@cyberthreatwatch.com",
                "custom"
            ]
        )

        email = demo_email
        if demo_email == "custom":
            custom_email = st.text_input("Enter custom email:", placeholder="user@example.com")
            email = custom_email

        if st.button("🚪 Enter Dashboard", type="primary", use_container_width=True):
            if self._validate_email(email):
                auth.quick_login(email=email)
            else:
                st.warning("Please enter a valid email address")

    def _render_security_info(self):
        with st.expander("🔒 Security Information"):
            st.markdown("""
            **Why we use secure authentication:**
            - 🔐 **Multi-Factor Authentication** (MFA) available  
            - 📧 **Magic links** - no passwords to remember or steal  
            - ⏰ **Automatic session expiry** for security  
            - 🌐 **HTTPS encryption** for all communications  

            **Your data is protected by:**
            - Enterprise-grade security protocols  
            - Regular security audits  
            - Compliance with industry standards  
            """)

    def _validate_email(self, email: str) -> bool:
        if not email or "@" not in email:
            return False
        if len(email) > 254:
            return False
        return True

    def render_logout_section(self):
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            auth.logout()
            st.rerun()

        if st.session_state.get("authenticated"):
            st.sidebar.markdown("---")
            st.sidebar.markdown("### 👤 User Info")
            st.sidebar.markdown(f"**Email:** {st.session_state.user_email}")
            st.sidebar.markdown(f"**Name:** {st.session_state.user_name}")

            expiry = st.session_state.get("session_expiry")
            if expiry:
                time_left = expiry - datetime.now()
                hours_left = max(0, int(time_left.total_seconds() / 3600))
                st.sidebar.markdown(f"**Session expires in:** {hours_left} hours")

    def check_authentication(self):
        """Check session state for authentication & MFA."""
        # Handle magic link callback
        auth.handle_magic_link_callback()

        if not st.session_state.get("authenticated", False):
            self.render_login_page()
            st.stop()

        # Handle MFA
        if st.session_state.get("mfa_enabled", False) and not st.session_state.get("mfa_verified", False):
            st.warning("🔐 MFA Verification Required")
            if auth.verify_mfa():
                st.rerun()
            st.stop()