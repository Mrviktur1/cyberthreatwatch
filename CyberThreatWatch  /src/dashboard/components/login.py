import streamlit as st
import logging
from datetime import datetime, timedelta

# ✅ Import hCaptcha component
from dashboard.components.captcha_component import st_hcaptcha

# Configure logging
logger = logging.getLogger(__name__)


class LoginComponent:
    def __init__(self):
        self.auth_service = None
        try:
            from dashboard.services.auth_service import AuthService
            self.auth_service = AuthService()
        except ImportError:
            logger.warning("AuthService not available, using simplified auth")
        except Exception as e:
            logger.error(f"Error initializing auth service: {e}")

    def render_login_page(self):
        """Render the main login page with multiple options."""
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

        # ✅ Add CAPTCHA for Email Login
        st.markdown("### Human Verification")
        captcha_token = st_hcaptcha(site_key=st.secrets["HCAPTCHA_SITE_KEY"])

        col1, col2 = st.columns([1, 2])
        with col1:
            if st.button("📧 Send Magic Link", use_container_width=True):
                if not captcha_token:
                    st.warning("⚠️ Please complete the CAPTCHA first.")
                elif self._validate_email(email):
                    self._send_magic_link(email, captcha_token)
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

        if demo_email == "custom":
            custom_email = st.text_input("Enter custom email:", placeholder="user@example.com")
            email = custom_email
        else:
            email = demo_email

        # ✅ Add CAPTCHA for Quick Access
        st.markdown("### Human Verification")
        captcha_token = st_hcaptcha(site_key=st.secrets["HCAPTCHA_SITE_KEY"])

        if st.button("🚪 Enter Dashboard", type="primary", use_container_width=True):
            if not captcha_token:
                st.warning("⚠️ Please complete the CAPTCHA first.")
            elif self._validate_email(email):
                self._quick_login(email)
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

    def _send_magic_link(self, email: str, captcha_token=None):
        try:
            if self.auth_service:
                success = self.auth_service.send_magic_link(email)
                if success:
                    st.success(f"📧 Magic link sent to {email}")
                else:
                    st.error("❌ Failed to send magic link")
            else:
                from dashboard.components import auth
                success = auth.send_magic_link(email, captcha_token=captcha_token)
                if success:
                    st.success(f"📧 Magic link sent to {email}")
                else:
                    st.error("❌ Failed to send magic link")
        except Exception as e:
            logger.error(f"Error sending magic link: {e}")
            st.error(f"❌ Error sending magic link: {str(e)}")

    def _quick_login(self, email: str):
        try:
            from dashboard.components import auth
            if hasattr(auth, 'quick_login'):
                success = auth.quick_login(email)
            else:
                st.session_state.authenticated = True
                st.session_state.user_email = email
                st.session_state.user_name = email.split('@')[0]
                st.session_state.mfa_enabled = True
                st.session_state.mfa_verified = True
                st.session_state.session_expiry = datetime.now() + timedelta(hours=24)
                success = True

            if success:
                st.success(f"✅ Welcome, {email.split('@')[0]}!")
                st.rerun()
            else:
                st.error("❌ Login failed")
        except Exception as e:
            logger.error(f"Quick login error: {e}")
            st.error(f"❌ Login error: {str(e)}")

    def handle_oauth_callback(self):
        try:
            query_params = st.query_params
            if query_params.get('code') and query_params.get('state'):
                if self.auth_service:
                    self.auth_service.handle_oauth_callback()
        except Exception as e:
            logger.error(f"OAuth callback error: {e}")

    def render_logout_section(self):
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            self._perform_logout()
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

    def _perform_logout(self):
        try:
            from dashboard.components import auth
            auth.logout()
            st.success("👋 You have been logged out successfully!")
            st.rerun()
        except Exception as e:
            logger.error(f"Logout error: {e}")
            for key in ['authenticated', 'user_email', 'user_name', 'mfa_enabled', 'mfa_verified']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

    def check_authentication(self):
        self.handle_oauth_callback()
        from dashboard.components import auth
        if not auth.is_authenticated():
            self.render_login_page()
            st.stop()
        if not self._check_mfa_requirements():
            st.stop()

    def _check_mfa_requirements(self):
        from dashboard.components import auth
        if not st.session_state.get("mfa_enabled", False):
            return True
        if not st.session_state.get("mfa_verified", False):
            st.warning("🔐 MFA Verification Required")
            if auth.verify_mfa():
                st.rerun()
            return False
        return True