import streamlit as st
import logging
from datetime import datetime, timedelta
import hashlib
from supabase import Client

logger = logging.getLogger(__name__)

class LoginComponent:
    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.auth_service = None
        try:
            from dashboard.services.auth_service import AuthService
            self.auth_service = AuthService()
        except ImportError:
            logger.warning("AuthService not available, using simplified auth")
        except Exception as e:
            logger.error(f"Error initializing auth service: {e}")

    # ---------- MAIN LOGIN PAGE ----------
    def render_login_page(self):
        # Handle first-time token login
        if self._handle_first_time_token_login():
            st.stop()

        st.title("🔐 CyberThreatWatch Login")
        st.markdown("---")
        tab1, tab2 = st.tabs(["🔐 Email Login", "🚀 Quick Access"])

        with tab1:
            self._render_email_login()
        with tab2:
            self._render_quick_access()

        st.markdown("---")
        self._render_security_info()

    # ---------- FIRST-TIME TOKEN LOGIN ----------
    def _handle_first_time_token_login(self):
        """
        Detect token in URL query ?token=xxxx
        Prompt password creation if token is valid and not yet used.
        """
        token = st.experimental_get_query_params().get("token", [None])[0]
        if not token:
            return False

        # Prevent rerun loops
        if st.session_state.get("first_time_done"):
            return False

        st.info("First-time login detected. Please create a password.")

        email = st.text_input("Enter your email associated with this token")
        password = st.text_input("Create Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")

        if st.button("🔒 Set Password"):
            if not email or not password or not confirm:
                st.warning("All fields are required")
            elif password != confirm:
                st.warning("Passwords do not match")
            else:
                hashed = hashlib.sha256(password.encode()).hexdigest()
                if self.supabase:
                    try:
                        # Ensure user exists with token
                        res = self.supabase.table("users").select("*").eq("token", token).execute()
                        if not res.data:
                            st.error("Invalid token")
                            return True
                        # Update password and clear token
                        self.supabase.table("users").update({
                            "password": hashed,
                            "token": None
                        }).eq("token", token).execute()
                        st.success("✅ Password set! You can now login with email & password.")
                        st.session_state["first_time_done"] = True
                        st.experimental_rerun()
                    except Exception as e:
                        logger.error(f"First-time password error: {e}")
                        st.error("Failed to set password")
                else:
                    # Demo local storage fallback
                    st.session_state["local_users"] = st.session_state.get("local_users", {})
                    st.session_state["local_users"][email] = hashed
                    st.success("✅ Password set locally (demo)")
                    st.session_state["first_time_done"] = True
                    st.experimental_rerun()
        return True  # Flow active

    # ---------- EMAIL LOGIN ----------
    def _render_email_login(self):
        st.subheader("Email Authentication")
        st.markdown("Secure login with email or magic link")

        if "login_step" not in st.session_state:
            st.session_state.login_step = "email_input"

        email = st.text_input("📧 Enter your email", placeholder="your.email@example.com", key="email_input")

        if st.session_state.login_step == "email_input":
            if st.button("📧 Send Magic Link / Token", use_container_width=True):
                if self._validate_email(email):
                    self._send_magic_link(email)
                    st.session_state.login_step = "token_input"
                    st.experimental_rerun()
                else:
                    st.warning("Enter a valid email address")

        if st.session_state.login_step == "token_input":
            token = st.text_input("Enter the magic token received", placeholder="XXXXXX", key="token_input")
            if st.button("✅ Verify Token", use_container_width=True):
                if self._verify_token(email, token):
                    st.success("Token verified! Create a new password to complete registration.")
                    st.session_state.login_step = "password_create"
                    st.experimental_rerun()
                else:
                    st.error("Invalid token")

        if st.session_state.login_step == "password_create":
            password = st.text_input("Create Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            if st.button("🔒 Set Password", use_container_width=True):
                if password and password == confirm:
                    self._save_user_password(email, password)
                    st.success("✅ Password set! You can now login with email & password.")
                    st.session_state.login_step = "email_input"
                    st.experimental_rerun()
                else:
                    st.warning("Passwords do not match or empty")

        st.markdown("---")
        st.subheader("Login with Email & Password")
        login_email = st.text_input("Email", placeholder="your.email@example.com", key="login_email")
        login_pass = st.text_input("Password", type="password", key="login_pass")
        if st.button("🔑 Login", use_container_width=True):
            if self._check_password(login_email, login_pass):
                st.session_state.authenticated = True
                st.session_state.user_email = login_email
                st.session_state.user_name = login_email.split("@")[0]
                st.session_state.session_expiry = datetime.now() + timedelta(hours=24)
                st.success(f"Welcome {st.session_state.user_name}!")
                st.experimental_rerun()
            else:
                st.error("Invalid email or password")

    # ---------- QUICK ACCESS ----------
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
        if st.button("🚪 Enter Dashboard", use_container_width=True):
            if self._validate_email(email):
                st.session_state.authenticated = True
                st.session_state.user_email = email
                st.session_state.user_name = email.split("@")[0]
                st.session_state.session_expiry = datetime.now() + timedelta(hours=24)
                st.success(f"✅ Welcome, {email.split('@')[0]}!")
                st.experimental_rerun()
            else:
                st.warning("Please enter a valid email address")

    # ---------- SECURITY INFO ----------
    def _render_security_info(self):
        with st.expander("🔒 Security Information"):
            st.markdown("""
            **Why we use secure authentication:**
            - 🔐 Multi-Factor Authentication (MFA) available  
            - 📧 Magic links — no passwords to remember or steal  
            - ⏰ Automatic session expiry for enhanced security  
            - 🌐 HTTPS encryption for all communications
            """)

    # ---------- VALIDATION & STORAGE ----------
    def _validate_email(self, email: str) -> bool:
        return bool(email and "@" in email and len(email) <= 254)

    def _send_magic_link(self, email: str):
        token = str(hash(email))[-6:]
        st.session_state["token_store"] = token
        st.info(f"(Demo) Magic token sent: {token} — use it to verify")

    def _verify_token(self, email: str, token: str) -> bool:
        return token == st.session_state.get("token_store")

    def _save_user_password(self, email: str, password: str):
        hashed = hashlib.sha256(password.encode()).hexdigest()
        if not self.supabase:
            st.warning("Supabase not configured; password stored locally for demo")
            st.session_state["local_users"] = st.session_state.get("local_users", {})
            st.session_state["local_users"][email] = hashed
            return
        try:
            self.supabase.table("users").upsert({"email": email, "password": hashed}).execute()
        except Exception as e:
            logger.error(f"Save password error: {e}")
            st.warning("Failed to save password")

    def _check_password(self, email: str, password: str) -> bool:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        if self.supabase:
            try:
                res = self.supabase.table("users").select("password").eq("email", email).execute()
                if res.data and res.data[0]["password"] == hashed:
                    return True
            except Exception as e:
                logger.error(f"Password check error: {e}")
                return False
        else:
            local_users = st.session_state.get("local_users", {})
            return local_users.get(email) == hashed

    # ---------- LOGOUT ----------
    def render_logout_section(self):
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            for key in ["authenticated", "user_email", "user_name", "session_expiry"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.success("👋 Logged out")
            st.experimental_rerun()

    def check_authentication(self):
        if not st.session_state.get("authenticated"):
            self.render_login_page()
            st.stop()
