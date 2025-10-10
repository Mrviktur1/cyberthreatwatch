import streamlit as st
import logging
import hashlib
from datetime import datetime, timedelta
from supabase import Client

logger = logging.getLogger(__name__)

class LoginComponent:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    # ---------- MAIN AUTH HANDLER ----------
    def render_auth_page(self):
        st.title("🔐 CyberThreatWatch Account Portal")
        st.markdown("Securely register or sign in to access your dashboard.")

        tab1, tab2 = st.tabs(["🆕 Create Account", "🔑 Login"])
        with tab1:
            self._render_signup()
        with tab2:
            self._render_login()

    # ---------- SIGNUP ----------
    def _render_signup(self):
        st.subheader("Create an Account")

        with st.form("signup_form", clear_on_submit=False):
            full_name = st.text_input("Full Name", key="signup_full_name")
            username = st.text_input("Username (unique)", key="signup_username")
            email = st.text_input("Email Address", key="signup_email")
            phone = st.text_input("Phone Number", key="signup_phone")
            account_type = st.selectbox("Account Type", ["Student", "Business"], key="signup_type")
            org_name = st.text_input(
                "School Name" if account_type == "Student" else "Business Name",
                key="signup_org",
            )
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm")

            submitted = st.form_submit_button("🚀 Register")

            if submitted:
                # Validation
                if not all([full_name, username, email, phone, org_name, password, confirm_password]):
                    st.warning("⚠️ Please complete all fields.")
                    return

                if password != confirm_password:
                    st.error("❌ Passwords do not match.")
                    return

                if not self._validate_email(email):
                    st.error("❌ Invalid email address.")
                    return

                hashed_pw = hashlib.sha256(password.encode()).hexdigest()

                try:
                    # Step 1: Create user in Supabase Auth
                    auth_res = self.supabase.auth.sign_up({
                        "email": email,
                        "password": password,
                    })

                    # Handle auth errors
                    if getattr(auth_res, "error", None):
                        logger.error(f"Auth signup error: {auth_res.error}")
                        st.error(f"Auth signup failed: {auth_res.error.get('message', 'Please try again')}")
                        return

                    if not auth_res or not getattr(auth_res, "user", None):
                        st.error("❌ Account creation failed. Please try again.")
                        return

                    user_id = auth_res.user.id

                    # Step 2: Insert into public.users table
                    payload = {
                        "id": user_id,
                        "full_name": full_name,     # ✅ use full_name instead of name
                        "username": username,
                        "email": email,
                        "phone": phone,
                        "account_type": account_type,
                        "organization_name": org_name,
                        "password_hash": hashed_pw,
                    }

                    insert_res = self.supabase.table("users").insert(payload).execute()

                    if getattr(insert_res, "error", None):
                        logger.error(f"DB insert error: {insert_res.error}")
                        st.error(f"Signup failed: {insert_res.error.get('message', 'Database error')}")
                        return

                    st.success("✅ Account created successfully! Please verify your email before logging in.")

                except Exception as e:
                    logger.error(f"Signup error: {e}")
                    st.error("⚠️ An error occurred during signup. Please try again later.")

    # ---------- LOGIN ----------
    def _render_login(self):
        st.subheader("Login to Your Account")

        with st.form("login_form", clear_on_submit=False):
            login_input = st.text_input("Email or Username", key="login_input")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("🔓 Login")

            if submitted:
                if not login_input or not password:
                    st.warning("Please enter both email/username and password.")
                    return

                try:
                    # Determine whether the login input is email or username
                    if "@" in login_input:
                        res = self.supabase.table("users").select("*").eq("email", login_input).execute()
                    else:
                        res = self.supabase.table("users").select("*").eq("username", login_input).execute()

                    if not res.data:
                        st.error("Account not found.")
                        return

                    user = res.data[0]
                    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

                    if hashed_pw != user.get("password_hash"):
                        st.error("Incorrect password.")
                        return

                    # Verify via Supabase Auth
                    try:
                        auth_user = self.supabase.auth.sign_in_with_password({
                            "email": user["email"],
                            "password": password,
                        })
                        if not auth_user or not getattr(auth_user, "user", None):
                            st.error("Please verify your email before logging in.")
                            return
                    except Exception:
                        st.warning("Please verify your email before logging in.")
                        return

                    # Save session data
                    st.session_state.authenticated = True
                    st.session_state.user_id = user["id"]
                    st.session_state.user_email = user["email"]
                    st.session_state.user_name = user["full_name"]
                    st.session_state.account_type = user["account_type"]
                    st.session_state.organization = user["organization_name"]
                    st.session_state.session_expiry = datetime.now() + timedelta(hours=24)

                    st.success(f"✅ Welcome back, {user['full_name']}!")
                    st.experimental_rerun()

                except Exception as e:
                    logger.error(f"Login error: {e}")
                    st.error("Login failed. Please try again later.")

    # ---------- LOGOUT ----------
    def render_logout_section(self):
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            for key in list(st.session_state.keys()):
                if key in [
                    "authenticated", "user_id", "user_email", "user_name",
                    "account_type", "organization", "session_expiry"
                ]:
                    del st.session_state[key]
            st.success("👋 Logged out successfully.")
            st.experimental_rerun()

    # ---------- UTILITIES ----------
    def _validate_email(self, email: str) -> bool:
        return bool(email and "@" in email and "." in email and len(email) <= 254)

    def check_authentication(self):
        """Check if user is authenticated; if not, show login/register."""
        if not st.session_state.get("authenticated"):
            self.render_auth_page()
            st.stop()
