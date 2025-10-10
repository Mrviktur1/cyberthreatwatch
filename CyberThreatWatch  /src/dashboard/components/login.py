import streamlit as st
import logging
import hashlib
import time
from datetime import datetime, timedelta
from supabase import Client, create_client

logger = logging.getLogger(__name__)

# ======================================================
# EMAIL VERIFICATION HANDLER (runs when link clicked)
# ======================================================
def handle_email_verification():
    """Handle Supabase email verification redirect."""
    query_params = st.query_params
    if "access_token" in query_params:
        st.markdown("<style>div.block-container {text-align:center;}</style>", unsafe_allow_html=True)

        st.success("✅ Email verified successfully!")

        st.image("assets/CyberThreatWatch.png", width=180)
        st.markdown("<h2 style='color:#013047;'>Welcome to <b>CyberThreatWatch</b></h2>", unsafe_allow_html=True)
        st.markdown(
            "Your account has been verified successfully.<br>Redirecting to your dashboard...",
            unsafe_allow_html=True,
        )

        # Loading animation for 4–5 seconds
        progress_text = "Loading your secure dashboard..."
        progress_bar = st.progress(0)
        for percent_complete in range(100):
            time.sleep(0.04)  # ~4 seconds
            progress_bar.progress(percent_complete + 1, text=progress_text)

        st.session_state.authenticated = True
        st.switch_page("dashboard.py")  # Redirect to dashboard page


# ======================================================
# MAIN LOGIN COMPONENT
# ======================================================
class LoginComponent:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    # ---------- AUTH HANDLER ----------
    def render_auth_page(self):
        handle_email_verification()

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

                    auth_error = getattr(auth_res, "error", None)
                    if not auth_error and isinstance(auth_res, dict):
                        auth_error = auth_res.get("error")

                    if auth_error:
                        st.error(f"Auth signup failed: {auth_error.get('message', 'Please try again')}")
                        return

                    # Extract user object safely
                    user_obj = getattr(auth_res, "user", None)
                    if not user_obj and isinstance(auth_res, dict):
                        user_obj = auth_res.get("user")

                    if not user_obj:
                        st.error("❌ Account creation failed. Please try again.")
                        return

                    user_id = getattr(user_obj, "id", None) or (isinstance(user_obj, dict) and user_obj.get("id"))
                    if not user_id:
                        st.error("❌ Missing user ID from signup response.")
                        return

                    # Step 2: Store profile in users table
                    session = self.supabase.auth.get_session()
                    access_token = None

                    if session and hasattr(session, "access_token"):
                        access_token = session.access_token
                    elif isinstance(session, dict):
                        access_token = session.get("access_token")

                    if not access_token:
                        st.info(
                            "✅ Account created successfully! Please check your email to verify your account. "
                            "You’ll be able to log in after verification."
                        )
                        return

                    # Authenticated insert
                    user_supabase = create_client(
                        self.supabase.supabase_url,
                        self.supabase.supabase_key,
                        options={"headers": {"Authorization": f"Bearer {access_token}"}}
                    )

                    payload = {
                        "id": user_id,
                        "full_name": full_name,
                        "username": username,
                        "email": email,
                        "phone": phone,
                        "account_type": account_type,
                        "organization_name": org_name,
                        "password_hash": hashed_pw,
                    }

                    insert_res = user_supabase.table("users").insert(payload).execute()
                    st.success("✅ Account created successfully! Please verify your email before logging in.")

                except Exception as e:
                    logger.exception(f"Signup error: {e}")
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
                    # Check if email or username
                    if "@" in login_input:
                        res = self.supabase.table("users").select("*").eq("email", login_input).execute()
                    else:
                        res = self.supabase.table("users").select("*").eq("username", login_input).execute()

                    res_data = getattr(res, "data", None)
                    if not res_data and isinstance(res, dict):
                        res_data = res.get("data")

                    if not res_data:
                        st.error("Account not found.")
                        return

                    user = res_data[0]
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
                        if hasattr(auth_user, "error") and getattr(auth_user, "error"):
                            st.warning("Please verify your email before logging in.")
                            return
                    except Exception as e:
                        logger.warning(f"Auth signin exception: {e}")
                        st.warning("Please verify your email before logging in.")
                        return

                    # Save session data
                    st.session_state.authenticated = True
                    st.session_state.user_id = user["id"]
                    st.session_state.user_email = user["email"]
                    st.session_state.user_name = user.get("full_name") or user.get("username")
                    st.session_state.account_type = user.get("account_type")
                    st.session_state.organization = user.get("organization_name")
                    st.session_state.session_expiry = datetime.now() + timedelta(hours=24)

                    # Show animation + redirect
                    st.success(f"✅ Welcome back, {st.session_state.user_name}!")
                    with st.spinner("Redirecting to your dashboard..."):
                        time.sleep(2)
                    st.switch_page("dashboard.py")

                except Exception as e:
                    logger.exception(f"Login error: {e}")
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
            st.switch_page("main.py")  # Return to main or login page

    # ---------- UTILITIES ----------
    def _validate_email(self, email: str) -> bool:
        return bool(email and "@" in email and "." in email and len(email) <= 254)

    def check_authentication(self):
        """Check if user is authenticated; if not, show login/register."""
        if not st.session_state.get("authenticated"):
            self.render_auth_page()
            st.stop()
