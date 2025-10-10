import streamlit as st
from supabase import create_client, Client
import pyotp
import qrcode
import io
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

# --- Configure logging ---
logger = logging.getLogger(__name__)

# --- Initialize Supabase Client ---
@st.cache_resource
def get_supabase() -> Client:
    """Initialize and return Supabase client."""
    try:
        if "SUPABASE_URL" in st.secrets and "SUPABASE_KEY" in st.secrets:
            url = st.secrets["SUPABASE_URL"]
            key = st.secrets["SUPABASE_KEY"]
            client = create_client(url, key)
            logger.info("✅ Supabase client initialized successfully")
            return client
        else:
            st.error("❌ Missing Supabase credentials in Streamlit secrets.")
            return None
    except Exception as e:
        logger.error(f"Supabase initialization failed: {e}")
        return None


supabase = get_supabase()

# --- Initialize session state ---
def initialize_session_state():
    defaults = {
        "user": None,
        "user_email": "",
        "user_name": "",
        "user_type": "",
        "authenticated": False,
        "mfa_enabled": False,
        "mfa_verified": False,
        "session_expiry": None
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


initialize_session_state()

# --- Authentication helpers ---
def is_authenticated() -> bool:
    """Check if user session is valid."""
    if not st.session_state.get("authenticated"):
        return False
    expiry = st.session_state.get("session_expiry")
    if expiry and datetime.now() > expiry:
        logout()
        return False
    return True


def get_current_user() -> Optional[Dict[str, Any]]:
    """Return current user info."""
    if is_authenticated():
        return {
            "email": st.session_state.user_email,
            "name": st.session_state.user_name,
            "type": st.session_state.user_type
        }
    return None


# --- Registration (Email Verification via Supabase) ---
def register_user(email: str, password: str, full_name: str, user_type: str, phone: str, address: str, business_or_school: str):
    """
    Register a user with email/password and trigger Supabase email verification.
    """
    if not supabase:
        st.error("Database not connected.")
        return False

    try:
        # Sign up user with Supabase Auth (triggers verification email)
        res = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "email_redirect_to": get_redirect_url(),
                "data": {
                    "full_name": full_name,
                    "user_type": user_type,
                    "phone": phone,
                    "address": address,
                    "business_or_school": business_or_school
                }
            }
        })

        if res and res.user:
            st.success("✅ Registration successful! Check your email to verify your account.")

            # Store user in custom 'users' table for analytics and separation
            try:
                supabase.table("users").insert({
                    "email": email,
                    "full_name": full_name,
                    "user_type": user_type,
                    "phone": phone,
                    "address": address,
                    "business_or_school": business_or_school,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.warning(f"User insert warning: {e}")

            return True
        else:
            st.error("❌ Registration failed. Try again.")
            return False

    except Exception as e:
        logger.error(f"Registration error: {e}")
        st.error(f"Error: {e}")
        return False


# --- Login ---
def login_user(email_or_username: str, password: str):
    """Login with email or username."""
    if not supabase:
        st.error("Database not connected.")
        return False

    try:
        # If user entered username, look up email
        if "@" not in email_or_username:
            user_lookup = supabase.table("users").select("email").eq("full_name", email_or_username).execute()
            if user_lookup.data:
                email_or_username = user_lookup.data[0]["email"]
            else:
                st.error("❌ Invalid username or email.")
                return False

        # Authenticate user
        res = supabase.auth.sign_in_with_password({
            "email": email_or_username,
            "password": password
        })

        if res and res.user:
            set_user_session(res.user)
            st.success("🎉 Login successful!")
            return True
        else:
            st.error("❌ Invalid credentials or unverified email.")
            return False

    except Exception as e:
        logger.error(f"Login error: {e}")
        st.error(f"Login failed: {e}")
        return False


# --- Session handling ---
def set_user_session(user_data):
    """Set active user session."""
    st.session_state.authenticated = True
    st.session_state.user_email = user_data.email
    st.session_state.user_name = user_data.user_metadata.get("full_name", "")
    st.session_state.user_type = user_data.user_metadata.get("user_type", "")
    st.session_state.session_expiry = datetime.now() + timedelta(hours=24)
    logger.info(f"User session started for {st.session_state.user_email}")


def logout():
    """Sign out and clear session."""
    try:
        supabase.auth.sign_out()
    except Exception as e:
        logger.warning(f"Logout error: {e}")
    st.session_state.clear()
    st.success("👋 You have been logged out.")
    st.rerun()


# --- Redirect URL for verification ---
def get_redirect_url() -> str:
    try:
        ctx = st.runtime.get_instance()._runtime.state
        origin = getattr(ctx, "browser_server_address", "http://localhost:8501")
        return origin
    except Exception:
        return "http://localhost:8501"
