import streamlit as st
from supabase import create_client, Client
import pyotp
import qrcode
import io
import os

# --- Supabase Client ---
@st.cache_resource
def get_supabase() -> Client:
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = get_supabase()

# --- Authentication Helpers ---
def is_authenticated():
    """Check if a user session exists."""
    return "user" in st.session_state and st.session_state.user is not None

def get_current_user():
    """Return the logged-in user."""
    return st.session_state.get("user")

def send_magic_link(email: str):
    """Send a Supabase magic link to user's email."""
    try:
        res = supabase.auth.sign_in_with_otp({"email": email})
        if res:
            st.info(f"📧 Magic link sent to {email}. Check your inbox.")
    except Exception as e:
        st.error(f"Magic link error: {e}")

def logout():
    """Clear session state and log out user."""
    st.session_state.user = None
    st.session_state.mfa_enabled = False
    st.session_state.mfa_verified = False
    st.session_state.mfa_secret = None

def get_user_by_email(email: str):
    """Fetch a user from Supabase users table (optional)."""
    try:
        data = supabase.table("users").select("*").eq("email", email).execute()
        if data.data:
            return data.data[0]
        return None
    except Exception:
        return None

# --- MFA Functions ---
def enroll_mfa():
    """
    Setup MFA for the user. Show QR and fallback secret.
    Returns True when MFA is enabled.
    """
    if "mfa_secret" not in st.session_state or not st.session_state.mfa_secret:
        st.session_state.mfa_secret = pyotp.random_base32()

    secret = st.session_state.mfa_secret
    user = get_current_user()
    email = user.get("email", "user@example.com")

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="CyberThreatWatch")

    # Generate QR code
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    st.image(buf.getvalue(), caption="Scan this QR with your Authenticator app")

    st.write("Or manually enter this secret key:")
    st.code(secret)

    code = st.text_input("Enter the 6-digit code from your Authenticator app", type="password")
    if st.button("✅ Verify MFA Setup"):
        if totp.verify(code):
            st.success("MFA enabled successfully ✅")
            st.session_state.mfa_enabled = True
            return True
        else:
            st.error("❌ Invalid code, try again.")
    return False

def verify_mfa():
    """Verify user-provided MFA code."""
    secret = st.session_state.get("mfa_secret")
    if not secret:
        st.error("No MFA secret found. Please enroll first.")
        return False

    totp = pyotp.TOTP(secret)
    code = st.text_input("Enter your 6-digit MFA code", type="password")

    if st.button("🔑 Verify Code"):
        if totp.verify(code):
            st.success("MFA verified 🎉")
            st.session_state.mfa_verified = True
            return True
        else:
            st.error("❌ Invalid MFA code.")
    return False
