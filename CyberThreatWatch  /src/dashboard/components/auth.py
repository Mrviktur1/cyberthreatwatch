import streamlit as st
from supabase import create_client, Client
import pyotp
import qrcode
import io
import os
import logging
from typing import Optional, Dict, Any

# Configure logging
logger = logging.getLogger(__name__)


# --- Supabase Client ---
@st.cache_resource
def get_supabase() -> Client:
    """Initialize and return Supabase client with error handling."""
    try:
        if "SUPABASE_URL" in st.secrets and "SUPABASE_KEY" in st.secrets:
            url = st.secrets["SUPABASE_URL"]
            key = st.secrets["SUPABASE_KEY"]
            client = create_client(url, key)

            # Test connection
            try:
                # Simple test query that should work with anon key
                result = client.from_('alerts').select('id', count='exact').limit(1).execute()
                logger.info("Supabase client initialized successfully")
            except Exception as query_error:
                logger.warning(f"Supabase test query failed (may be normal): {query_error}")

            return client
        else:
            logger.error("Supabase credentials not found in secrets")
            return None
    except Exception as e:
        logger.error(f"Supabase client initialization failed: {e}")
        return None


supabase = get_supabase()


# --- Session State Initialization ---
def initialize_session_state():
    """Initialize all required session state variables."""
    defaults = {
        "user": None,
        "user_email": "",
        "user_name": "",
        "user_picture": None,
        "authenticated": False,
        "mfa_enabled": False,
        "mfa_verified": False,
        "mfa_secret": None,
        "session_expiry": None,
        "auth_initialized": True
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# Initialize session state
initialize_session_state()


# --- Authentication Helpers ---
def is_authenticated() -> bool:
    """Check if user is authenticated with valid session."""
    if not st.session_state.get("authenticated"):
        return False

    # Check session expiry
    expiry = st.session_state.get("session_expiry")
    if expiry:
        from datetime import datetime
        if datetime.now() > expiry:
            logout()
            return False

    return True


def get_current_user() -> Optional[Dict[str, Any]]:
    """Return current user information."""
    if is_authenticated():
        return {
            "email": st.session_state.user_email,
            "name": st.session_state.user_name,
            "picture": st.session_state.user_picture
        }
    return None


def send_magic_link(email: str) -> bool:
    """Send a Supabase magic link to user's email."""
    if not supabase:
        st.error("❌ Database connection not available")
        return False

    try:
        if not email or "@" not in email:
            st.warning("⚠️ Please enter a valid email address")
            return False

        # Validate email format
        if len(email) > 254:  # RFC 5321 limit
            st.warning("⚠️ Email address too long")
            return False

        # Send magic link
        res = supabase.auth.sign_in_with_otp({
            "email": email,
            "options": {
                "email_redirect_to": get_redirect_url()
            }
        })

        if res:
            st.success(f"📧 Magic link sent to {email}")
            logger.info(f"Magic link sent to {email}")
            return True
        else:
            st.error("❌ Failed to send magic link")
            return False

    except Exception as e:
        error_msg = str(e).lower()
        if "rate limit" in error_msg:
            st.warning("⏳ Rate limit exceeded. Please try again in a few minutes.")
        elif "invalid email" in error_msg:
            st.warning("⚠️ Please enter a valid email address")
        else:
            st.error(f"❌ Error sending magic link: {e}")
        logger.error(f"Magic link error for {email}: {e}")
        return False


def get_redirect_url() -> str:
    """Get the appropriate redirect URL based on environment."""
    try:
        # For Streamlit Cloud deployment
        if 'streamlit.app' in st.get_script_run_ctx().request.origin:
            return st.get_script_run_ctx().request.origin
        # For local development
        else:
            return "http://localhost:8501"
    except:
        return "http://localhost:8501"  # Fallback


def handle_magic_link_callback():
    """Handle magic link authentication callback."""
    try:
        query_params = st.experimental_get_query_params()
        if query_params.get('token') and query_params.get('type') == 'magiclink':
            token = query_params['token'][0]

            # Exchange token for session
            session = supabase.auth.set_session(token)
            if session and session.user:
                set_user_session(session.user)
                st.experimental_set_query_params()  # Clear URL parameters
                st.rerun()

    except Exception as e:
        logger.error(f"Magic link callback error: {e}")


def set_user_session(user_data):
    """Set user session after successful authentication."""
    st.session_state.authenticated = True
    st.session_state.user_email = user_data.get('email', '')
    st.session_state.user_name = user_data.get('user_metadata', {}).get('full_name',
                                                                        user_data.get('email', '').split('@')[0])
    st.session_state.user_picture = user_data.get('user_metadata', {}).get('avatar_url')

    # Set session expiry (24 hours)
    from datetime import datetime, timedelta
    st.session_state.session_expiry = datetime.now() + timedelta(hours=24)

    logger.info(f"User session created for: {st.session_state.user_email}")


def logout():
    """Clear session state and log out user."""
    try:
        if supabase:
            supabase.auth.sign_out()

        # Clear all session state
        keys_to_clear = [
            "user", "user_email", "user_name", "user_picture",
            "authenticated", "mfa_enabled", "mfa_verified",
            "mfa_secret", "session_expiry"
        ]

        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]

        logger.info("User logged out successfully")
        st.success("👋 You have been logged out")

    except Exception as e:
        logger.error(f"Logout error: {e}")
        # Force clear session state even if logout fails
        st.session_state.clear()
        st.rerun()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetch a user from Supabase users table."""
    if not supabase:
        return None

    try:
        data = supabase.table("users").select("*").eq("email", email).execute()
        return data.data[0] if data.data else None
    except Exception as e:
        logger.error(f"Error fetching user {email}: {e}")
        return None


# --- MFA Functions ---
def enroll_mfa() -> bool:
    """
    Setup MFA for the user. Show QR and fallback secret.
    Returns True when MFA is successfully enabled.
    """
    if not st.session_state.get("authenticated"):
        st.error("❌ Please log in first")
        return False

    # Generate or reuse MFA secret
    if "mfa_secret" not in st.session_state or not st.session_state.mfa_secret:
        st.session_state.mfa_secret = pyotp.random_base32()

    secret = st.session_state.mfa_secret
    user_email = st.session_state.user_email

    # Create TOTP instance
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user_email, issuer_name="CyberThreatWatch")

    st.subheader("🔐 Multi-Factor Authentication Setup")
    st.info("Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)")

    # Generate QR code
    try:
        qr = qrcode.make(uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        st.image(buf.getvalue(), caption="Scan with your authenticator app", width=200)
    except Exception as e:
        logger.error(f"QR code generation error: {e}")
        st.warning("Could not generate QR code. Please use the secret key below.")

    # Manual entry option
    st.write("**Manual entry:**")
    st.code(secret, language="text")
    st.info("If you can't scan the QR code, manually enter the secret above into your authenticator app.")

    # Verification
    st.markdown("---")
    st.subheader("Verify Setup")
    code = st.text_input(
        "Enter the 6-digit code from your authenticator app",
        placeholder="123456",
        max_chars=6,
        type="password"
    )

    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("✅ Verify MFA", use_container_width=True):
            if len(code) != 6 or not code.isdigit():
                st.error("❌ Please enter a valid 6-digit code")
                return False

            if totp.verify(code):
                st.session_state.mfa_enabled = True
                st.session_state.mfa_verified = True
                st.success("🎉 MFA enabled successfully!")
                logger.info(f"MFA enabled for user: {user_email}")
                return True
            else:
                st.error("❌ Invalid code. Please try again.")
                return False

    with col2:
        if st.button("🔄 Generate New Secret", use_container_width=True):
            st.session_state.mfa_secret = pyotp.random_base32()
            st.rerun()

    return False


def verify_mfa() -> bool:
    """Verify user-provided MFA code."""
    if not st.session_state.get("mfa_enabled"):
        st.error("❌ MFA not enabled for this account")
        return False

    secret = st.session_state.get("mfa_secret")
    if not secret:
        st.error("❌ No MFA secret found. Please enroll first.")
        return False

    totp = pyotp.TOTP(secret)

    st.subheader("🔑 MFA Verification Required")
    code = st.text_input(
        "Enter your 6-digit MFA code",
        placeholder="000000",
        max_chars=6,
        type="password",
        key="mfa_verify_input"
    )

    if st.button("🔐 Verify Code", type="primary", use_container_width=True):
        if len(code) != 6 or not code.isdigit():
            st.error("❌ Please enter a valid 6-digit code")
            return False

        if totp.verify(code):
            st.session_state.mfa_verified = True
            st.success("✅ MFA verified successfully!")
            return True
        else:
            st.error("❌ Invalid MFA code. Please try again.")
            return False

    return False


def should_enforce_mfa() -> bool:
    """Determine if MFA should be enforced for the current user."""
    # For now, make MFA optional for better user experience
    return False  # Change to True to enforce MFA


# --- Simplified Authentication for Development ---
def quick_login(email: str) -> bool:
    """
    Quick login for development/demo purposes.
    Bypasses full auth flow for easier testing.
    """
    if not email or "@" not in email:
        st.warning("⚠️ Please enter a valid email address")
        return False

    try:
        st.session_state.authenticated = True
        st.session_state.user_email = email
        st.session_state.user_name = email.split('@')[0]
        st.session_state.mfa_enabled = True  # Skip MFA for dev
        st.session_state.mfa_verified = True

        from datetime import datetime, timedelta
        st.session_state.session_expiry = datetime.now() + timedelta(hours=24)

        logger.info(f"Quick login for: {email}")
        return True

    except Exception as e:
        logger.error(f"Quick login error: {e}")
        return False


# Handle magic link callbacks on page load
handle_magic_link_callback()