import streamlit as st
from supabase import create_client, Client

# --- Supabase Client ---
@st.cache_resource
def init_supabase() -> Client:
    url: str = st.secrets["SUPABASE_URL"]
    key: str = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_supabase()


# --- Authentication Functions ---
def signup(email: str, password: str):
    """Sign up new user"""
    try:
        response = supabase.auth.sign_up({"email": email, "password": password})
        if response.user:
            st.success("✅ Signup successful! Please check your email to confirm.")
        else:
            st.error("❌ Signup failed. Try again.")
    except Exception as e:
        st.error(f"Error: {e}")


def login(email: str, password: str):
    """Login existing user"""
    try:
        response = supabase.auth.sign_in_with_password(
            {"email": email, "password": password}
        )
        if response.user:
            st.session_state["user"] = response.user
            st.success(f"✅ Welcome {response.user.email}")
        else:
            st.error("❌ Invalid credentials.")
    except Exception as e:
        st.error(f"Error: {e}")


def login_with_google():
    """Login with Google (OAuth)"""
    try:
        res = supabase.auth.sign_in_with_oauth({"provider": "google"})
        st.markdown(
            f"[Click here to login with Google]({res.url})",
            unsafe_allow_html=True,
        )
    except Exception as e:
        st.error(f"Google login failed: {e}")


def reset_password(email: str):
    """Trigger Supabase password reset"""
    try:
        res = supabase.auth.reset_password_email(email)
        st.success("📧 Password reset email sent. Check your inbox.")
    except Exception as e:
        st.error(f"Error: {e}")


def logout():
    """Logout user"""
    supabase.auth.sign_out()
    st.session_state.pop("user", None)
    st.success("👋 Logged out successfully!")
create this