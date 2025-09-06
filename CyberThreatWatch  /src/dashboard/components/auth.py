import streamlit as st
from supabase import create_client, Client

# ✅ Initialize Supabase client once
@st.cache_resource
def init_supabase() -> Client:
    url: str = st.secrets["SUPABASE_URL"]
    key: str = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_supabase()

# ---------------- AUTH FUNCTIONS ---------------- #

def signup(email: str, password: str):
    try:
        response = supabase.auth.sign_up({"email": email, "password": password})
        if response.user:
            st.success("✅ Signup successful! Please check your email to confirm.")
            return True
        st.error("❌ Signup failed. Try again.")
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False


def login(email: str, password: str):
    try:
        response = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if response.user:
            st.session_state["user"] = response.user
            st.success(f"✅ Welcome {response.user.email}")
            return True
        st.error("❌ Invalid credentials.")
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False


def login_with_google():
    """Open Google OAuth URL in a new tab."""
    try:
        redirect_to = st.secrets.get("SITE_URL", "http://localhost:8501")
        res = supabase.auth.sign_in_with_oauth(
            {"provider": "google", "options": {"redirect_to": redirect_to}}
        )
        if res and "url" in res:
            st.session_state["oauth_url"] = res["url"]
            return True
        st.error("❌ Could not initiate Google login.")
        return False
    except Exception as e:
        st.error(f"Google login failed: {e}")
        return False


def logout():
    try:
        supabase.auth.sign_out()
        st.session_state.pop("user", None)
        st.success("👋 Logged out successfully!")
        return True
    except Exception as e:
        st.error(f"Error during logout: {e}")
        return False


def handle_oauth_callback():
    """Handle OAuth callback after redirect"""
    try:
        params = st.query_params   # ✅ updated from experimental_get_query_params
        if "code" in params:
            session = supabase.auth.get_session()
            if session and session.user:
                user = session.user
                st.session_state["user"] = user

                # --- ✅ Ensure user is stored in Supabase "users" table ---
                try:
                    email = user.email
                    supabase.table("users").upsert({
                        "email": email,
                        "provider": "google"
                    }).execute()
                except Exception as db_err:
                    st.warning(f"⚠️ Could not sync user to database: {db_err}")

                st.success(f"✅ Welcome {user.email}")
                st.query_params.clear()   # ✅ clear URL params
                st.rerun()
    except Exception as e:
        st.error(f"OAuth callback error: {e}")


def is_authenticated():
    if "user" in st.session_state:
        return True
    try:
        session = supabase.auth.get_session()
        if session and session.user:
            st.session_state["user"] = session.user
            return True
    except Exception:
        pass
    return False


def get_current_user():
    if is_authenticated():
        return st.session_state["user"]
    return None


# ---------------- UI ---------------- #

def show_login_form():
    with st.form("login_form"):
        st.subheader("Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")

        if submit:
            if email and password:
                if login(email, password):
                    st.rerun()
            else:
                st.error("Please enter both email and password")

    st.write("---")
    st.write("Or login with:")
    if st.button("🔗 Google Login"):
        if login_with_google() and "oauth_url" in st.session_state:
            st.markdown(f"[👉 Continue with Google]({st.session_state.oauth_url})")


def show_signup_form():
    with st.form("signup_form"):
        st.subheader("Sign Up")
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        submit = st.form_submit_button("Sign Up")

        if submit:
            if email and password and confirm_password:
                if password == confirm_password:
                    if signup(email, password):
                        st.rerun()
                else:
                    st.error("Passwords do not match")
            else:
                st.error("Please fill all fields")


def show_auth_page():
    st.title("🔐 User Authentication")
    handle_oauth_callback()
    if is_authenticated():
        user = get_current_user()
        st.success(f"✅ Welcome, {user.email}!")
        if st.button("Logout"):
            logout()
            st.rerun()
        return
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    with tab1:
        show_login_form()
    with tab2:
        show_signup_form()
