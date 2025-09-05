import streamlit as st
from supabase import create_client, Client

# ✅ Initialize Supabase client
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
    """Generate Supabase-hosted Google OAuth link"""
    try:
        site_url = st.secrets.get("SITE_URL", "http://localhost:8501")
        google_url = (
            f"{st.secrets['SUPABASE_URL']}/auth/v1/authorize"
            f"?provider=google&redirect_to={site_url}"
        )
        st.markdown(f"[🔗 Continue with Google]({google_url})", unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Google login failed: {e}")


def handle_oauth_callback():
    """Handle OAuth callback after redirect"""
    query_params = st.query_params
    if "access_token" in query_params:
        st.session_state["user"] = {
            "access_token": query_params["access_token"],
            "refresh_token": query_params.get("refresh_token"),
            "provider": "google"
        }
        st.success("✅ Logged in with Google!")
        # clear query params
        st.query_params.clear()
        st.rerun()


def is_authenticated():
    return "user" in st.session_state


def get_current_user():
    if is_authenticated():
        return st.session_state["user"]
    return None


def logout():
    st.session_state.pop("user", None)
    st.success("👋 Logged out successfully!")
    st.rerun()

# ---------------- UI ---------------- #

def show_login_form():
    with st.form("login_form"):
        st.subheader("Login with Email")
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
    st.write("Or login with Google:")
    login_with_google()


def show_signup_form():
    with st.form("signup_form"):
        st.subheader("Sign Up with Email")
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
        if isinstance(user, dict):  # Google login
            st.success("✅ Logged in with Google")
        else:  # Email/password login
            st.success(f"✅ Welcome, {user.email}!")

        if st.button("Logout"):
            logout()
        return

    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    with tab1:
        show_login_form()
    with tab2:
        show_signup_form()
