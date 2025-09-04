import streamlit as st
from supabase import create_client, Client
import os
from PIL import Image

# ✅ Initialize Supabase client
@st.cache_resource
def init_supabase() -> Client:
    url: str = st.secrets["SUPABASE_URL"]
    key: str = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_supabase()

# ---------------- AUTH FUNCTIONS ---------------- #

def signup(email: str, password: str):
    """Sign up new user"""
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
        if res.user:
            st.success("✅ Signup successful! Check your email to confirm.")
            return True
        st.error("❌ Signup failed.")
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def login(email: str, password: str):
    """Login existing user"""
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if res.user:
            st.session_state["user"] = res.user
            st.success(f"✅ Welcome {res.user.email}")
            return True
        st.error("❌ Invalid credentials")
        return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def login_with_google():
    """Login with Google (OAuth)"""
    try:
        redirect_to = st.secrets.get("SITE_URL", "http://localhost:8501")  # your app URL
        res = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {"redirect_to": redirect_to}
        })
        if res and res.url:
            st.session_state["oauth_url"] = res.url
            return True
        st.error("❌ Could not initiate Google login.")
        return False
    except Exception as e:
        st.error(f"Google login failed: {e}")
        return False

def handle_oauth_callback():
    """Handle OAuth callback from Supabase"""
    try:
        session = supabase.auth.get_session()
        if session and session.user:
            st.session_state["user"] = session.user
            st.success(f"✅ Welcome {session.user.email}")
            st.experimental_set_query_params()  # clear URL params
            st.rerun()
    except Exception as e:
        st.error(f"OAuth callback error: {e}")

def logout():
    """Logout user"""
    try:
        supabase.auth.sign_out()
        st.session_state.pop("user", None)
        st.success("👋 Logged out successfully!")
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def is_authenticated():
    """Check if user is authenticated"""
    if "user" in st.session_state:
        return True
    try:
        session = supabase.auth.get_session()
        if session and session.user:
            st.session_state["user"] = session.user
            return True
    except:
        pass
    return False

def get_current_user():
    if is_authenticated():
        return st.session_state["user"]
    return None

# ---------------- UI COMPONENTS ---------------- #

def show_login_form():
    """Display login form"""
    with st.form("login_form"):
        st.subheader("Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")

        if submit and email and password:
            if login(email, password):
                st.rerun()
            else:
                st.error("Invalid credentials")
        elif submit:
            st.error("Please enter email and password")

    st.write("---")
    st.write("Or login with:")

    google_logo_path = "assets/google_logo.png"
    if google_logo_path and os.path.exists(google_logo_path):
        google_logo = Image.open(google_logo_path)
        if st.button("Continue with Google"):
            if login_with_google() and "oauth_url" in st.session_state:
                st.markdown(
                    f'<a href="{st.session_state["oauth_url"]}" target="_self">'
                    f'<img src="data:image/png;base64,{_image_to_base64(google_logo)}" width="24"> Continue with Google</a>',
                    unsafe_allow_html=True
                )
    else:
        if st.button("Continue with Google"):
            login_with_google()

def _image_to_base64(image: Image.Image) -> str:
    """Convert PIL image to base64 string for inline display"""
    import io, base64
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def show_signup_form():
    """Display signup form"""
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
    """Main authentication page"""
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
