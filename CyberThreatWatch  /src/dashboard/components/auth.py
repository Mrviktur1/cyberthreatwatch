import streamlit as st
from supabase import create_client, Client
import urllib.parse

# Initialize Supabase client
@st.cache_resource
def init_supabase() -> Client:
    url: str = st.secrets["SUPABASE_URL"]
    key: str = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_supabase()

# Authentication Functions
def signup(email: str, password: str):
    """Sign up new user"""
    try:
        response = supabase.auth.sign_up({"email": email, "password": password})
        if response.user:
            st.success("✅ Signup successful! Please check your email to confirm.")
            return True
        else:
            st.error("❌ Signup failed. Try again.")
            return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def login(email: str, password: str):
    """Login existing user"""
    try:
        response = supabase.auth.sign_in_with_password(
            {"email": email, "password": password}
        )
        if response.user:
            st.session_state["user"] = response.user
            st.success(f"✅ Welcome {response.user.email}")
            return True
        else:
            st.error("❌ Invalid credentials.")
            return False
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def login_with_google():
    """Login with Google (OAuth)"""
    try:
        # Get the current URL to redirect back after OAuth
        current_url = st.experimental_get_route()
        redirect_to = f"{st.secrets.get('SITE_URL', 'http://localhost:8501')}{current_url}"
        
        # URL encode the redirect URL
        encoded_redirect = urllib.parse.quote(redirect_to)
        
        res = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": encoded_redirect
            }
        })
        st.session_state.oauth_url = res.url
        return True
    except Exception as e:
        st.error(f"Google login failed: {e}")
        return False

def reset_password(email: str):
    """Trigger Supabase password reset"""
    try:
        supabase.auth.reset_password_for_email(email)
        st.success("📧 Password reset email sent. Check your inbox.")
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def logout():
    """Logout user"""
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
        # Get the current query parameters
        query_params = st.experimental_get_query_params()
        
        if 'code' in query_params or 'error' in query_params:
            # Try to get the session from URL
            session = supabase.auth.get_session_from_url(st.experimental_get_route())
            if session:
                st.session_state["user"] = session.user
                st.success(f"✅ Welcome {session.user.email}")
                # Clear the URL parameters
                st.experimental_set_query_params()
                st.rerun()
    except Exception as e:
        st.error(f"OAuth callback error: {e}")

# Check if user is logged in
def is_authenticated():
    """Check if user is authenticated"""
    if "user" in st.session_state:
        return True
    
    # Try to get existing session
    try:
        session = supabase.auth.get_session()
        if session and session.user:
            st.session_state["user"] = session.user
            return True
    except:
        pass
    
    return False

# Get current user
def get_current_user():
    """Get current user if authenticated"""
    if is_authenticated():
        return st.session_state["user"]
    return None

# UI Components
def show_login_form():
    """Display login form"""
    with st.form("login_form"):
        st.subheader("Login to Your Account")
        email = st.text_input("Email", placeholder="Enter your email")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if email and password:
                if login(email, password):
                    st.rerun()
            else:
                st.error("Please enter both email and password")
    
    # OAuth login option
    st.write("---")
    st.write("Or login with:")
    if st.button("Google", icon="🔗"):
        if login_with_google():
            # Add a link to the OAuth URL
            if "oauth_url" in st.session_state:
                st.markdown(f"Please [click here]({st.session_state.oauth_url}) to complete Google authentication.")
    
    # Password reset option
    st.write("---")
    with st.expander("Forgot Password?"):
        reset_email = st.text_input("Email for password reset", key="reset_email")
        if st.button("Send Reset Link"):
            if reset_email:
                reset_password(reset_email)
            else:
                st.error("Please enter your email")

def show_signup_form():
    """Display signup form"""
    with st.form("signup_form"):
        st.subheader("Create New Account")
        email = st.text_input("Email", placeholder="Enter your email", key="signup_email")
        password = st.text_input("Password", type="password", placeholder="Create a password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password", key="confirm_password")
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
    
    # Handle OAuth callback if needed
    handle_oauth_callback()
    
    # If user is authenticated, show logout option
    if is_authenticated():
        user = get_current_user()
        st.success(f"Welcome, {user.email}!")
        if st.button("Logout"):
            logout()
            st.rerun()
        return
    
    # If not authenticated, show auth options
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        show_login_form()
    
    with tab2:
        show_signup_form()

# Main app
def main():
    # Set page config
    st.set_page_config(
        page_title="Authentication",
        page_icon="🔐",
        layout="centered"
    )
    
    # Show authentication interface
    show_auth_page()

if __name__ == "__main__":
    main()