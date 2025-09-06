import streamlit as st
import streamlit_authenticator as stauth
import os
import requests
import json
from urllib.parse import urlencode

# -------------------------
# Config
# -------------------------
GOOGLE_CLIENT_ID = st.secrets.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = st.secrets.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = st.secrets.get("REDIRECT_URI", "https://cyberwatch.streamlit.app")

# -------------------------
# Email/Password Authenticator
# -------------------------
def init_authenticator():
    credentials = {
        "usernames": {
            "testuser": {
                "name": "Test User",
                "password": stauth.Hasher(["testpass"]).generate()[0],
                "email": "test@example.com"
            }
        }
    }

    authenticator = stauth.Authenticate(
        credentials,
        "auth_cookie", "auth_key", cookie_expiry_days=7
    )
    return authenticator


def login_email_password():
    authenticator = init_authenticator()
    name, auth_status, username = authenticator.login("Login with Email", "main")

    if auth_status:
        st.session_state["authenticator"] = authenticator
        st.session_state["user"] = {"name": name, "username": username, "method": "password"}
        return True
    elif auth_status is False:
        st.error("❌ Username/password is incorrect")
    else:
        st.info("ℹ️ Please log in with your email/password")

    return False


# -------------------------
# Google OAuth Flow
# -------------------------
def get_google_auth_url():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


def handle_google_callback():
    query_params = st.query_params  # ✅ new API
    if "code" in query_params:
        code = query_params["code"]

        # Exchange code for token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        token_res = requests.post(token_url, data=data)
        if token_res.status_code == 200:
            tokens = token_res.json()
            userinfo_res = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
            if userinfo_res.status_code == 200:
                profile = userinfo_res.json()
                st.session_state["user"] = {
                    "name": profile.get("name"),
                    "email": profile.get("email"),
                    "picture": profile.get("picture"),
                    "method": "google"
                }
                return True
        st.error("❌ Google authentication failed.")
    return False


def login_google():
    if "user" in st.session_state and st.session_state["user"].get("method") == "google":
        return True

    st.markdown("### Or login with Google")
    login_url = get_google_auth_url()
    st.markdown(f"[🔑 Sign in with Google]({login_url})")

    return handle_google_callback()


# -------------------------
# Unified Login
# -------------------------
def login():
    # First check Google
    if login_google():
        return True

    # Otherwise fallback to email/password
    return login_email_password()


def logout():
    if "authenticator" in st.session_state:
        st.session_state["authenticator"].logout("Logout", "sidebar")
    st.session_state.clear()
    st.rerun()
