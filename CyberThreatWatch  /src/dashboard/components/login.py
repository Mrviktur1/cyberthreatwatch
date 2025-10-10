import streamlit as st
import logging
from supabase import Client
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

class LoginComponent:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def create_account(self, full_name, email, phone, address, account_type, username, business_or_school, password):
        try:
            # Supabase Auth: create user and send email verification link
            auth_response = self.supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "email_redirect_to": "https://cyberwatch.streamlit.app"
                }
            })

            if "error" in auth_response and auth_response["error"]:
                st.error(f"Signup error: {auth_response['error']['message']}")
                return

            # Hash password for custom user table
            hashed_pw = self.hash_password(password)

            # Store full profile in your custom 'users' table
            self.supabase.table("users").insert({
                "full_name": full_name,
                "email": email,
                "phone": phone,
                "address": address,
                "account_type": account_type,
                "username": username,
                "business_or_school": business_or_school,
                "password_hash": hashed_pw,
                "created_at": datetime.utcnow().isoformat()
            }).execute()

            st.success("✅ Account created successfully! Please verify your email before logging in.")
        except Exception as e:
            logger.error(f"Signup error: {e}")
            st.error("An unexpected error occurred during signup.")

    def login_user(self, email_or_username, password):
        try:
            # Check login with Supabase Auth
            response = self.supabase.auth.sign_in_with_password({
                "email": email_or_username,
                "password": password
            })
            if not response or "user" not in response:
                st.error("Invalid login credentials.")
                return False

            st.session_state["authenticated"] = True
            st.session_state["user_email"] = email_or_username
            st.success("✅ Login successful!")
            return True
        except Exception as e:
            logger.error(f"Login error: {e}")
            st.error("Login failed. Please check your credentials or verify your email.")
            return False

    def render_signup(self):
        st.subheader("🧾 Create Account")
        full_name = st.text_input("Full Name")
        email = st.text_input("Email")
        phone = st.text_input("Phone Number")
        address = st.text_input("Address")
        account_type = st.selectbox("Account Type", ["Student", "Business"])
        business_or_school = st.text_input("Business Name or School Name")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Sign Up"):
            if not all([full_name, email, phone, address, account_type, username, password, confirm_password]):
                st.warning("Please fill out all fields.")
                return
            if password != confirm_password:
                st.error("Passwords do not match.")
                return
            self.create_account(full_name, email, phone, address, account_type, username, business_or_school, password)

    def render_login(self):
        st.subheader("🔐 Login")
        email_or_username = st.text_input("Email or Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            self.login_user(email_or_username, password)

    def check_authentication(self):
        if st.session_state.get("authenticated"):
            st.success(f"Welcome back, {st.session_state.get('user_email', '')}")
            return True

        tabs = st.tabs(["Login", "Sign Up"])
        with tabs[0]:
            self.render_login()
        with tabs[1]:
            self.render_signup()
        return False

    def render_logout_section(self):
        if st.session_state.get("authenticated"):
            if st.button("🚪 Logout"):
                st.session_state.clear()
                st.experimental_rerun()
