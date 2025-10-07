import logging
from dashboard.components import auth

logger = logging.getLogger(__name__)

class AuthService:
    """Handles authentication operations using Supabase and session state."""
    def __init__(self):
        self.supabase = auth.supabase
        logger.info("✅ AuthService initialized successfully")

    def send_magic_link(self, email):
        return auth.send_magic_link(email)

    def handle_magic_link_callback(self):
        return auth.handle_magic_link_callback()

    def is_authenticated(self):
        return auth.is_authenticated()

    def get_current_user(self):
        return auth.get_current_user()

    def quick_login(self, email):
        return auth.quick_login(email)

    def enroll_mfa(self):
        return auth.enroll_mfa()

    def verify_mfa(self):
        return auth.verify_mfa()

    def logout(self):
        return auth.logout()