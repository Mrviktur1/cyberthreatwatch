import pyotp
import streamlit as st
from supabase import create_client


class OTPManager:
    def __init__(self, supabase_client):
        self.supabase = supabase_client

    def generate_otp_secret(self, user_id):
        """
        Generate a new OTP secret for a user

        :param user_id: UUID of the user
        :return: OTP secret and provisioning URI
        """
        try:
            # Call PostgreSQL function to generate secret
            response = self.supabase.rpc(
                'generate_otp_secret',
                {'user_id': user_id}
            ).execute()

            secret = response.data

            # Generate TOTP URI for QR code
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_email,
                issuer_name='YourAppName'
            )

            return {
                'secret': secret,
                'qr_uri': totp_uri
            }
        except Exception as e:
            st.error(f"OTP Secret Generation Failed: {e}")
            return None

    def validate_otp(self, user_id, provided_otp):
        """
        Validate a provided OTP

        :param user_id: UUID of the user
        :param provided_otp: OTP entered by user
        :return: Boolean indicating OTP validity
        """
        try:
            # Retrieve stored secret
            user = self.supabase.table('users').select('otp_secret').eq('id', user_id).execute()
            secret = user.data[0]['otp_secret']

            # Use PyOTP for verification
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(provided_otp)

            # Call PostgreSQL validation function
            validation_result = self.supabase.rpc(
                'validate_otp',
                {
                    'user_id': user_id,
                    'provided_otp': provided_otp
                }
            ).execute()

            return is_valid
        except Exception as e:
            st.error(f"OTP Validation Failed: {e}")
            return False

    def invalidate_otp_secret(self, user_id):
        """
        Invalidate a user's OTP secret

        :param user_id: UUID of the user
        """
        try:
            # Call PostgreSQL function to clear OTP secret
            self.supabase.rpc(
                'invalidate_otp_secret',
                {'user_id': user_id}
            ).execute()

            st.success("OTP Secret has been invalidated")
        except Exception as e:
            st.error(f"OTP Secret Invalidation Failed: {e}")