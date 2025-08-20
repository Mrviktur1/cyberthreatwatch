import pyotp
import qrcode
from io import BytesIO

class MFAService:
    def generate_totp(self, user_email: str) -> tuple:
        """Returns (secret, qr_code_bytes)"""
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="CyberThreatWatch"
        )
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        return secret, buf.getvalue()
        
    def verify_totp(self, secret: str, code: str) -> bool:
        return pyotp.TOTP(secret).verify(code)