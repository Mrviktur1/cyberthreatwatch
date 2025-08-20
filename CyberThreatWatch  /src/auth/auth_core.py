import os
from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from passlib.hash import bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from authlib.integrations.httpx_client import OAuth2Client
import httpx
import pyotp

# Database configuration
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
db = client["threatwatch"]
users_collection = db["users"]

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
JWT_ALGORITHM = "HS256"

# Email Configuration
SMTP_CONFIG = {
    "server": os.getenv("SMTP_SERVER"),
    "port": int(os.getenv("SMTP_PORT", 587)),
    "username": os.getenv("SMTP_USERNAME"),
    "password": os.getenv("SMTP_PASSWORD")
}

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

def create_user(
    email: str,
    password: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    **kwargs
) -> Optional[Dict]:
    """Create a new user with email/password"""
    if users_collection.find_one({"email": email}):
        return None  # User already exists

    hashed_password = bcrypt.hash(password)
    user = {
        "email": email,
        "password": hashed_password,
        "first_name": first_name,
        "last_name": last_name,
        "email_verified": False,
        "2fa_enabled": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        **kwargs
    }
    
    result = users_collection.insert_one(user)
    user["_id"] = str(result.inserted_id)
    return user

def create_user_from_google(
    email: str,
    google_id: str,
    name: Optional[str] = None,
    verified: bool = True
) -> Optional[Dict]:
    """Create a new user from Google OAuth data"""
    existing_user = users_collection.find_one({"email": email})
    
    if existing_user:
        # Update existing user with Google ID
        users_collection.update_one(
            {"_id": existing_user["_id"]},
            {"$set": {
                "google_id": google_id,
                "email_verified": verified,
                "updated_at": datetime.utcnow()
            }}
        )
        existing_user["_id"] = str(existing_user["_id"])
        return existing_user
    
    # Create new user
    first_name, last_name = name.split(" ", 1) if name else (None, None)
    user = {
        "email": email,
        "google_id": google_id,
        "first_name": first_name,
        "last_name": last_name,
        "email_verified": verified,
        "2fa_enabled": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = users_collection.insert_one(user)
    user["_id"] = str(result.inserted_id)
    return user

def verify_login(email: str, password: str) -> Optional[Dict]:
    """Verify email/password login"""
    user = users_collection.find_one({"email": email})
    if not user:
        return None
    
    if user.get("google_id") and not user.get("password"):
        return None  # Google-only user
    
    if not bcrypt.verify(password, user["password"]):
        return None
    
    user["_id"] = str(user["_id"])
    return user

def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email"""
    user = users_collection.find_one({"email": email})
    if user:
        user["_id"] = str(user["_id"])
    return user

def send_verification_email(email: str) -> bool:
    """Send email verification link"""
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    
    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(hours=24)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    
    verification_url = f"{os.getenv('APP_URL')}/verify-email?token={token}"
    # Implement your email sending logic here
    return True

def verify_email_token(token: str) -> Optional[Dict]:
    """Verify email verification token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload["email"]
        
        result = users_collection.update_one(
            {"email": email},
            {"$set": {"email_verified": True}}
        )
        
        if result.modified_count == 1:
            return get_user_by_email(email)
        return None
    except jwt.PyJWTError:
        return None

def send_password_reset(email: str) -> bool:
    """Send password reset email"""
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    
    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    
    reset_url = f"{os.getenv('APP_URL')}/reset-password?token={token}"
    # Implement your email sending logic here
    return True

def update_user_password(email: str, current_password: str, new_password: str) -> bool:
    """Update user password with verification"""
    user = users_collection.find_one({"email": email})
    if not user or not user.get("password"):
        return False
    
    if not bcrypt.verify(current_password, user["password"]):
        return False
    
    hashed_password = bcrypt.hash(new_password)
    result = users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_password}}
    )
    return result.modified_count == 1

def initiate_2fa_setup(email: str) -> Optional[Dict]:
    """Initialize 2FA setup for a user"""
    user = users_collection.find_one({"email": email})
    if not user:
        return None
    
    secret = pyotp.random_base32()
    
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="CyberThreatWatch"
    )
    
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri
    }

def verify_2fa_code(email: str, code: str, secret: str = None) -> bool:
    """Verify 2FA code"""
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    
    # Use provided secret (for setup) or stored secret (for login)
    use_secret = secret or user.get("2fa_secret")
    if not use_secret:
        return False
    
    totp = pyotp.TOTP(use_secret)
    if totp.verify(code, valid_window=1):
        if secret and not user.get("2fa_secret"):
            # Finalize 2FA setup
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "2fa_secret": secret,
                    "2fa_enabled": True
                }}
            )
        return True
    return False

def get_google_oauth_url() -> str:
    """Generate Google OAuth URL"""
    oauth = OAuth2Client(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    auth_url, _ = oauth.create_authorization_url(
        "https://accounts.google.com/o/oauth2/auth",
        scope=["openid", "email", "profile"]
    )
    return auth_url

def get_google_user_info(code: str) -> Optional[Dict]:
    """Get user info from Google using authorization code"""
    oauth = OAuth2Client(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    try:
        token = oauth.fetch_token(
            "https://oauth2.googleapis.com/token",
            authorization_response=code,
            grant_type="authorization_code"
        )
        resp = oauth.get("https://www.googleapis.com/oauth2/v3/userinfo")
        return resp.json()
    except Exception:
        return None