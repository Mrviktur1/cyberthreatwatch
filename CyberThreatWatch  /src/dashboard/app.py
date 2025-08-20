import streamlit as st
import sys
import os
import qrcode
from datetime import datetime, timedelta
from io import BytesIO
import pandas as pd
from PIL import Image
from pathlib import Path
import httpx
import json
import time
import base64
import hashlib
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from authlib.integrations.httpx_client import OAuth2Client
import secrets
import string
import urllib.parse
import re
import bcrypt
import logging
from typing import Optional, Dict, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberThreatWatch")

# Set up paths and imports
sys.path.append(os.path.absp(os.path.join(os.path.dirname(__file__), "..")))

# Configure paths
current_dir = Path(__file__).parent
assets_dir = current_dir.parent / "assets"

# Ensure directories exist
os.makedirs(assets_dir, exist_ok=True)

# Rate limiting storage
failed_attempts = {}
login_attempts = {}

# Database setup - Fallback to SQLite if MongoDB is not available
def init_db():
    """Initialize database - use SQLite as fallback"""
    import sqlite3
    db_path = current_dir.parent / "data" / "users.db"
    os.makedirs(current_dir.parent / "data", exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        first_name TEXT,
        last_name TEXT,
        google_id TEXT,
        email_verified BOOLEAN DEFAULT FALSE,
        verification_token TEXT,
        verification_token_expiry DATETIME,
        reset_token TEXT,
        reset_token_expiry DATETIME,
        two_fa_secret TEXT,
        two_fa_enabled BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked_until DATETIME
    )
    ''')
    
    # Create indexes for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_token ON users(verification_token)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reset_token ON users(reset_token)')
    
    conn.commit()
    conn.close()
    return True

# Input validation functions
def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent XSS"""
    if not input_str:
        return ""
    # Remove potentially dangerous characters
    return re.sub(r'[<>"\'();&]', '', input_str.strip())

def validate_password(password: str) -> tuple:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(not char.isalnum() for char in password):
        return False, "Password must contain at least one special character"
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    return True, "Password is strong"

# Rate limiting functions
def check_rate_limit(email: str, action: str = 'login') -> bool:
    """Check if user has exceeded rate limits"""
    now = datetime.now()
    key = f"{email}_{action}"
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    # Remove attempts older than 15 minutes
    login_attempts[key] = [
        t for t in login_attempts[key] 
        if now - t < timedelta(minutes=15)
    ]
    
    # Allow max 5 attempts per 15 minutes
    if len(login_attempts[key]) >= 5:
        return False
    
    login_attempts[key].append(now)
    return True

def record_failed_attempt(email: str):
    """Record a failed login attempt in database"""
    try:
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get current failed attempts
        cursor.execute('SELECT failed_login_attempts FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        
        if result:
            failed_attempts = result[0] + 1
            
            # Lock account after 5 failed attempts for 30 minutes
            lock_until = None
            if failed_attempts >= 5:
                lock_until = datetime.now() + timedelta(minutes=30)
                logger.warning(f"Account locked for {email} due to too many failed attempts")
            
            cursor.execute('''
                UPDATE users 
                SET failed_login_attempts = ?, account_locked_until = ?
                WHERE email = ?
            ''', (failed_attempts, lock_until, email))
            
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error recording failed attempt: {e}")

def reset_failed_attempts(email: str):
    """Reset failed login attempts after successful login"""
    try:
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users 
            SET failed_login_attempts = 0, account_locked_until = NULL
            WHERE email = ?
        ''', (email,))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error resetting failed attempts: {e}")

def is_account_locked(email: str) -> bool:
    """Check if account is locked"""
    try:
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT account_locked_until FROM users WHERE email = ?
        ''', (email,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            lock_until = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S.%f')
            if datetime.now() < lock_until:
                return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking account lock: {e}")
        return False

# Core authentication functions using SQLite
def create_user(email: str, password: str, first_name: str = "", last_name: str = "") -> Optional[Dict]:
    """Create a new user with secure password hashing"""
    try:
        # Validate input
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        first_name = sanitize_input(first_name)
        last_name = sanitize_input(last_name)
        
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            st.error(message)
            return None
        
        # Generate secure password hash using bcrypt
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        verification_token = secrets.token_urlsafe(32)
        verification_token_expiry = datetime.now() + timedelta(hours=24)
        
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO users (email, password_hash, first_name, last_name, verification_token, verification_token_expiry)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, password_hash, first_name, last_name, verification_token, verification_token_expiry))
        
        conn.commit()
        conn.close()
        
        logger.info(f"New user created: {email}")
        
        return {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'email_verified': False
        }
    except sqlite3.IntegrityError:
        logger.warning(f"User already exists: {email}")
        return None
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return None

def verify_login(email: str, password: str) -> Optional[Dict]:
    """Verify user login with secure password checking"""
    try:
        # Validate input
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        
        # Check rate limiting
        if not check_rate_limit(email, 'login'):
            st.error("Too many login attempts. Please try again in 15 minutes.")
            logger.warning(f"Rate limit exceeded for: {email}")
            return None
            
        # Check if account is locked
        if is_account_locked(email):
            st.error("Account temporarily locked due to too many failed attempts. Please try again later.")
            logger.warning(f"Login attempt on locked account: {email}")
            return None
        
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT email, password_hash, first_name, last_name, email_verified, two_fa_enabled, two_fa_secret
        FROM users 
        WHERE email = ? AND email_verified = TRUE
        ''', (email,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Verify password using bcrypt
            if bcrypt.checkpw(password.encode(), user[1].encode()):
                # Reset failed attempts on successful login
                reset_failed_attempts(email)
                
                # Update last login
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE users SET last_login = ? WHERE email = ?
                ''', (datetime.now(), email))
                conn.commit()
                conn.close()
                
                logger.info(f"Successful login: {email}")
                
                return {
                    'email': user[0],
                    'first_name': user[2],
                    'last_name': user[3],
                    'email_verified': bool(user[4]),
                    '2fa_enabled': bool(user[5]),
                    '2fa_secret': user[6]
                }
            else:
                # Record failed attempt
                record_failed_attempt(email)
                logger.warning(f"Failed login attempt: {email}")
        
        return None
    except Exception as e:
        logger.error(f"Error verifying login: {e}")
        return None

def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email with input validation"""
    try:
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT email, first_name, last_name, email_verified, two_fa_enabled, two_fa_secret
        FROM users 
        WHERE email = ?
        ''', (email,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'email': user[0],
                'first_name': user[1],
                'last_name': user[2],
                'email_verified': bool(user[3]),
                '2fa_enabled': bool(user[4]),
                '2fa_secret': user[5]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def create_user_from_google(email: str, name: str, google_id: str, verified: bool = True) -> Optional[Dict]:
    """Create user from Google OAuth with input validation"""
    try:
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        name = sanitize_input(name)
        google_id = sanitize_input(google_id)
        
        first_name, last_name = (name.split(' ', 1) + [''])[:2]
        
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO users (email, first_name, last_name, google_id, email_verified)
        VALUES (?, ?, ?, ?, ?)
        ''', (email, first_name, last_name, google_id, verified))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Google user created: {email}")
        
        return {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'email_verified': verified,
            '2fa_enabled': False
        }
    except sqlite3.IntegrityError:
        # User already exists, return existing user
        logger.info(f"Google user already exists: {email}")
        return get_user_by_email(email)
    except Exception as e:
        logger.error(f"Error creating Google user: {e}")
        return None

def send_verification_email(email: str) -> bool:
    """Send verification email with secure token"""
    try:
        # In a real app, you would send an actual email
        # This is a simplified version for demonstration
        
        # Generate a new secure token with expiration
        verification_token = secrets.token_urlsafe(32)
        verification_token_expiry = datetime.now() + timedelta(hours=24)
        
        # Store token in database
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE users 
        SET verification_token = ?, verification_token_expiry = ?
        WHERE email = ?
        ''', (verification_token, verification_token_expiry, email))
        
        conn.commit()
        conn.close()
        
        st.session_state.verification_sent = True
        logger.info(f"Verification email sent to: {email}")
        return True
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")
        return False

def send_password_reset(email: str) -> bool:
    """Send password reset email with secure token"""
    try:
        # In a real app, you would send an actual email
        # This is a simplified version for demonstration
        
        # Generate a new secure token with expiration
        reset_token = secrets.token_urlsafe(32)
        reset_token_expiry = datetime.now() + timedelta(hours=1)  # 1 hour expiration
        
        # Store token in database
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE users 
        SET reset_token = ?, reset_token_expiry = ?
        WHERE email = ?
        ''', (reset_token, reset_token_expiry, email))
        
        conn.commit()
        conn.close()
        
        st.session_state.reset_sent = True
        logger.info(f"Password reset email sent to: {email}")
        return True
    except Exception as e:
        logger.error(f"Error sending password reset email: {e}")
        return False

def verify_email_token(token: str) -> bool:
    """Verify email token with expiration check"""
    try:
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if token exists and is not expired
        cursor.execute('''
        SELECT email, verification_token_expiry FROM users 
        WHERE verification_token = ?
        ''', (token,))
        
        result = cursor.fetchone()
        
        if not result:
            return False
            
        email, expiry_str = result
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
        
        if datetime.now() > expiry:
            logger.warning(f"Expired verification token for: {email}")
            return False
        
        # Update user as verified
        cursor.execute('''
        UPDATE users 
        SET email_verified = TRUE, verification_token = NULL, verification_token_expiry = NULL
        WHERE verification_token = ?
        ''', (token,))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        if success:
            logger.info(f"Email verified for: {email}")
        
        return success
    except Exception as e:
        logger.error(f"Error verifying email token: {e}")
        return False

def initiate_2fa_setup(email: str) -> Dict:
    """Initiate 2FA setup with secure secret generation"""
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, 
        issuer_name="CyberThreatWatch"
    )
    
    # Store the secret temporarily in session state
    return {
        'secret': secret,
        'provisioning_uri': provisioning_uri
    }

def verify_2fa_code(email: str, code: str, secret: Optional[str] = None) -> bool:
    """Verify 2FA code with secure validation"""
    if secret:
        # New 2FA setup
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # Save the secret to the database
            import sqlite3
            db_path = current_dir.parent / "data" / "users.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE users 
            SET two_fa_secret = ?, two_fa_enabled = TRUE
            WHERE email = ?
            ''', (secret, email))
            conn.commit()
            success = cursor.rowcount > 0
            conn.close()
            
            if success:
                logger.info(f"2FA enabled for: {email}")
            
            return success
    else:
        # Existing 2FA verification
        user = get_user_by_email(email)
        if user and user.get('2fa_secret'):
            totp = pyotp.TOTP(user['2fa_secret'])
            return totp.verify(code)
    
    return False

def update_user_password(email: str, new_password: str) -> bool:
    """Update user password with secure hashing"""
    try:
        # Validate password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            st.error(message)
            return False
            
        # Generate secure password hash using bcrypt
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        
        import sqlite3
        db_path = current_dir.parent / "data" / "users.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE users 
        SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL
        WHERE email = ?
        ''', (password_hash, email))
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        if success:
            logger.info(f"Password updated for: {email}")
        
        return success
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return False

# Google OAuth Configuration - Simplified for demo
def get_google_oauth_url() -> str:
    """Generate Google OAuth URL - simplified for demo"""
    # For demo purposes, we'll use a simplified approach
    # In production, you'd use proper OAuth flow
    return "#"

def get_google_user_info(code: str) -> Dict:
    """Simplified Google user info for demo"""
    # For demo purposes, return a mock user
    # In production, you'd implement proper OAuth flow
    return {
        'email': 'demo@example.com',
        'name': 'Demo User',
        'sub': '1234567890',
        'email_verified': True
    }

# Threat intelligence functions
def fetch_recent_cves(api_key: Optional[str] = None, days: int = 7, max_results: int = 50) -> pd.DataFrame:
    """Fetch recent CVEs from NVD API with improved error handling"""
    try:
        # Try to use the NVD API if an API key is provided
        if api_key and api_key != "demo":
            headers = {"apiKey": api_key} if api_key else {}
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={max_results}"
            
            with httpx.Client() as client:
                response = client.get(url, headers=headers, timeout=30.0)
                if response.status_code == 200:
                    data = response.json()
                    cves = []
                    for vuln in data.get('vulnerabilities', [])[:max_results]:
                        cve = vuln.get('cve', {})
                        metrics = cve.get('metrics', {})
                        cvss_metric = list(metrics.get('cvssMetricV2', []) + 
                                         metrics.get('cvssMetricV30', []) + 
                                         metrics.get('cvssMetricV31', []))
                        
                        cvss_score = cvss_metric[0]['cvssData']['baseScore'] if cvss_metric else 0.0
                        severity = cvss_metric[0]['cvssData']['baseSeverity'] if cvss_metric else "UNKNOWN"
                        
                        cves.append({
                            'CVE ID': cve.get('id', ''),
                            'Description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'Published': cve.get('published', ''),
                            'CVSS Score': cvss_score,
                            'Severity': severity
                        })
                    
                    if cves:
                        return pd.DataFrame(cves)
        
        # Fallback to sample data if API fails or no key provided
        cve_ids = [f'CVE-2023-{1000+i}' for i in range(max_results)]
        descriptions = [f'Sample vulnerability description {i+1}' for i in range(max_results)]
        published_dates = [(datetime.now() - timedelta(days=i % days)).strftime('%Y-%m-%d') for i in range(max_results)]
        cvss_scores = [round(1 + (i % 9), 1) for i in range(max_results)]
        
        # Create severity list
        severity_options = ['Low', 'Medium', 'High', 'Critical']
        severities = [severity_options[i % 4] for i in range(max_results)]
        
        sample_data = {
            'CVE ID': cve_ids,
            'Description': descriptions,
            'Published': published_dates,
            'CVSS Score': cvss_scores,
            'Severity': severities
        }
        return pd.DataFrame(sample_data)
        
    except Exception as e:
        logger.error(f"Error fetching CVE data: {e}")
        # Return empty dataframe on error
        return pd.DataFrame()

def get_pulse_indicators(api_key: Optional[str] = None) -> pd.DataFrame:
    """Fetch threat indicators from OTX with improved error handling"""
    try:
        # Try to use the OTX API if an API key is provided
        if api_key and api_key != "demo":
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": api_key}
            
            with httpx.Client() as client:
                response = client.get(url, headers=headers, timeout=30.0)
                if response.status_code == 200:
                    data = response.json()
                    indicators = []
                    
                    for pulse in data.get('results', [])[:10]:  # Limit to 10 pulses
                        for indicator in pulse.get('indicators', [])[:20]:  # Limit to 20 indicators per pulse
                            indicators.append({
                                'Indicator': indicator.get('indicator', ''),
                                'Type': indicator.get('type', ''),
                                'Malware': pulse.get('name', ''),
                                'First Seen': indicator.get('created', ''),
                                'Reputation': 'Malicious' if indicator.get('is_malicious') else 'Unknown'
                            })
                    
                    if indicators:
                        return pd.DataFrame(indicators[:20])  # Return max 20 indicators
        
        # Fallback to sample data if API fails or no key provided
        indicators = [f'192.168.1.{i}' for i in range(1, 21)]
        
        # Create type list
        type_options = ['IPv4', 'Domain', 'URL', 'Hash']
        types = [type_options[i % 4] for i in range(20)]
        
        malware = [f'Malware Family {chr(65 + (i % 5))}' for i in range(20)]
        first_seen = [(datetime.now() - timedelta(days=i % 30)).strftime('%Y-%m-%d') for i in range(20)]
        
        # Create reputation list
        reputation_options = ['Malicious', 'Suspicious', 'Unknown']
        reputations = [reputation_options[i % 3] for i in range(20)]
        
        sample_data = {
            'Indicator': indicators,
            'Type': types,
            'Malware': malware,
            'First Seen': first_seen,
            'Reputation': reputations
        }
        return pd.DataFrame(sample_data)
        
    except Exception as e:
        logger.error(f"Error fetching OTX data: {e}")
        # Return empty dataframe on error
        return pd.DataFrame()

# Page configuration
try:
    st.set_page_config(
        layout="wide",
        page_title="CyberThreatWatch",
        page_icon=str(assets_dir / "CyberThreatWatch.png"),
        menu_items={
            'About': "CyberThreatWatch™ v2.1 | © 2025 SecureCorp Inc."
        }
    )
except FileNotFoundError:
    st.set_page_config(
        layout="wide",
        page_title="CyberThreatWatch",
        menu_items={
            'About': "CyberThreatWatch™ v2.1 | © 2025 SecureCorp Inc."
        }
    )

# Initialize session state
def init_session_state():
    if 'auth' not in st.session_state:
        st.session_state.auth = {
            'authenticated': False,
            'user': None,
            'last_activity': None,
            'requires_2fa': False
        }
    if 'temp_2fa_secret' not in st.session_state:
        st.session_state.temp_2fa_secret = None
    if 'verification_sent' not in st.session_state:
        st.session_state.verification_sent = False
    if 'reset_sent' not in st.session_state:
        st.session_state.reset_sent = False
    if 'data_loaded' not in st.session_state:
        st.session_state.data_loaded = False
    if 'threat_data' not in st.session_state:
        st.session_state.threat_data = {'cves': pd.DataFrame(), 'indicators': pd.DataFrame()}

# Initialize database
init_db()

# --- Google OAuth Functions --- #
def handle_google_callback():
    """Handle Google OAuth callback"""
    # Use the new st.query_params instead of deprecated st.experimental_get_query_params
    query_params = st.query_params
    if 'code' in query_params:
        code = query_params['code'][0]
        try:
            # For demo purposes, use mock data
            user_info = {
                'email': 'demo@example.com',
                'name': 'Demo User',
                'sub': '1234567890',
                'email_verified': True
            }
            
            if not user_info:
                st.error("Failed to authenticate with Google")
                return
            
            # Check if user exists
            existing_user = get_user_by_email(user_info['email'])
            if existing_user:
                complete_login(existing_user)
            else:
                # Create new user from Google info
                user = create_user_from_google(
                    email=user_info['email'],
                    name=user_info.get('name', ''),
                    google_id=user_info['sub'],
                    verified=user_info.get('email_verified', False)
                )
                if user:
                    complete_login(user)
                    st.success("Account created successfully with Google!")
        except Exception as e:
            logger.error(f"Google login failed: {str(e)}")
            st.error("Google authentication failed")
        finally:
            # Clear the query params
            st.query_params.clear()

# --- Cache Brand Assets --- #
@st.cache_data
def load_brand_assets():
    """Load and cache brand images"""
    try:
        # Create placeholder images if they don't exist
        if not (assets_dir / "CyberThreatWatch.png").exists():
            img = Image.new('RGB', (200, 200), color='red')
            img.save(assets_dir / "CyberThreatWatch.png")
        
        if not (assets_dir / "CyberThreatWatch_signature.png").exists():
            img = Image.new('RGB', (400, 100), color='blue')
            img.save(assets_dir / "CyberThreatWatch_signature.png")
            
        return {
            "logo": Image.open(assets_dir / "CyberThreatWatch.png"),
            "signature": Image.open(assets_dir / "CyberThreatWatch_signature.png")
        }
    except Exception as e:
        logger.error(f"Error loading brand assets: {e}")
        return None

# --- Authentication Functions --- #
def complete_login(user):
    """Finalize successful login with 2FA check"""
    if user.get('2fa_enabled', False):
        st.session_state.auth = {
            'authenticated': False,
            'user': user,
            'last_activity': datetime.now(),
            'requires_2fa': True
        }
        st.session_state.temp_2fa_secret = initiate_2fa_setup(user['email']) if not user.get('2fa_secret') else None
    else:
        st.session_state.auth = {
            'authenticated': True,
            'user': user,
            'last_activity': datetime.now(),
            'requires_2fa': False
        }
    st.rerun()

def show_2fa_verification():
    """Show 2FA verification interface"""
    brand = load_brand_assets()
    
    st.markdown("""
    <style>
    .auth-header { text-align: center; margin-bottom: 2rem; }
    .auth-container { max-width: 500px; margin: 0 auto; }
    </style>
    """, unsafe_allow_html=True)
    
    with st.container():
        # Brand header
        if brand:
            st.image(brand["logo"], width=200, use_column_width=True)
        st.markdown("<h1 class='auth-header'>Two-Factor Authentication</h1>", 
                   unsafe_allow_html=True)
        
        # Show QR code if setting up new 2FA
        if st.session_state.temp_2fa_secret:
            st.info("Scan this QR code with your authenticator app")
            img = qrcode.make(st.session_state.temp_2fa_secret['provisioning_uri'])
            buf = BytesIO()
            img.save(buf, format="PNG")
            st.image(buf, width=200)
            st.code(st.session_state.temp_2fa_secret['secret'])
        
        # Verification form
        with st.form(key="2fa_form"):
            code = st.text_input("Enter 6-digit code", max_chars=6)
            
            if st.form_submit_button("Verify"):
                if verify_2fa_code(
                    email=st.session_state.auth['user']['email'],
                    code=code,
                    secret=st.session_state.temp_2fa_secret['secret'] if st.session_state.temp_2fa_secret else None
                ):
                    st.session_state.auth['authenticated'] = True
                    st.session_state.auth['requires_2fa'] = False
                    st.session_state.temp_2fa_secret = None
                    st.rerun()
                else:
                    st.error("Invalid verification code")

# --- Main Application Interface --- #
def show_main_app():
    """Main application dashboard"""
    st.title(f"🔍 CyberThreatWatch - Live Threat Intelligence")
    
    # Sidebar controls
    with st.sidebar:
        st.header("Settings")
        days = st.slider("Lookback period (days)", 1, 30, 7)
        max_results = st.slider("Max results", 10, 100, 50)
        
        # API key configuration
        st.subheader("API Configuration")
        nvd_api_key = st.text_input("NVD API Key (optional)", type="password")
        otx_api_key = st.text_input("OTX API Key (optional)", type="password")
        
        if st.button("🔄 Refresh Data", type="primary"):
            with st.spinner("Loading threat data..."):
                # Load CVE data
                cve_data = fetch_recent_cves(
                    api_key=nvd_api_key or st.secrets.get("nvd_api_key", None),
                    days=days,
                    max_results=max_results
                )
                
                # Load OTX data
                otx_data = get_pulse_indicators(
                    otx_api_key or st.secrets.get("otx_api_key", None)
                )
                
                # Store data in session state
                st.session_state.threat_data = {
                    'cves': cve_data,
                    'indicators': otx_data
                }
                st.session_state.data_loaded = True
                
        if st.button("Logout"):
            st.session_state.auth = {
                'authenticated': False,
                'user': None,
                'last_activity': None,
                'requires_2fa': False
            }
            st.session_state.data_loaded = False
            st.rerun()

    # Main dashboard
    if st.session_state.data_loaded:
        cve_data = st.session_state.threat_data['cves']
        otx_data = st.session_state.threat_data['indicators']
        
        if cve_data.empty or otx_data.empty:
            st.error("Failed to load some data. Check logs and try later.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("📜 Recent CVEs")
                st.dataframe(cve_data, height=600, use_container_width=True)
                
                # Export option
                csv = cve_data.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="cve_data.csv",
                    mime="text/csv",
                    key="cve-download"
                )
            with col2:
                st.subheader("🦠 Malware Indicators")
                st.dataframe(otx_data, height=600, use_container_width=True)
                
                # Export option
                csv = otx_data.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="indicator_data.csv",
                    mime="text/csv",
                    key="indicator-download"
                )
    else:
        # Show placeholder data on initial load
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📜 Recent CVEs")
            st.info("Click 'Refresh Data' to load threat intelligence")
        with col2:
            st.subheader("🦠 Malware Indicators")
            st.info("Click 'Refresh Data' to load threat intelligence")

# --- Enhanced Authentication UI --- #
def show_auth_interface():
    """Login and signup interface with Google Sign-In"""
    brand = load_brand_assets()
    
    st.markdown("""
    <style>
    .auth-header { text-align: center; margin-bottom: 2rem; }
    .auth-container { max-width: 500px; margin: 0 auto; }
    .google-btn { 
        background: #4285F4; 
        color: white; 
        border-radius: 4px; 
        padding: 10px; 
        text-align: center;
        margin: 10px 0;
    }
    .divider {
        display: flex;
        align-items: center;
        text-align: center;
        margin: 20px 0;
    }
    .divider::before, .divider::after {
        content: "";
        flex: 1;
        border-bottom: 1px solid #ddd;
    }
    .divider::before {
        margin-right: 10px;
    }
    .divider::after {
        margin-left: 10px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    with st.container():
        # Brand header
        if brand:
            st.image(brand["logo"], width=200, use_column_width=True)
        st.markdown("<h1 class='auth-header'>Secure Access Portal</h1>", 
                   unsafe_allow_html=True)
        
        # Show 2FA verification if required
        if st.session_state.auth.get('requires_2fa', False):
            show_2fa_verification()
            return
            
        tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Password Reset"])
        
        with tab1:
            # Google Sign-In Button - disabled for demo
            st.markdown(
                f'<a href="#" class="google-btn">Sign in with Google (Demo)</a>',
                unsafe_allow_html=True
            )
            
            st.markdown('<div class="divider">OR</div>', unsafe_allow_html=True)
            
            with st.form(key="login_form"):
                email = st.text_input("Email Address", value="demo@example.com")
                password = st.text_input("Password", type="password", value="demo123!")
                
                if st.form_submit_button("Login"):
                    if email == "demo@example.com" and password == "demo123!":
                        # Demo login
                        user = {
                            'email': 'demo@example.com',
                            'first_name': 'Demo',
                            'last_name': 'User',
                            'email_verified': True,
                            '2fa_enabled': False
                        }
                        complete_login(user)
                    else:
                        user = verify_login(email, password)
                        if user:
                            complete_login(user)
                        else:
                            st.error("Invalid credentials")
        
        with tab2:
            st.markdown(
                f'<a href="#" class="google-btn">Sign up with Google (Demo)</a>',
                unsafe_allow_html=True
            )
            
            st.markdown('<div class="divider">OR</div>', unsafe_allow_html=True)
            
            with st.form(key="signup_form"):
                col1, col2 = st.columns(2)
                with col1:
                    first_name = st.text_input("First Name", key="signup_first_name")
                with col2:
                    last_name = st.text_input("Last Name", key="signup_last_name")
                
                email = st.text_input("Email Address", key="signup_email")
                
                col1, col2 = st.columns(2)
                with col1:
                    password = st.text_input("Password", type="password", 
                                           help="Minimum 8 characters with at least one number, special character, and uppercase letter",
                                           key="signup_password")
                with col2:
                    confirm = st.text_input("Confirm Password", type="password",
                                          key="signup_confirm")
                
                # Terms and conditions checkbox
                accept_terms = st.checkbox(
                    "I accept the Terms of Service and Privacy Policy",
                    key="signup_terms"
                )
                
                if st.form_submit_button("Create Account"):
                    if not accept_terms:
                        st.error("You must accept the Terms of Service")
                    elif password != confirm:
                        st.error("Passwords don't match")
                    else:
                        is_valid, message = validate_password(password)
                        if not is_valid:
                            st.error(message)
                        else:
                            user = create_user(
                                email=email,
                                password=password,
                                first_name=first_name,
                                last_name=last_name
                            )
                            if user:
                                send_verification_email(email)
                                st.success("Account created! Please check your email for verification instructions.")
                                st.balloons()
                            else:
                                st.error("Email already exists")

        with tab3:
            with st.form(key="reset_form"):
                email = st.text_input("Enter your email address")
                if st.form_submit_button("Send Reset Link"):
                    if send_password_reset(email):
                        st.success("Password reset link sent to your email")
                    else:
                        st.error("Error sending reset link")

# --- Main Application Flow --- #
init_session_state()

# Handle Google OAuth callback if present
query_params = st.query_params
if 'code' in query_params:
    handle_google_callback()

if st.session_state.auth.get('authenticated'):
    if not st.session_state.auth['user'].get('email_verified'):
        st.warning("Please verify your email address")
        if st.button("Resend Verification Email"):
            send_verification_email(st.session_state.auth['user']['email'])
            st.success("Verification email sent!")
    else:
        show_main_app()
else:
    show_auth_interface()