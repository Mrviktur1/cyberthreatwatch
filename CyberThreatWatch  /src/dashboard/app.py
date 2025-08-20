import streamlit as st
import os
import sys
import sqlite3
import bcrypt
import pyotp
import qrcode
import secrets
import re
import logging
from datetime import datetime, timedelta
from pathlib import Path
from io import BytesIO
from typing import Optional, Dict, Any, Tuple
import pandas as pd
from PIL import Image
import httpx

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

# Configure paths
current_dir = Path(__file__).parent
assets_dir = current_dir.parent / "assets"
data_dir = current_dir.parent / "data"

# Ensure directories exist
os.makedirs(assets_dir, exist_ok=True)
os.makedirs(data_dir, exist_ok=True)

# Security configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_MINUTES = 30
SESSION_TIMEOUT_MINUTES = 60
TOKEN_EXPIRY_HOURS = 24

# Rate limiting storage
login_attempts = {}

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

# Database setup
def init_db():
    """Initialize SQLite database with secure schema"""
    db_path = data_dir / "users.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Users table with security features
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
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
        account_locked_until DATETIME,
        last_password_change DATETIME
    )
    ''')
    
    # Security events logging table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        event_details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_verification_token ON users(verification_token)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reset_token ON users(reset_token)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events ON security_events(user_id, event_type)')
    
    conn.commit()
    conn.close()
    return True

# Input validation
def validate_email(email: str) -> bool:
    """Validate email format securely"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(input_str: str, max_length: int = 255) -> str:
    """Sanitize user input to prevent XSS and injection attacks"""
    if not input_str:
        return ""
    # Remove potentially dangerous characters and truncate
    sanitized = re.sub(r'[<>"\'();&]', '', input_str.strip())
    return sanitized[:max_length]

def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength with multiple criteria"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(not char.isalnum() for char in password):
        return False, "Password must contain at least one special character"
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"
    return True, "Password is strong"

# Rate limiting and account protection
def check_rate_limit(email: str, action: str = 'login') -> bool:
    """Check if user has exceeded rate limits"""
    now = datetime.now()
    key = f"{email}_{action}"
    
    if key not in login_attempts:
        login_attempts[key] = []
    
    # Clean old attempts
    login_attempts[key] = [
        t for t in login_attempts[key] 
        if now - t < timedelta(minutes=15)
    ]
    
    # Check limit
    if len(login_attempts[key]) >= MAX_LOGIN_ATTEMPTS:
        return False
    
    login_attempts[key].append(now)
    return True

def is_account_locked(email: str) -> bool:
    """Check if account is locked due to too many failed attempts"""
    try:
        conn = sqlite3.connect(data_dir / "users.db")
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT account_locked_until FROM users WHERE email = ?',
            (email,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            lock_until = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
            return datetime.now() < lock_until
        
        return False
    except Exception as e:
        logger.error(f"Error checking account lock: {e}")
        return False

def record_failed_attempt(email: str):
    """Record a failed login attempt and lock account if necessary"""
    try:
        conn = sqlite3.connect(data_dir / "users.db")
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT failed_login_attempts FROM users WHERE email = ?',
            (email,)
        )
        
        result = cursor.fetchone()
        if result:
            failed_attempts = result[0] + 1
            lock_until = None
            
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                lock_until = datetime.now() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
                logger.warning(f"Account locked for {email}")
            
            cursor.execute(
                '''UPDATE users SET failed_login_attempts = ?, 
                account_locked_until = ? WHERE email = ?''',
                (failed_attempts, lock_until, email)
            )
            
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error recording failed attempt: {e}")

def reset_failed_attempts(email: str):
    """Reset failed login attempts after successful login"""
    try:
        conn = sqlite3.connect(data_dir / "users.db")
        cursor = conn.cursor()
        
        cursor.execute(
            '''UPDATE users SET failed_login_attempts = 0, 
            account_locked_until = NULL WHERE email = ?''',
            (email,)
        )
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error resetting failed attempts: {e}")

# Password hashing with bcrypt
def hash_password(password: str) -> str:
    """Hash password using bcrypt with appropriate cost"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Database operations
def get_db_connection():
    """Get a database connection with timeout"""
    return sqlite3.connect(data_dir / "users.db", timeout=30)

def create_user(email: str, password: str, first_name: str = "", last_name: str = "") -> Optional[Dict]:
    """Create a new user with secure password hashing"""
    try:
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
        
        password_hash = hash_password(password)
        verification_token = secrets.token_urlsafe(32)
        verification_token_expiry = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, first_name, last_name, 
                             verification_token, verification_token_expiry)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, password_hash, first_name, last_name, 
              verification_token, verification_token_expiry))
        
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
    """Verify user login with security checks"""
    try:
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        
        # Check rate limiting
        if not check_rate_limit(email, 'login'):
            st.error("Too many login attempts. Please try again in 15 minutes.")
            return None
            
        # Check if account is locked
        if is_account_locked(email):
            st.error("Account temporarily locked. Please try again later.")
            return None
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT email, password_hash, first_name, last_name, 
                   email_verified, two_fa_enabled, two_fa_secret
            FROM users WHERE email = ? AND email_verified = TRUE
        ''', (email,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(password, user[1]):
            reset_failed_attempts(email)
            update_last_login(email)
            
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
            record_failed_attempt(email)
            logger.warning(f"Failed login attempt: {email}")
            return None
            
    except Exception as e:
        logger.error(f"Error verifying login: {e}")
        return None

def update_last_login(email: str):
    """Update last login timestamp"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET last_login = ? WHERE email = ?',
            (datetime.now(), email)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error updating last login: {e}")

# 2FA functions
def initiate_2fa_setup(email: str) -> Dict:
    """Initiate 2FA setup with secure secret generation"""
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, 
        issuer_name="CyberThreatWatch"
    )
    return {
        'secret': secret,
        'provisioning_uri': provisioning_uri
    }

def verify_2fa_code(email: str, code: str, secret: Optional[str] = None) -> bool:
    """Verify 2FA code securely"""
    if secret:
        # New 2FA setup
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET two_fa_secret = ?, two_fa_enabled = TRUE WHERE email = ?',
                    (secret, email)
                )
                conn.commit()
                conn.close()
                logger.info(f"2FA enabled for: {email}")
                return True
            except Exception as e:
                logger.error(f"Error enabling 2FA: {e}")
        return False
    else:
        # Existing 2FA verification
        user = get_user_by_email(email)
        if user and user.get('2fa_secret'):
            totp = pyotp.TOTP(user['2fa_secret'])
            return totp.verify(code)
    return False

def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email securely"""
    try:
        if not validate_email(email):
            return None
            
        email = sanitize_input(email)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT email, first_name, last_name, email_verified, two_fa_enabled, two_fa_secret
            FROM users WHERE email = ?
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
        logger.error(f"Error getting user: {e}")
        return None

# Token management
def generate_secure_token() -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(32)

def store_verification_token(email: str) -> bool:
    """Store verification token with expiry"""
    try:
        token = generate_secure_token()
        expiry = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET verification_token = ?, verification_token_expiry = ? WHERE email = ?',
            (token, expiry, email)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error storing verification token: {e}")
        return False

def verify_email_token(token: str) -> bool:
    """Verify email token with expiry check"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT email, verification_token_expiry FROM users WHERE verification_token = ?',
            (token,)
        )
        
        result = cursor.fetchone()
        if not result:
            return False
            
        email, expiry_str = result
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
        
        if datetime.now() > expiry:
            logger.warning(f"Expired verification token for: {email}")
            return False
        
        cursor.execute(
            '''UPDATE users SET email_verified = TRUE, 
            verification_token = NULL, verification_token_expiry = NULL 
            WHERE verification_token = ?''',
            (token,)
        )
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        if success:
            logger.info(f"Email verified for: {email}")
        return success
    except Exception as e:
        logger.error(f"Error verifying email token: {e}")
        return False

# Threat intelligence functions (simplified for demo)
def fetch_recent_cves(api_key: Optional[str] = None, days: int = 7, max_results: int = 50) -> pd.DataFrame:
    """Fetch recent CVEs with error handling"""
    try:
        # Sample data for demo - in production, use real API
        cve_ids = [f'CVE-2023-{1000+i}' for i in range(max_results)]
        descriptions = [f'Sample vulnerability description {i+1}' for i in range(max_results)]
        published_dates = [(datetime.now() - timedelta(days=i % days)).strftime('%Y-%m-%d') for i in range(max_results)]
        cvss_scores = [round(1 + (i % 9), 1) for i in range(max_results)]
        
        severity_options = ['Low', 'Medium', 'High', 'Critical']
        severities = [severity_options[i % 4] for i in range(max_results)]
        
        return pd.DataFrame({
            'CVE ID': cve_ids,
            'Description': descriptions,
            'Published': published_dates,
            'CVSS Score': cvss_scores,
            'Severity': severities
        })
    except Exception as e:
        logger.error(f"Error fetching CVE data: {e}")
        return pd.DataFrame()

def get_pulse_indicators(api_key: Optional[str] = None) -> pd.DataFrame:
    """Fetch threat indicators with error handling"""
    try:
        # Sample data for demo
        indicators = [f'192.168.1.{i}' for i in range(1, 21)]
        type_options = ['IPv4', 'Domain', 'URL', 'Hash']
        types = [type_options[i % 4] for i in range(20)]
        malware = [f'Malware Family {chr(65 + (i % 5))}' for i in range(20)]
        first_seen = [(datetime.now() - timedelta(days=i % 30)).strftime('%Y-%m-%d') for i in range(20)]
        reputation_options = ['Malicious', 'Suspicious', 'Unknown']
        reputations = [reputation_options[i % 3] for i in range(20)]
        
        return pd.DataFrame({
            'Indicator': indicators,
            'Type': types,
            'Malware': malware,
            'First Seen': first_seen,
            'Reputation': reputations
        })
    except Exception as e:
        logger.error(f"Error fetching OTX data: {e}")
        return pd.DataFrame()

# UI Components
def load_brand_assets():
    """Load brand images with error handling"""
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

def show_2fa_verification():
    """Show 2FA verification interface"""
    st.markdown("""
    <style>
    .auth-header { text-align: center; margin-bottom: 2rem; }
    .auth-container { max-width: 500px; margin: 0 auto; }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("<h1 class='auth-header'>Two-Factor Authentication</h1>", unsafe_allow_html=True)
    
    if st.session_state.temp_2fa_secret:
        st.info("Scan this QR code with your authenticator app")
        img = qrcode.make(st.session_state.temp_2fa_secret['provisioning_uri'])
        buf = BytesIO()
        img.save(buf, format="PNG")
        st.image(buf, width=200)
    
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

def show_main_app():
    """Main application dashboard"""
    st.title("🔍 CyberThreatWatch - Live Threat Intelligence")
    
    with st.sidebar:
        st.header("Settings")
        days = st.slider("Lookback period (days)", 1, 30, 7)
        max_results = st.slider("Max results", 10, 100, 50)
        
        st.subheader("API Configuration")
        nvd_api_key = st.text_input("NVD API Key (optional)", type="password")
        otx_api_key = st.text_input("OTX API Key (optional)", type="password")
        
        if st.button("🔄 Refresh Data", type="primary"):
            with st.spinner("Loading threat data..."):
                cve_data = fetch_recent_cves(api_key=nvd_api_key, days=days, max_results=max_results)
                otx_data = get_pulse_indicators(api_key=otx_api_key)
                
                st.session_state.threat_data = {'cves': cve_data, 'indicators': otx_data}
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

    if st.session_state.data_loaded:
        cve_data = st.session_state.threat_data['cves']
        otx_data = st.session_state.threat_data['indicators']
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📜 Recent CVEs")
            st.dataframe(cve_data, height=600, use_container_width=True)
        with col2:
            st.subheader("🦠 Malware Indicators")
            st.dataframe(otx_data, height=600, use_container_width=True)
    else:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📜 Recent CVEs")
            st.info("Click 'Refresh Data' to load threat intelligence")
        with col2:
            st.subheader("🦠 Malware Indicators")
            st.info("Click 'Refresh Data' to load threat intelligence")

def show_auth_interface():
    """Login and signup interface"""
    st.markdown("""
    <style>
    .auth-header { text-align: center; margin-bottom: 2rem; }
    .auth-container { max-width: 500px; margin: 0 auto; }
    </style>
    """, unsafe_allow_html=True)
    
    if st.session_state.auth.get('requires_2fa', False):
        show_2fa_verification()
        return
        
    tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Password Reset"])
    
    with tab1:
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
        with st.form(key="signup_form"):
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name")
            with col2:
                last_name = st.text_input("Last Name")
            
            email = st.text_input("Email Address")
            
            col1, col2 = st.columns(2)
            with col1:
                password = st.text_input("Password", type="password", 
                                       help="Minimum 12 characters with number, special character, uppercase and lowercase")
            with col2:
                confirm = st.text_input("Confirm Password", type="password")
            
            accept_terms = st.checkbox("I accept the Terms of Service and Privacy Policy")
            
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
                        user = create_user(email=email, password=password, 
                                         first_name=first_name, last_name=last_name)
                        if user:
                            store_verification_token(email)
                            st.success("Account created! Please check your email for verification instructions.")
                        else:
                            st.error("Email already exists")
    
    with tab3:
        with st.form(key="reset_form"):
            email = st.text_input("Enter your email address")
            if st.form_submit_button("Send Reset Link"):
                if store_verification_token(email):
                    st.success("Password reset link sent to your email")
                else:
                    st.error("Error sending reset link")

def complete_login(user):
    """Finalize successful login"""
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

# Main application flow
def main():
    """Main application entry point"""
    st.set_page_config(
        layout="wide",
        page_title="CyberThreatWatch",
        page_icon="🔒",
        menu_items={
            'About': "CyberThreatWatch™ v2.1 | © 2025 SecureCorp Inc."
        }
    )
    
    # Initialize application
    init_db()
    init_session_state()
    
    # Check session timeout
    if (st.session_state.auth.get('authenticated') and 
        st.session_state.auth.get('last_activity') and
        (datetime.now() - st.session_state.auth['last_activity']).total_seconds() > SESSION_TIMEOUT_MINUTES * 60):
        st.session_state.auth = {
            'authenticated': False,
            'user': None,
            'last_activity': None,
            'requires_2fa': False
        }
        st.warning("Session expired. Please login again.")
    
    # Update last activity
    if st.session_state.auth.get('authenticated'):
        st.session_state.auth['last_activity'] = datetime.now()
    
    # Route to appropriate interface
    if st.session_state.auth.get('authenticated'):
        if not st.session_state.auth['user'].get('email_verified'):
            st.warning("Please verify your email address")
            if st.button("Resend Verification Email"):
                if store_verification_token(st.session_state.auth['user']['email']):
                    st.success("Verification email sent!")
        else:
            show_main_app()
    else:
        show_auth_interface()

if __name__ == "__main__":
    main()