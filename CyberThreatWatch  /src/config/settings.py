# CyberThreatWatch Configuration Settings

# Application Settings
APP_NAME = "CyberThreatWatch"
APP_VERSION = "1.0.0"
DEBUG = True
HOST = "0.0.0.0"
PORT = 8050

# Database Settings
DATABASE = {
    "path": "data/cyberthreatwatch.db",
    "timeout": 30,
    "check_same_thread": False
}

# Data Processing Settings
DATA_PROCESSING = {
    "batch_size": 1000,
    "max_workers": 4,
    "timezone": "UTC"
}

# Logging Settings
LOGGING = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/cyberthreatwatch.log"
}

# API Settings
API = {
    "timeout": 30,
    "retries": 3,
    "rate_limit": 100  # requests per minute
}

# Search Settings
SEARCH = {
    "max_results": 1000,
    "default_time_range": "24h",
    "highlight_results": True
}

# Alert Settings
ALERTS = {
    "max_alerts": 100,
    "retention_days": 30,
    "email_notifications": False
}

# Visualization Settings
VISUALIZATION = {
    "default_theme": "light",
    "chart_animation": True,
    "max_data_points": 10000
}

# Security Settings
SECURITY = {
    "secret_key": "change-this-in-production",
    "password_hashing": "sha256",
    "session_timeout": 3600  # 1 hour
}

# External Integrations
INTEGRATIONS = {
    "virustotal": {
        "enabled": False,
        "api_key": ""
    },
    "abuseipdb": {
        "enabled": False,
        "api_key": ""
    },
    "alienvault_otx": {
        "enabled": False,
        "api_key": ""
    }
}

# Feature Flags
FEATURES = {
    "advanced_correlation": True,
    "threat_intel_enrichment": True,
    "behavioral_analytics": True,
    "real_time_processing": True
}