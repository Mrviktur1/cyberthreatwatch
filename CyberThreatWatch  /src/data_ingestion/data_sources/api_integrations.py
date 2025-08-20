import requests
import json
from datetime import datetime, timedelta
import time
from typing import List, Dict, Any, Optional

class APIIntegration:
    def __init__(self, base_url: str, auth_type: str = "none", 
                 credentials: Optional[Dict] = None, headers: Optional[Dict] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_type = auth_type
        self.credentials = credentials or {}
        self.headers = headers or {}
        self.session = requests.Session()
        self.setup_auth()
    
    def setup_auth(self):
        """Setup authentication based on type"""
        if self.auth_type == "basic":
            self.session.auth = (self.credentials.get('username'), self.credentials.get('password'))
        elif self.auth_type == "bearer":
            token = self.credentials.get('token')
            if token:
                self.headers['Authorization'] = f'Bearer {token}'
        elif self.auth_type == "api_key":
            key_name = self.credentials.get('key_name', 'X-API-Key')
            key_value = self.credentials.get('key_value')
            if key_value:
                self.headers[key_name] = key_value
    
    def make_request(self, endpoint: str, method: str = "GET", 
                    params: Optional[Dict] = None, data: Optional[Dict] = None,
                    timeout: int = 30) -> Dict:
        """Make API request"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=self.headers,
                timeout=timeout
            )
            
            response.raise_for_status()
            
            if response.headers.get('content-type', '').startswith('application/json'):
                return response.json()
            else:
                return {'data': response.text, 'status_code': response.status_code}
                
        except requests.exceptions.RequestException as e:
            return {'error': str(e), 'status_code': getattr(e.response, 'status_code', None)}
    
    def fetch_data(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch data from API endpoint"""
        result = self.make_request(endpoint, params=params)
        if 'error' not in result:
            return result.get('data', []) if isinstance(result, dict) else result
        return []
    
    def stream_data(self, endpoint: str, callback: callable, 
                   interval: int = 60, params: Optional[Dict] = None):
        """Continuously fetch data from API"""
        while True:
            data = self.fetch_data(endpoint, params)
            if data:
                callback({
                    'timestamp': datetime.now(),
                    'data': data,
                    'source': f"{self.base_url}/{endpoint}"
                })
            time.sleep(interval)

class SecurityAPIIntegration(APIIntegration):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add security-specific headers
        self.headers.update({
            'User-Agent': 'CyberThreatWatch/1.0',
            'Accept': 'application/json'
        })
    
    def fetch_security_events(self, since: Optional[datetime] = None):
        """Fetch security events from API"""
        params = {}
        if since:
            params['since'] = since.isoformat()
        
        return self.fetch_data('/security/events', params)
    
    def fetch_threat_intel(self, ioc_type: Optional[str] = None):
        """Fetch threat intelligence data"""
        params = {}
        if ioc_type:
            params['type'] = ioc_type
        
        return self.fetch_data('/threat-intel', params)