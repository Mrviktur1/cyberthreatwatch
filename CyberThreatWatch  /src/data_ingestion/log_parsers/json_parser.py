import json
from datetime import datetime

class JSONParser:
    def __init__(self):
        pass
    
    def parse(self, json_data):
        """Parse JSON data"""
        try:
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data
            
            # Ensure standard fields
            parsed = {
                'timestamp': data.get('timestamp', data.get('time', data.get('@timestamp', datetime.now()))),
                'message': data.get('message', str(data)),
                'source': data.get('source', data.get('host', data.get('hostname', 'unknown'))),
                'severity': data.get('severity', data.get('level', 'info')).lower(),
                'raw': json_data if isinstance(json_data, str) else json.dumps(json_data)
            }
            
            # Add all other fields
            for key, value in data.items():
                if key not in parsed:
                    parsed[key] = value
            
            return parsed
        except json.JSONDecodeError:
            return {
                'timestamp': datetime.now(),
                'message': f"Invalid JSON: {json_data}",
                'source': 'parser',
                'severity': 'error',
                'raw': json_data
            }
    
    def batch_parse(self, json_lines):
        """Parse multiple JSON objects"""
        results = []
        for line in json_lines:
            if line.strip():
                results.append(self.parse(line))
        return results