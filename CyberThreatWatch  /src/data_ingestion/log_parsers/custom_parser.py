import re
from datetime import datetime

class CustomParser:
    def __init__(self, pattern=None, field_mapping=None):
        """
        Initialize custom parser with pattern and field mapping
        
        Args:
            pattern: Regex pattern with named groups
            field_mapping: Dictionary mapping regex groups to output fields
        """
        self.pattern = pattern
        self.field_mapping = field_mapping or {}
        
        if pattern:
            self.regex = re.compile(pattern)
    
    def set_pattern(self, pattern, field_mapping=None):
        """Set parsing pattern and field mapping"""
        self.pattern = pattern
        self.regex = re.compile(pattern)
        if field_mapping:
            self.field_mapping = field_mapping
    
    def parse(self, log_line):
        """Parse log line using custom pattern"""
        if not self.pattern:
            return self._fallback_parse(log_line)
        
        match = self.regex.match(log_line)
        if not match:
            return self._fallback_parse(log_line)
        
        parsed = {
            'timestamp': datetime.now(),
            'message': log_line,
            'source': 'unknown',
            'raw': log_line
        }
        
        # Extract named groups
        for group_name, group_value in match.groupdict().items():
            output_field = self.field_mapping.get(group_name, group_name)
            parsed[output_field] = group_value
            
            # Special handling for common fields
            if group_name in ['timestamp', 'time']:
                parsed['timestamp'] = self._parse_timestamp(group_value)
            elif group_name in ['host', 'hostname', 'source']:
                parsed['source'] = group_value
            elif group_name in ['message', 'msg']:
                parsed['message'] = group_value
        
        return parsed
    
    def _fallback_parse(self, log_line):
        """Fallback parsing when pattern doesn't match"""
        return {
            'timestamp': datetime.now(),
            'message': log_line,
            'source': 'unknown',
            'raw': log_line
        }
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp from string"""
        try:
            # Try common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%b %d %H:%M:%S',  # Standard syslog
                '%Y-%m-%dT%H:%M:%S',  # ISO
                '%Y-%m-%dT%H:%M:%S.%fZ'  # ISO with milliseconds
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            return datetime.now()
        except:
            return datetime.now()
    
    def validate_pattern(self, test_lines):
        """Test pattern against sample lines"""
        results = []
        for line in test_lines:
            match = self.regex.match(line) if self.pattern else None
            results.append({
                'line': line,
                'matches': bool(match),
                'groups': match.groupdict() if match else {}
            })
        return results