import re
from datetime import datetime

class SyslogParser:
    def __init__(self):
        # Common syslog patterns
        self.patterns = {
            'cisco': r'<(\d+)>(\d+): (\w+ \d+ \d+:\d+:\d+) (\S+) (\S+): (.*)',
            'standard': r'<(\d+)>(\w+ \d+ \d+:\d+:\d+) (\S+) (.*)',
            'rsyslog': r'<(\d+)>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\d+-]+) (\S+) (.*)'
        }
    
    def parse(self, log_line):
        """Parse a syslog line"""
        for format_name, pattern in self.patterns.items():
            match = re.match(pattern, log_line)
            if match:
                return self._parse_by_format(format_name, match, log_line)
        
        # Fallback to simple parsing
        return self._parse_fallback(log_line)
    
    def _parse_by_format(self, format_name, match, log_line):
        """Parse based on detected format"""
        if format_name == 'cisco':
            return {
                'priority': match.group(1),
                'timestamp': self._parse_timestamp(match.group(3)),
                'hostname': match.group(4),
                'process': match.group(5),
                'message': match.group(6),
                'raw': log_line,
                'format': format_name
            }
        elif format_name == 'standard':
            return {
                'priority': match.group(1),
                'timestamp': self._parse_timestamp(match.group(2)),
                'hostname': match.group(3),
                'message': match.group(4),
                'raw': log_line,
                'format': format_name
            }
        elif format_name == 'rsyslog':
            return {
                'priority': match.group(1),
                'timestamp': self._parse_timestamp(match.group(2)),
                'hostname': match.group(3),
                'message': match.group(4),
                'raw': log_line,
                'format': format_name
            }
    
    def _parse_fallback(self, log_line):
        """Fallback parsing for unknown formats"""
        parts = log_line.split()
        if len(parts) >= 4:
            return {
                'priority': parts[0].strip('<>') if parts[0].startswith('<') else 'unknown',
                'timestamp': ' '.join(parts[1:3]),
                'hostname': parts[3],
                'message': ' '.join(parts[4:]),
                'raw': log_line,
                'format': 'unknown'
            }
        return {'raw': log_line, 'format': 'unparseable'}
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime"""
        try:
            # Try various timestamp formats
            formats = [
                '%b %d %H:%M:%S',  # Standard syslog
                '%Y-%m-%dT%H:%M:%S',  # ISO format
                '%Y-%m-%d %H:%M:%S'   # Common format
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            return datetime.now()
        except:
            return datetime.now()
    
    def batch_parse(self, log_lines):
        """Parse multiple log lines"""
        return [self.parse(line) for line in log_lines if line.strip()]