import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class FieldExtractor:
    def __init__(self):
        # Common regex patterns for field extraction
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b',
            'mac': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b'
        }
    
    def extract_fields(self, text: str, custom_patterns: Optional[Dict] = None) -> Dict[str, List[str]]:
        """Extract fields from text using regex patterns"""
        results = {}
        all_patterns = {**self.patterns, **(custom_patterns or {})}
        
        for field_name, pattern in all_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results[field_name] = list(set(matches))  # Remove duplicates
        
        return results
    
    def extract_from_json(self, json_data: Dict, field_mapping: Optional[Dict] = None) -> Dict[str, Any]:
        """Extract fields from JSON data using mapping"""
        results = {}
        field_mapping = field_mapping or {}
        
        for target_field, source_path in field_mapping.items():
            value = self._get_nested_value(json_data, source_path)
            if value is not None:
                results[target_field] = value
        
        # Also extract all top-level fields
        for key, value in json_data.items():
            if key not in results:
                results[key] = value
        
        return results
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def extract_using_xpath(self, xml_content: str, xpath_expressions: Dict[str, str]) -> Dict[str, Any]:
        """Extract fields from XML using XPath expressions"""
        try:
            import xml.etree.ElementTree as ET
            results = {}
            
            root = ET.fromstring(xml_content)
            
            for field_name, xpath in xpath_expressions.items():
                elements = root.findall(xpath)
                if elements:
                    if len(elements) == 1:
                        results[field_name] = elements[0].text
                    else:
                        results[field_name] = [elem.text for elem in elements]
            
            return results
            
        except ImportError:
            print("XML parsing requires ElementTree")
            return {}
        except Exception as e:
            print(f"XPath extraction error: {e}")
            return {}

class LogFieldExtractor(FieldExtractor):
    def __init__(self):
        super().__init__()
        # Common log field patterns
        self.log_patterns = {
            'timestamp': r'\b(?:\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2})',
            'log_level': r'\b(?:INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL|FATAL)\b',
            'process_id': r'\bpid[=\s:]*(\d+)\b',
            'thread_id': r'\btid[=\s:]*(\d+)\b',
            'user_id': r'\buser[=\s:]*([^\s]+)\b',
            'session_id': r'\bsession[=\s:]*([^\s]+)\b'
        }
    
    def extract_log_fields(self, log_line: str) -> Dict[str, Any]:
        """Extract common log fields"""
        results = self.extract_fields(log_line, self.log_patterns)
        
        # Try to extract structured data if it looks like JSON
        if log_line.strip().startswith(('{', '[')):
            try:
                json_data = json.loads(log_line)
                if isinstance(json_data, dict):
                    results.update(self.extract_from_json(json_data))
            except json.JSONDecodeError:
                pass
        
        return results