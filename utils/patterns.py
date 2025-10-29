"""
Pattern matching utilities for FlagSniff
Contains regex patterns and matching logic
"""

import re
from typing import List, Dict, Any

class PatternMatcher:
    """Handles pattern matching for flags, credentials, and sensitive data"""
    
    def __init__(self):
        # Predefined regex patterns
        self.patterns = {
            'flag': [
                r'flag\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'htb\{[^}]+\}',
                r'DUCTF\{[^}]+\}',
                r'PICOCTF\{[^}]+\}',
                r'flag:\s*[a-zA-Z0-9_\-!@#$%^&*()]+',
                r'[a-z]{4,}\{[A-Za-z0-9_\-!@#$%^&*()]+\}'  # ADDED: More general flag pattern
            ],
            'credentials': [
                r'username[:\s=]+([^\s\r\n&]+)',
                r'user[:\s=]+([^\s\r\n&]+)',
                r'login[:\s=]+([^\s\r\n&]+)',
                r'password[:\s=]+([^\s\r\n&]+)',
                r'pass[:\s=]+([^\s\r\n&]+)',
                r'pwd[:\s=]+([^\s\r\n&]+)',
                r'Authorization: Basic ([A-Za-z0-9+/=]+)',
                r'admin[:\s=]+([^\s\r\n&]+)',
                r'root[:\s=]+([^\s\r\n&]+)',
            ],
            'tokens': [
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',  # JWT
                r'(?i)apikey[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)token[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)secret[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)key[\s:=]+[A-Za-z0-9]{16,}'
            ],
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'hashes': [
                r'\b[a-fA-F0-9]{32}\b',  # MD5
                r'\b[a-fA-F0-9]{40}\b',  # SHA1
                r'\b[a-fA-F0-9]{64}\b'   # SHA256
            ]
        }
    
    def search_pattern(self, pattern_type: str, packet_data_list: List[Dict]) -> List[Dict]:
        """Search for patterns in packet data list"""
        results = []
        
        if pattern_type not in self.patterns:
            return results
        
        patterns = self.patterns[pattern_type]
        
        for packet_data in packet_data_list:
            data = packet_data.get('data', '')
            if not data:
                continue
                
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, data, re.IGNORECASE)
                    for match in matches:
                        results.append({
                            'type': pattern_type,
                            'pattern': pattern,
                            'match': match.group(),
                            'packet_index': packet_data.get('packet_index', 0),
                            'protocol': packet_data.get('protocol', 'Unknown'),
                            'src': packet_data.get('src', ''),
                            'dst': packet_data.get('dst', ''),
                            'confidence': self._calculate_confidence(pattern_type, match.group())
                        })
                except re.error:
                    continue
        
        return results
    
    def _calculate_confidence(self, pattern_type: str, match: str) -> int:
        """Calculate confidence score for pattern matches (0-100)"""
        # Base confidence scores by type
        base_scores = {
            'flag': 90,
            'credentials': 85, 
            'tokens': 80,
            'emails': 75,
            'hashes': 70
        }
        
        base = base_scores.get(pattern_type, 70)
        
        # Adjust based on match characteristics
        if pattern_type == 'flag':
            if len(match) > 20:
                base += 5  # Longer flags tend to be more specific
            if match.lower().startswith(('flag{', 'ctf{')):
                base += 5  # Standard flag formats
        
        elif pattern_type == 'credentials':
            if len(match) > 10:
                base += 5  # Longer credentials more likely to be real
            if any(word in match.lower() for word in ['admin', 'root', 'user']):
                base += 5  # Common credential keywords
        
        return min(100, base)
    
    def search_patterns(self, packet_data: Dict[str, Any], search_types: List[str], custom_regex: str = None) -> List[Dict]:
        """Search for patterns in packet data"""
        results = []
        data_to_search = packet_data.get('data', '')
        
        if not data_to_search:
            return results
        
        # Search predefined patterns
        for search_type in search_types:
            if search_type in self.patterns:
                for pattern in self.patterns[search_type]:
                    matches = re.finditer(pattern, data_to_search, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Calculate confidence based on pattern type and match characteristics
                        confidence = self._calculate_pattern_confidence(search_type, pattern, match.group(0))
                        
                        results.append({
                            'type': search_type,
                            'pattern': pattern,
                            'data': match.group(0),
                            'position': match.span(),
                            'protocol': packet_data.get('protocol', 'Unknown'),
                            'src': packet_data.get('src', ''),
                            'dst': packet_data.get('dst', ''),
                            'context': self._get_context(data_to_search, match.span(), 50),
                            'confidence': confidence
                        })
        
        # Search custom regex
        if custom_regex:
            try:
                matches = re.finditer(custom_regex, data_to_search, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    confidence = self._calculate_pattern_confidence('custom', custom_regex, match.group(0))
                    
                    results.append({
                        'type': 'custom',
                        'pattern': custom_regex,
                        'data': match.group(0),
                        'position': match.span(),
                        'protocol': packet_data.get('protocol', 'Unknown'),
                        'src': packet_data.get('src', ''),
                        'dst': packet_data.get('dst', ''),
                        'context': self._get_context(data_to_search, match.span(), 50),
                        'confidence': confidence
                    })
            except re.error as e:
                print(f"❌ Invalid regex pattern: {e}")
        
        return results
    
    def _get_context(self, text: str, span: tuple, context_size: int = 50) -> str:
        """Get context around matched text"""
        start, end = span
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        context = text[context_start:context_end]
        
        # Add ellipsis if truncated
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
        
        return context
    
    def add_custom_pattern(self, pattern_type: str, regex: str):
        """Add a custom pattern to the matcher"""
        if pattern_type not in self.patterns:
            self.patterns[pattern_type] = []
        self.patterns[pattern_type].append(regex)
    
    def get_pattern_info(self) -> Dict[str, List[str]]:
        """Get information about all available patterns"""
        return self.patterns.copy()
    
    def _calculate_pattern_confidence(self, search_type: str, pattern: str, match_text: str) -> int:
        """Calculate confidence score for a pattern match"""
        
        # Base confidence by pattern type
        base_confidence = {
            'flag': 95,        # Flags are highly specific
            'credentials': 90,  # Credentials are important
            'tokens': 85,      # Tokens are valuable
            'emails': 80,      # Emails are common but useful
            'hashes': 75,      # Hashes need context
            'ips': 70,         # IPs are common
            'urls': 75,        # URLs are moderately useful
            'custom': 80       # Custom patterns get medium confidence
        }.get(search_type, 70)
        
        # Adjust confidence based on match characteristics
        confidence = base_confidence
        
        # Pattern-specific adjustments
        if search_type == 'flag':
            # Higher confidence for well-formed flags
            if any(prefix in match_text.lower() for prefix in ['flag{', 'ctf{', 'htb{']):
                confidence = 95
            elif match_text.count('{') == 1 and match_text.count('}') == 1:
                confidence = 90
            else:
                confidence = 85
                
        elif search_type == 'credentials':
            # Higher confidence for explicit credential patterns
            if any(keyword in match_text.lower() for keyword in ['password', 'passwd', 'admin', 'root']):
                confidence = 92
            elif 'authorization: basic' in match_text.lower():
                confidence = 95  # Base64 auth is very likely credentials
            else:
                confidence = 88
                
        elif search_type == 'tokens':
            # Adjust based on token format and length
            if match_text.startswith('eyJ'):  # JWT
                confidence = 90
            elif len(match_text) > 40:  # Long tokens are more likely to be real
                confidence = 88
            elif len(match_text) > 20:
                confidence = 85
            else:
                confidence = 75
                
        elif search_type == 'hashes':
            # Adjust based on hash format
            if len(match_text) == 32:  # MD5
                confidence = 80
            elif len(match_text) == 40:  # SHA1
                confidence = 82
            elif len(match_text) == 64:  # SHA256
                confidence = 85
            else:
                confidence = 70
        
        # Additional adjustments for context
        match_lower = match_text.lower()
        
        # Boost confidence for suspicious/interesting content
        if any(word in match_lower for word in ['secret', 'key', 'private', 'hidden']):
            confidence = min(confidence + 5, 98)
            
        # Lower confidence for very common/generic patterns
        if any(word in match_lower for word in ['example', 'test', 'demo', 'sample']):
            confidence = max(confidence - 10, 50)
            
        return max(50, min(confidence, 98))  # Keep between 50-98%
