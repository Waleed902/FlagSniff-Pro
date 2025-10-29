"""
Enhanced CTF Flag Reconstruction Engine
Reconstructs flags distributed across multiple packets, protocols, and encoding layers
"""

import re
import json
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque
from datetime import datetime
import base64
import hashlib

class TemporalCorrelator:
    """Correlates flag fragments based on timing patterns"""
    
    def __init__(self, time_window: float = 5.0):
        self.time_window = time_window  # seconds
        
    def group_by_timing(self, fragments: List[Dict]) -> List[List[Dict]]:
        """Group fragments that appear within time windows"""
        if not fragments:
            return []
            
        # Sort by timestamp
        sorted_fragments = sorted(fragments, key=lambda x: x.get('timestamp', 0))
        groups = []
        current_group = [sorted_fragments[0]]
        
        for fragment in sorted_fragments[1:]:
            last_time = current_group[-1].get('timestamp', 0)
            current_time = fragment.get('timestamp', 0)
            
            if current_time - last_time <= self.time_window:
                current_group.append(fragment)
            else:
                groups.append(current_group)
                current_group = [fragment]
        
        if current_group:
            groups.append(current_group)
            
        return groups

class FragmentAnalyzer:
    """Analyzes individual flag fragments for reconstruction clues"""
    
    def __init__(self):
        self.flag_patterns = [
            r'flag\{[^}]*\}',
            r'CTF\{[^}]*\}',
            r'HTB\{[^}]*\}',
            r'DUCTF\{[^}]*\}',
            r'PICOCTF\{[^}]*\}',
            r'[A-Z]{2,8}\{[^}]*\}'
        ]
        
    def identify_fragments(self, findings: List[Dict]) -> List[Dict]:
        """Identify potential flag fragments from findings"""
        fragments = []
        
        for finding in findings:
            data = str(finding.get('data', ''))
            
            # Check for partial flag patterns
            partial_patterns = [
                r'flag\{[^}]*$',  # Opening fragment
                r'^[^{]*\}',      # Closing fragment
                r'[a-zA-Z0-9_]{8,}',  # Middle fragment
                r'CTF\{[^}]*$',
                r'^[^{]*\}'
            ]
            
            for pattern in partial_patterns:
                matches = re.finditer(pattern, data, re.IGNORECASE)
                for match in matches:
                    fragment_info = self._analyze_fragment(match.group(), finding)
                    if fragment_info['is_potential_fragment']:
                        fragments.append(fragment_info)
        
        return fragments
    
    def _analyze_fragment(self, fragment: str, finding: Dict) -> Dict[str, Any]:
        """Analyze a single fragment for reconstruction potential"""
        return {
            'fragment': fragment,
            'packet_index': finding.get('packet_index', 0),
            'protocol': finding.get('protocol', 'Unknown'),
            'timestamp': finding.get('timestamp', 0),
            'src': finding.get('src', ''),
            'dst': finding.get('dst', ''),
            'is_opening': fragment.endswith('{') or 'flag{' in fragment.lower(),
            'is_closing': fragment.endswith('}'),
            'is_middle': not (fragment.endswith('{') or fragment.endswith('}')),
            'length': len(fragment),
            'encoding_hints': self._detect_encoding_hints(fragment),
            'confidence': self._calculate_fragment_confidence(fragment),
            'is_potential_fragment': self._is_potential_fragment(fragment)
        }
    
    def _detect_encoding_hints(self, fragment: str) -> List[str]:
        """Detect encoding patterns in fragment"""
        hints = []
        
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', fragment):
            hints.append('base64')
        if re.match(r'^[0-9a-fA-F]+$', fragment):
            hints.append('hex')
        if re.match(r'^[01]+$', fragment):
            hints.append('binary')
        if any(c in fragment for c in '.-'):
            hints.append('morse')
            
        return hints
    
    def _calculate_fragment_confidence(self, fragment: str) -> float:
        """Calculate confidence that this is a legitimate flag fragment"""
        confidence = 0.5
        
        # Pattern matching boosts
        if 'flag' in fragment.lower():
            confidence += 0.3
        if 'ctf' in fragment.lower():
            confidence += 0.2
        if '{' in fragment or '}' in fragment:
            confidence += 0.2
        
        # Length analysis
        if 5 <= len(fragment) <= 50:
            confidence += 0.1
        elif len(fragment) > 50:
            confidence -= 0.1
            
        return min(1.0, confidence)
    
    def _is_potential_fragment(self, fragment: str) -> bool:
        """Determine if fragment could be part of a flag"""
        if len(fragment) < 3:
            return False
        
        # Check for flag-like characteristics
        has_flag_keywords = any(word in fragment.lower() 
                               for word in ['flag', 'ctf', 'htb'])
        has_brackets = '{' in fragment or '}' in fragment
        has_alphanumeric = any(c.isalnum() for c in fragment)
        
        return has_flag_keywords or has_brackets or (has_alphanumeric and len(fragment) >= 8)

class FlagReconstructionEngine:
    """Main flag reconstruction engine with advanced correlation"""
    
    def __init__(self):
        self.fragment_analyzer = FragmentAnalyzer()
        self.temporal_correlator = TemporalCorrelator()
        self.reconstruction_strategies = [
            self._sequential_reconstruction,
            self._protocol_based_reconstruction,
            self._encoding_chain_reconstruction,
            self._temporal_reconstruction
        ]
        
    def reconstruct_distributed_flags(self, findings: List[Dict]) -> Dict[str, Any]:
        """Main reconstruction method using multiple strategies"""
        start_time = time.time()
        
        # Identify fragments
        fragments = self.fragment_analyzer.identify_fragments(findings)
        
        # Apply reconstruction strategies
        reconstructed_flags = []
        reconstruction_logs = []
        
        for strategy in self.reconstruction_strategies:
            try:
                results = strategy(fragments)
                if results:
                    reconstructed_flags.extend(results['flags'])
                    reconstruction_logs.append({
                        'strategy': strategy.__name__,
                        'flags_found': len(results['flags']),
                        'confidence': results.get('confidence', 0.5),
                        'details': results.get('details', {})
                    })
            except Exception as e:
                reconstruction_logs.append({
                    'strategy': strategy.__name__,
                    'error': str(e)
                })
        
        # Remove duplicates and rank by confidence
        unique_flags = self._deduplicate_flags(reconstructed_flags)
        ranked_flags = sorted(unique_flags, key=lambda x: x['confidence'], reverse=True)
        
        return {
            'reconstructed_flags': ranked_flags,
            'fragments_analyzed': len(fragments),
            'strategies_applied': len(self.reconstruction_strategies),
            'reconstruction_logs': reconstruction_logs,
            'processing_time': time.time() - start_time,
            'success_rate': len(ranked_flags) / max(len(fragments), 1)
        }
    
    def _sequential_reconstruction(self, fragments: List[Dict]) -> Dict[str, Any]:
        """Reconstruct flags by sequential packet order"""
        flags = []
        
        # Sort by packet index
        sorted_fragments = sorted(fragments, key=lambda x: x['packet_index'])
        
        # Try to combine adjacent fragments
        for i in range(len(sorted_fragments)):
            for j in range(i + 1, min(i + 5, len(sorted_fragments))):
                combined = self._attempt_combination(sorted_fragments[i:j+1])
                if combined and self._validate_flag(combined['flag']):
                    flags.append(combined)
        
        return {
            'flags': flags,
            'confidence': 0.7,
            'details': {'method': 'sequential_packet_order'}
        }
    
    def _protocol_based_reconstruction(self, fragments: List[Dict]) -> Dict[str, Any]:
        """Reconstruct flags by grouping same protocol fragments"""
        flags = []
        protocol_groups = defaultdict(list)
        
        # Group by protocol
        for fragment in fragments:
            protocol_groups[fragment['protocol']].append(fragment)
        
        # Try reconstruction within each protocol
        for protocol, group in protocol_groups.items():
            if len(group) >= 2:
                combined = self._attempt_combination(group)
                if combined and self._validate_flag(combined['flag']):
                    flags.append(combined)
        
        return {
            'flags': flags,
            'confidence': 0.8,
            'details': {'protocols_analyzed': list(protocol_groups.keys())}
        }
    
    def _encoding_chain_reconstruction(self, fragments: List[Dict]) -> Dict[str, Any]:
        """Reconstruct flags through encoding chain analysis"""
        flags = []
        
        # Group fragments with encoding hints
        encoded_fragments = [f for f in fragments if f.get('encoding_hints')]
        
        if len(encoded_fragments) >= 2:
            # Try combining and decoding
            combined = self._attempt_combination(encoded_fragments)
            if combined:
                decoded_flag = self._apply_encoding_chain(combined['flag'])
                if decoded_flag and self._validate_flag(decoded_flag):
                    combined['flag'] = decoded_flag
                    combined['reconstruction_method'] = 'encoding_chain'
                    flags.append(combined)
        
        return {
            'flags': flags,
            'confidence': 0.9,
            'details': {'encoded_fragments': len(encoded_fragments)}
        }
    
    def _temporal_reconstruction(self, fragments: List[Dict]) -> Dict[str, Any]:
        """Reconstruct flags using temporal correlation"""
        flags = []
        
        # Group by timing
        temporal_groups = self.temporal_correlator.group_by_timing(fragments)
        
        for group in temporal_groups:
            if len(group) >= 2:
                combined = self._attempt_combination(group)
                if combined and self._validate_flag(combined['flag']):
                    combined['reconstruction_method'] = 'temporal_correlation'
                    flags.append(combined)
        
        return {
            'flags': flags,
            'confidence': 0.6,
            'details': {'temporal_groups': len(temporal_groups)}
        }
    
    def _attempt_combination(self, fragments: List[Dict]) -> Optional[Dict[str, Any]]:
        """Attempt to combine fragments into a complete flag"""
        if not fragments:
            return None
            
        # Sort fragments by likelihood of order
        ordered_fragments = self._order_fragments(fragments)
        
        # Combine fragment text
        combined_text = ''.join(f['fragment'] for f in ordered_fragments)
        
        # Calculate confidence
        confidence = sum(f['confidence'] for f in ordered_fragments) / len(ordered_fragments)
        
        return {
            'flag': combined_text,
            'fragments': ordered_fragments,
            'confidence': confidence,
            'packet_indices': [f['packet_index'] for f in ordered_fragments],
            'protocols': list(set(f['protocol'] for f in ordered_fragments))
        }
    
    def _order_fragments(self, fragments: List[Dict]) -> List[Dict]:
        """Order fragments logically for reconstruction"""
        # Priority: opening -> middle -> closing
        opening = [f for f in fragments if f['is_opening']]
        middle = [f for f in fragments if f['is_middle']]
        closing = [f for f in fragments if f['is_closing']]
        
        # Sort each category by packet index
        opening.sort(key=lambda x: x['packet_index'])
        middle.sort(key=lambda x: x['packet_index'])
        closing.sort(key=lambda x: x['packet_index'])
        
        return opening + middle + closing
    
    def _apply_encoding_chain(self, text: str) -> Optional[str]:
        """Apply common encoding chains to reconstruct flag"""
        # Try common encoding combinations
        chains = [
            lambda x: base64.b64decode(x).decode('utf-8', errors='ignore'),
            lambda x: bytes.fromhex(x).decode('utf-8', errors='ignore'),
            lambda x: self._rot13(x),
        ]
        
        for chain in chains:
            try:
                decoded = chain(text)
                if self._validate_flag(decoded):
                    return decoded
            except:
                continue
        
        return text
    
    def _rot13(self, text: str) -> str:
        """Apply ROT13 decoding"""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def _validate_flag(self, flag: str) -> bool:
        """Validate if reconstructed text is a valid flag"""
        flag_patterns = [
            r'^flag\{.+\}$',
            r'^CTF\{.+\}$',
            r'^HTB\{.+\}$',
            r'^[A-Z]{2,8}\{.+\}$'
        ]
        
        return any(re.match(pattern, flag, re.IGNORECASE) for pattern in flag_patterns)
    
    def _deduplicate_flags(self, flags: List[Dict]) -> List[Dict]:
        """Remove duplicate flags keeping highest confidence"""
        seen = {}
        for flag_data in flags:
            flag_text = flag_data['flag']
            if flag_text not in seen or flag_data['confidence'] > seen[flag_text]['confidence']:
                seen[flag_text] = flag_data
        return list(seen.values())

# Factory function for integration
def create_flag_reconstruction_engine() -> FlagReconstructionEngine:
    """Create flag reconstruction engine instance"""
    return FlagReconstructionEngine()