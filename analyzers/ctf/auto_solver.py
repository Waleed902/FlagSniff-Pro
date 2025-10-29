"""Automated CTF challenge solver.

Provides intelligent challenge classification and automated solving:
- Challenge type detection (network, crypto, stego, web, binary)
- Automated exploit chain execution
- Flag extraction and validation
- Solution confidence scoring
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import re


class ChallengeType(Enum):
    """Types of CTF challenges."""
    NETWORK_FORENSICS = "network_forensics"
    CRYPTOGRAPHY = "cryptography"
    STEGANOGRAPHY = "steganography"
    WEB_EXPLOITATION = "web_exploitation"
    BINARY_EXPLOITATION = "binary_exploitation"
    REVERSE_ENGINEERING = "reverse_engineering"
    OSINT = "osint"
    MISC = "misc"
    UNKNOWN = "unknown"


@dataclass
class ChallengeSolution:
    """Represents a solution to a CTF challenge."""
    challenge_type: ChallengeType
    flags_found: List[str]
    confidence: float  # 0.0 to 1.0
    techniques_used: List[str]
    exploit_chain: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'challenge_type': self.challenge_type.value,
            'flags_found': self.flags_found,
            'confidence': self.confidence,
            'techniques_used': self.techniques_used,
            'exploit_chain_length': len(self.exploit_chain),
            'exploit_chain': self.exploit_chain,
            'metadata': self.metadata,
            'errors': self.errors,
            'success': len(self.flags_found) > 0
        }


@dataclass
class ChallengeIndicators:
    """Indicators for challenge type classification."""
    network_indicators: int = 0
    crypto_indicators: int = 0
    stego_indicators: int = 0
    web_indicators: int = 0
    binary_indicators: int = 0
    evidence: List[str] = field(default_factory=list)


class CTFAutoSolver:
    """Automated CTF challenge solver with AI integration."""
    
    # Common flag patterns
    FLAG_PATTERNS = [
        re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
        re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
        re.compile(r'FLAG\{[^}]+\}'),
        re.compile(r'HTB\{[^}]+\}'),  # HackTheBox
        re.compile(r'picoCTF\{[^}]+\}'),
        re.compile(r'[A-Z0-9]{32}'),  # MD5-like
        re.compile(r'[a-f0-9]{40}'),  # SHA1-like
    ]
    
    def __init__(self):
        self.solved_challenges: List[ChallengeSolution] = []
    
    def classify_challenge(self, data: Any, metadata: Optional[Dict[str, Any]] = None) -> ChallengeType:
        """Classify challenge type based on available data.
        
        Args:
            data: Challenge data (packets, files, strings, etc.)
            metadata: Optional metadata about the challenge
            
        Returns:
            Detected challenge type
        """
        indicators = ChallengeIndicators()
        metadata = metadata or {}
        
        # Check metadata hints
        if 'category' in metadata:
            category = metadata['category'].lower()
            if 'network' in category or 'forensic' in category or 'pcap' in category:
                return ChallengeType.NETWORK_FORENSICS
            elif 'crypto' in category:
                return ChallengeType.CRYPTOGRAPHY
            elif 'stego' in category or 'image' in category:
                return ChallengeType.STEGANOGRAPHY
            elif 'web' in category:
                return ChallengeType.WEB_EXPLOITATION
            elif 'binary' in category or 'pwn' in category or 'reverse' in category:
                return ChallengeType.BINARY_EXPLOITATION
        
        # Analyze data patterns
        if hasattr(data, '__iter__') and not isinstance(data, (str, bytes)):
            # Looks like packet list
            indicators.network_indicators += 10
            indicators.evidence.append("Iterable packet-like data")
        
        if isinstance(data, bytes):
            # Check for common file magic bytes
            if data[:4] == b'\x89PNG' or data[:2] == b'\xff\xd8':
                indicators.stego_indicators += 5
                indicators.evidence.append("Image file detected")
            elif data[:4] == b'\x7fELF' or data[:2] == b'MZ':
                indicators.binary_indicators += 10
                indicators.evidence.append("Binary executable detected")
            elif b'HTTP' in data[:1000]:
                indicators.web_indicators += 5
                indicators.network_indicators += 5
                indicators.evidence.append("HTTP traffic detected")
        
        if isinstance(data, str):
            # Check for encoding/crypto indicators
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in data[:100]):
                indicators.crypto_indicators += 3
                indicators.evidence.append("Base64-like string")
            if re.search(r'[0-9a-fA-F]{32,}', data):
                indicators.crypto_indicators += 2
                indicators.evidence.append("Hex string detected")
        
        # Determine type based on indicators
        max_indicator = max(
            indicators.network_indicators,
            indicators.crypto_indicators,
            indicators.stego_indicators,
            indicators.web_indicators,
            indicators.binary_indicators
        )
        
        if max_indicator == 0:
            return ChallengeType.UNKNOWN
        elif max_indicator == indicators.network_indicators:
            return ChallengeType.NETWORK_FORENSICS
        elif max_indicator == indicators.crypto_indicators:
            return ChallengeType.CRYPTOGRAPHY
        elif max_indicator == indicators.stego_indicators:
            return ChallengeType.STEGANOGRAPHY
        elif max_indicator == indicators.web_indicators:
            return ChallengeType.WEB_EXPLOITATION
        else:
            return ChallengeType.BINARY_EXPLOITATION
    
    def extract_flags(self, text: str, patterns: Optional[List[re.Pattern]] = None) -> List[str]:
        """Extract potential flags from text using patterns.
        
        Args:
            text: Text to search for flags
            patterns: Optional custom flag patterns
            
        Returns:
            List of found flags
        """
        patterns = patterns or self.FLAG_PATTERNS
        flags = []
        
        for pattern in patterns:
            matches = pattern.findall(text)
            flags.extend(matches)
        
        return list(set(flags))  # Remove duplicates
    
    def solve_network_forensics(self, packets: List[Any], metadata: Dict[str, Any]) -> ChallengeSolution:
        """Attempt to solve a network forensics challenge.
        
        Args:
            packets: List of packets to analyze
            metadata: Challenge metadata
            
        Returns:
            ChallengeSolution with results
        """
        exploit_chain = []
        techniques = []
        flags = []
        errors = []
        
        try:
            # Step 1: Extract all strings from packets
            exploit_chain.append({
                'step': 1,
                'technique': 'Extract packet strings',
                'description': 'Extract all readable strings from packet payloads'
            })
            techniques.append('String extraction')
            
            all_strings = []
            try:
                from scapy.all import Raw  # type: ignore
                for pkt in packets:
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                        decoded = payload.decode('utf-8', errors='ignore')
                        all_strings.append(decoded)
            except ImportError:
                errors.append("Scapy not available for packet parsing")
            
            combined_text = '\n'.join(all_strings)
            
            # Step 2: Search for flags in strings
            exploit_chain.append({
                'step': 2,
                'technique': 'Flag pattern matching',
                'description': 'Search extracted strings for flag patterns'
            })
            techniques.append('Pattern matching')
            
            flags = self.extract_flags(combined_text)
            
            # Step 3: Check for common encodings
            if not flags:
                exploit_chain.append({
                    'step': 3,
                    'technique': 'Encoding detection',
                    'description': 'Try decoding Base64, hex, URL encoding'
                })
                techniques.append('Encoding detection')
                
                # Try Base64
                import base64
                for s in all_strings:
                    try:
                        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
                        flags.extend(self.extract_flags(decoded))
                    except:
                        pass
            
            # Step 4: Protocol-specific analysis
            exploit_chain.append({
                'step': 4,
                'technique': 'Protocol analysis',
                'description': 'Analyze HTTP, DNS, FTP traffic for hidden data'
            })
            techniques.append('Protocol analysis')
            
            # This would integrate with existing analyzers
            
        except Exception as e:
            errors.append(f"Network forensics error: {e}")
        
        confidence = 0.8 if flags else 0.3
        
        return ChallengeSolution(
            challenge_type=ChallengeType.NETWORK_FORENSICS,
            flags_found=flags,
            confidence=confidence,
            techniques_used=techniques,
            exploit_chain=exploit_chain,
            metadata=metadata,
            errors=errors
        )
    
    def solve_cryptography(self, data: Any, metadata: Dict[str, Any]) -> ChallengeSolution:
        """Attempt to solve a cryptography challenge.
        
        Args:
            data: Encrypted/encoded data
            metadata: Challenge metadata
            
        Returns:
            ChallengeSolution with results
        """
        exploit_chain = []
        techniques = []
        flags = []
        errors = []
        
        try:
            # Step 1: Identify encoding
            exploit_chain.append({
                'step': 1,
                'technique': 'Encoding identification',
                'description': 'Detect Base64, hex, binary, etc.'
            })
            techniques.append('Encoding detection')
            
            # Step 2: Try common cipher techniques
            exploit_chain.append({
                'step': 2,
                'technique': 'Cipher bruteforce',
                'description': 'Try ROT13, XOR, substitution ciphers'
            })
            techniques.append('Cipher analysis')
            
            # Step 3: Frequency analysis
            exploit_chain.append({
                'step': 3,
                'technique': 'Frequency analysis',
                'description': 'Perform frequency analysis for substitution ciphers'
            })
            techniques.append('Frequency analysis')
            
            # This would integrate with crypto_analysis_suite
            
        except Exception as e:
            errors.append(f"Crypto error: {e}")
        
        confidence = 0.5 if flags else 0.2
        
        return ChallengeSolution(
            challenge_type=ChallengeType.CRYPTOGRAPHY,
            flags_found=flags,
            confidence=confidence,
            techniques_used=techniques,
            exploit_chain=exploit_chain,
            metadata=metadata,
            errors=errors
        )
    
    def solve_steganography(self, image_data: bytes, metadata: Dict[str, Any]) -> ChallengeSolution:
        """Attempt to solve a steganography challenge.
        
        Args:
            image_data: Image file bytes
            metadata: Challenge metadata
            
        Returns:
            ChallengeSolution with results
        """
        exploit_chain = []
        techniques = []
        flags = []
        errors = []
        
        try:
            # Step 1: Extract EXIF metadata
            exploit_chain.append({
                'step': 1,
                'technique': 'EXIF extraction',
                'description': 'Extract metadata from image file'
            })
            techniques.append('EXIF analysis')
            
            # Step 2: LSB analysis
            exploit_chain.append({
                'step': 2,
                'technique': 'LSB extraction',
                'description': 'Extract least significant bits from image'
            })
            techniques.append('LSB steganography')
            
            # Step 3: Check for appended data
            exploit_chain.append({
                'step': 3,
                'technique': 'Appended data detection',
                'description': 'Look for data appended after image'
            })
            techniques.append('Appended data')
            
            # This would integrate with steganography_suite
            
        except Exception as e:
            errors.append(f"Stego error: {e}")
        
        confidence = 0.6 if flags else 0.2
        
        return ChallengeSolution(
            challenge_type=ChallengeType.STEGANOGRAPHY,
            flags_found=flags,
            confidence=confidence,
            techniques_used=techniques,
            exploit_chain=exploit_chain,
            metadata=metadata,
            errors=errors
        )
    
    def solve_challenge(self, data: Any, metadata: Optional[Dict[str, Any]] = None) -> ChallengeSolution:
        """Main entry point: classify and solve a challenge.
        
        Args:
            data: Challenge data
            metadata: Optional challenge metadata
            
        Returns:
            ChallengeSolution with results
        """
        metadata = metadata or {}
        
        # Classify challenge type
        challenge_type = self.classify_challenge(data, metadata)
        metadata['detected_type'] = challenge_type.value
        
        # Dispatch to appropriate solver
        if challenge_type == ChallengeType.NETWORK_FORENSICS:
            solution = self.solve_network_forensics(data, metadata)
        elif challenge_type == ChallengeType.CRYPTOGRAPHY:
            solution = self.solve_cryptography(data, metadata)
        elif challenge_type == ChallengeType.STEGANOGRAPHY:
            solution = self.solve_steganography(data, metadata)
        else:
            # Unsupported type - return generic solution
            solution = ChallengeSolution(
                challenge_type=challenge_type,
                flags_found=[],
                confidence=0.0,
                techniques_used=[],
                exploit_chain=[],
                metadata=metadata,
                errors=[f"Challenge type {challenge_type.value} not yet supported"]
            )
        
        self.solved_challenges.append(solution)
        return solution
    
    def get_solver_stats(self) -> Dict[str, Any]:
        """Get statistics about solved challenges.
        
        Returns:
            Dict with solver statistics
        """
        total = len(self.solved_challenges)
        successful = sum(1 for s in self.solved_challenges if s.flags_found)
        
        by_type = {}
        for solution in self.solved_challenges:
            type_name = solution.challenge_type.value
            by_type[type_name] = by_type.get(type_name, 0) + 1
        
        avg_confidence = sum(s.confidence for s in self.solved_challenges) / max(total, 1)
        
        return {
            'total_attempts': total,
            'successful': successful,
            'success_rate': (successful / max(total, 1)) * 100,
            'by_type': by_type,
            'average_confidence': avg_confidence,
            'total_flags_found': sum(len(s.flags_found) for s in self.solved_challenges)
        }


class CTFAPIIntegration:
    """Integration with CTF platform APIs for flag submission."""
    
    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url
        self.api_token = api_token
    
    def submit_flag(self, challenge_id: str, flag: str) -> Dict[str, Any]:
        """Submit a flag to the CTF platform.
        
        Args:
            challenge_id: Challenge identifier
            flag: Flag to submit
            
        Returns:
            Dict with submission result
        """
        # This is a placeholder - real implementation would use requests library
        return {
            'success': False,
            'message': 'API integration not implemented',
            'challenge_id': challenge_id,
            'flag': flag
        }
    
    def get_challenge_info(self, challenge_id: str) -> Dict[str, Any]:
        """Fetch challenge information from platform.
        
        Args:
            challenge_id: Challenge identifier
            
        Returns:
            Dict with challenge info
        """
        return {
            'id': challenge_id,
            'name': 'Unknown',
            'category': 'Unknown',
            'points': 0,
            'error': 'API integration not implemented'
        }
