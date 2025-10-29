"""
CTF-Specific UI Enhancements
Provides difficulty assessment, progressive hint system, and adaptive filtering
"""

import json
import time
import random
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict

class CTFUIEnhancements:
    """Enhanced UI features for CTF analysis"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.user_progress = {}
        self.hint_system = HintSystem()
        self.difficulty_assessor = DifficultyAssessor()
        self.adaptive_filter = AdaptiveFilter()
        
    def assess_challenge_difficulty(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive difficulty assessment for CTF challenges"""
        return self.difficulty_assessor.assess_difficulty(analysis_results)
    
    def get_progressive_hints(self, challenge_context: Dict[str, Any], user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Provide progressive hints based on user progress"""
        return self.hint_system.generate_hints(challenge_context, user_progress)
    
    def apply_adaptive_filtering(self, findings: List[Dict], user_context: Dict[str, Any]) -> List[Dict]:
        """Apply adaptive filtering to reduce false positives"""
        return self.adaptive_filter.filter_findings(findings, user_context)
    
    def track_user_progress(self, action: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Track user progress for hint system and difficulty adjustment"""
        timestamp = datetime.now().isoformat()
        
        if 'progress_log' not in self.user_progress:
            self.user_progress['progress_log'] = []
            
        self.user_progress['progress_log'].append({
            'timestamp': timestamp,
            'action': action,
            'context': context
        })
        
        # Update progress metrics
        self._update_progress_metrics()
        
        return self.user_progress
    
    def _update_progress_metrics(self):
        """Update internal progress metrics"""
        if not self.user_progress.get('progress_log'):
            return
            
        # Calculate time spent
        start_time = datetime.fromisoformat(self.user_progress['progress_log'][0]['timestamp'])
        current_time = datetime.now()
        self.user_progress['time_spent'] = (current_time - start_time).total_seconds() / 60  # minutes
        
        # Count actions
        actions = [log['action'] for log in self.user_progress['progress_log']]
        self.user_progress['action_counts'] = {
            action: actions.count(action) for action in set(actions)
        }
        
        # Determine progress stage
        self.user_progress['stage'] = self._determine_progress_stage()
    
    def _determine_progress_stage(self) -> str:
        """Determine current progress stage"""
        time_spent = self.user_progress.get('time_spent', 0)
        action_counts = self.user_progress.get('action_counts', {})
        
        if time_spent < 5:
            return 'initial_exploration'
        elif time_spent < 15 and action_counts.get('analyze_packet', 0) > 5:
            return 'deep_analysis'
        elif action_counts.get('test_exploit', 0) > 0:
            return 'exploitation_phase'
        elif action_counts.get('flag_found', 0) > 0:
            return 'completion'
        else:
            return 'investigation'

class DifficultyAssessor:
    """Assesses CTF challenge difficulty using multiple factors"""
    
    def __init__(self):
        self.scoring_weights = {
            'vulnerability_complexity': 0.25,
            'exploitation_chain_length': 0.20,
            'encoding_layers': 0.15,
            'steganography_depth': 0.15,
            'cryptographic_complexity': 0.15,
            'network_analysis_required': 0.10
        }
        
    def assess_difficulty(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive difficulty assessment"""
        assessment = {
            'overall_difficulty': 'Medium',
            'difficulty_score': 50,
            'factors': {},
            'detailed_breakdown': {},
            'estimated_solve_time': '30-60 minutes',
            'skill_level_required': 'Intermediate',
            'recommended_approach': [],
            'challenge_characteristics': []
        }
        
        try:
            total_score = 0
            factor_scores = {}
            
            # Vulnerability complexity assessment
            vuln_score = self._assess_vulnerability_complexity(analysis_results)
            factor_scores['vulnerability_complexity'] = vuln_score
            total_score += vuln_score * self.scoring_weights['vulnerability_complexity']
            
            # Exploitation chain analysis
            chain_score = self._assess_exploitation_chains(analysis_results)
            factor_scores['exploitation_chain_length'] = chain_score
            total_score += chain_score * self.scoring_weights['exploitation_chain_length']
            
            # Encoding complexity
            encoding_score = self._assess_encoding_complexity(analysis_results)
            factor_scores['encoding_layers'] = encoding_score
            total_score += encoding_score * self.scoring_weights['encoding_layers']
            
            # Steganography assessment
            stego_score = self._assess_steganography_complexity(analysis_results)
            factor_scores['steganography_depth'] = stego_score
            total_score += stego_score * self.scoring_weights['steganography_depth']
            
            # Cryptographic complexity
            crypto_score = self._assess_cryptographic_complexity(analysis_results)
            factor_scores['cryptographic_complexity'] = crypto_score
            total_score += crypto_score * self.scoring_weights['cryptographic_complexity']
            
            # Network analysis requirements
            network_score = self._assess_network_complexity(analysis_results)
            factor_scores['network_analysis_required'] = network_score
            total_score += network_score * self.scoring_weights['network_analysis_required']
            
            # Normalize score
            final_score = int(total_score)
            assessment['difficulty_score'] = min(100, max(0, final_score))
            assessment['factors'] = factor_scores
            
            # Determine overall difficulty rating
            if final_score < 25:
                assessment['overall_difficulty'] = 'Beginner'
                assessment['skill_level_required'] = 'Beginner'
                assessment['estimated_solve_time'] = '10-30 minutes'
            elif final_score < 50:
                assessment['overall_difficulty'] = 'Easy'
                assessment['skill_level_required'] = 'Novice'
                assessment['estimated_solve_time'] = '20-45 minutes'
            elif final_score < 70:
                assessment['overall_difficulty'] = 'Medium'
                assessment['skill_level_required'] = 'Intermediate'
                assessment['estimated_solve_time'] = '30-90 minutes'
            elif final_score < 85:
                assessment['overall_difficulty'] = 'Hard'
                assessment['skill_level_required'] = 'Advanced'
                assessment['estimated_solve_time'] = '1-3 hours'
            else:
                assessment['overall_difficulty'] = 'Expert'
                assessment['skill_level_required'] = 'Expert'
                assessment['estimated_solve_time'] = '2-6 hours'
                
            # Generate recommendations
            assessment['recommended_approach'] = self._generate_approach_recommendations(factor_scores)
            assessment['challenge_characteristics'] = self._identify_challenge_characteristics(analysis_results)
            assessment['detailed_breakdown'] = self._create_detailed_breakdown(factor_scores)
            
        except Exception as e:
            assessment['error'] = str(e)
            
        return assessment
    
    def _assess_vulnerability_complexity(self, analysis_results: Dict[str, Any]) -> int:
        """Assess vulnerability complexity"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return 20
            
        complexity_scores = {
            'sql_injection': 60,
            'xss': 40,
            'command_injection': 80,
            'buffer_overflow': 90,
            'auth_bypass': 50,
            'path_traversal': 35,
            'crypto_weakness': 85
        }
        
        max_score = 0
        total_vulns = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            score = complexity_scores.get(vuln_type, 50)
            max_score = max(max_score, score)
            
        # Bonus for multiple vulnerabilities
        if total_vulns > 3:
            max_score += 15
        elif total_vulns > 1:
            max_score += 5
            
        return min(100, max_score)
    
    def _assess_exploitation_chains(self, analysis_results: Dict[str, Any]) -> int:
        """Assess exploitation chain complexity"""
        opportunities = analysis_results.get('exploitation_opportunities', [])
        
        chain_lengths = []
        for opp in opportunities:
            if opp.get('type') == 'chained_exploitation':
                chain_length = len(opp.get('vulnerability_chain', []))
                chain_lengths.append(chain_length)
                
        if not chain_lengths:
            return 30
            
        max_chain = max(chain_lengths)
        if max_chain >= 4:
            return 90
        elif max_chain >= 3:
            return 70
        elif max_chain >= 2:
            return 50
        else:
            return 30
    
    def _assess_encoding_complexity(self, analysis_results: Dict[str, Any]) -> int:
        """Assess encoding complexity"""
        encoding_chains = analysis_results.get('encoding_chains', [])
        
        if not encoding_chains:
            return 20
            
        max_depth = 0
        for chain in encoding_chains:
            depth = len(chain.get('encoding_chain', []))
            max_depth = max(max_depth, depth)
            
        if max_depth >= 5:
            return 85
        elif max_depth >= 3:
            return 65
        elif max_depth >= 2:
            return 45
        else:
            return 25
    
    def _assess_steganography_complexity(self, analysis_results: Dict[str, Any]) -> int:
        """Assess steganography complexity"""
        stego_findings = []
        
        # Check different steganography types
        if 'timing_patterns' in analysis_results:
            stego_findings.extend(analysis_results['timing_patterns'])
        if 'size_patterns' in analysis_results:
            stego_findings.extend(analysis_results['size_patterns'])
        if 'covert_channels' in analysis_results:
            stego_findings.extend(analysis_results['covert_channels'])
            
        if not stego_findings:
            return 15
            
        complexity_map = {
            'timing_binary': 70,
            'timing_morse': 60,
            'size_binary': 65,
            'lsb_steganography': 80,
            'frequency_anomaly': 75,
            'dns_tunneling': 85
        }
        
        max_complexity = 0
        for finding in stego_findings:
            finding_type = finding.get('type', '')
            complexity = complexity_map.get(finding_type, 50)
            max_complexity = max(max_complexity, complexity)
            
        return min(100, max_complexity)
    
    def _assess_cryptographic_complexity(self, analysis_results: Dict[str, Any]) -> int:
        """Assess cryptographic complexity"""
        crypto_indicators = 0
        
        # Look for cryptographic patterns
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if 'crypto' in vuln.get('type', '').lower():
                crypto_indicators += 1
                
        # Check for encoding chains with crypto elements
        encoding_chains = analysis_results.get('encoding_chains', [])
        for chain in encoding_chains:
            encodings = chain.get('encoding_chain', [])
            if any(enc in ['jwt', 'base64', 'custom'] for enc in encodings):
                crypto_indicators += 1
                
        if crypto_indicators >= 3:
            return 85
        elif crypto_indicators >= 2:
            return 65
        elif crypto_indicators >= 1:
            return 45
        else:
            return 20
    
    def _assess_network_complexity(self, analysis_results: Dict[str, Any]) -> int:
        """Assess network analysis complexity"""
        total_packets = analysis_results.get('metadata', {}).get('total_packets', 0)
        protocols_found = len(set())  # Would need actual protocol data
        
        if total_packets > 1000:
            return 80
        elif total_packets > 500:
            return 60
        elif total_packets > 100:
            return 40
        else:
            return 25
    
    def _generate_approach_recommendations(self, factor_scores: Dict[str, int]) -> List[str]:
        """Generate approach recommendations based on complexity factors"""
        recommendations = []
        
        if factor_scores.get('vulnerability_complexity', 0) > 70:
            recommendations.append('Focus on advanced exploitation techniques')
            recommendations.append('Consider using specialized security tools')
            
        if factor_scores.get('encoding_layers', 0) > 60:
            recommendations.append('Systematic approach to decoding layers')
            recommendations.append('Use automated decoding tools where possible')
            
        if factor_scores.get('steganography_depth', 0) > 70:
            recommendations.append('Analyze packet timing and size patterns')
            recommendations.append('Look for covert communication channels')
            
        if factor_scores.get('cryptographic_complexity', 0) > 60:
            recommendations.append('Strong cryptographic analysis skills required')
            recommendations.append('Consider frequency analysis and known plaintext attacks')
            
        if not recommendations:
            recommendations.append('Standard CTF analysis approach should suffice')
            recommendations.append('Focus on basic vulnerability identification')
            
        return recommendations
    
    def _identify_challenge_characteristics(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Identify key challenge characteristics"""
        characteristics = []
        
        if analysis_results.get('vulnerabilities'):
            characteristics.append('Web application security')
            
        if analysis_results.get('encoding_chains'):
            characteristics.append('Multi-layer encoding')
            
        if any(key in analysis_results for key in ['timing_patterns', 'size_patterns', 'covert_channels']):
            characteristics.append('Network steganography')
            
        if analysis_results.get('exploitation_opportunities'):
            characteristics.append('Active exploitation required')
            
        return characteristics or ['General forensics analysis']
    
    def _create_detailed_breakdown(self, factor_scores: Dict[str, int]) -> Dict[str, Any]:
        """Create detailed breakdown of difficulty factors"""
        breakdown = {}
        
        for factor, score in factor_scores.items():
            if score < 30:
                level = 'Low'
            elif score < 60:
                level = 'Medium'
            elif score < 80:
                level = 'High'
            else:
                level = 'Very High'
                
            breakdown[factor] = {
                'score': score,
                'level': level,
                'contribution': f"{score * self.scoring_weights.get(factor, 0):.1f} points"
            }
            
        return breakdown

class HintSystem:
    """Progressive hint system for CTF challenges"""
    
    def __init__(self):
        self.hint_categories = {
            'initial_exploration': [
                'Start by examining the packet capture file structure',
                'Look for unusual protocols or traffic patterns',
                'Check for obvious flags in plaintext first'
            ],
            'deep_analysis': [
                'Focus on packets with unusual sizes or timing',
                'Examine HTTP requests and responses carefully',
                'Look for base64 or hex-encoded data'
            ],
            'exploitation_phase': [
                'Try common injection techniques if web vulnerabilities are found',
                'Consider using automated tools for complex exploits',
                'Check for authentication bypass opportunities'
            ],
            'stuck_hints': [
                'Review the challenge description for additional context',
                'Consider steganography in packet timing or sizes',
                'Look for multi-layer encoding schemes'
            ]
        }
        
    def generate_hints(self, challenge_context: Dict[str, Any], user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Generate progressive hints based on user progress"""
        hint_response = {
            'available_hints': [],
            'current_hint': '',
            'hint_level': 1,
            'progress_based_hints': [],
            'contextual_hints': []
        }
        
        try:
            # Determine hint level based on progress
            time_spent = user_progress.get('time_spent', 0)
            stage = user_progress.get('stage', 'initial_exploration')
            
            if time_spent < 10:
                hint_level = 1
            elif time_spent < 30:
                hint_level = 2
            elif time_spent < 60:
                hint_level = 3
            else:
                hint_level = 4
                
            hint_response['hint_level'] = hint_level
            
            # Get stage-appropriate hints
            stage_hints = self.hint_categories.get(stage, self.hint_categories['initial_exploration'])
            hint_response['available_hints'] = stage_hints[:hint_level]
            
            if hint_response['available_hints']:
                hint_response['current_hint'] = hint_response['available_hints'][-1]
                
            # Generate progress-based hints
            hint_response['progress_based_hints'] = self._generate_progress_hints(user_progress)
            
            # Generate contextual hints based on analysis results
            hint_response['contextual_hints'] = self._generate_contextual_hints(challenge_context)
            
        except Exception as e:
            hint_response['error'] = str(e)
            
        return hint_response
    
    def _generate_progress_hints(self, user_progress: Dict[str, Any]) -> List[str]:
        """Generate hints based on specific user progress patterns"""
        hints = []
        action_counts = user_progress.get('action_counts', {})
        
        if action_counts.get('analyze_packet', 0) > 20 and action_counts.get('test_exploit', 0) == 0:
            hints.append('You\'ve analyzed many packets. Try focusing on exploitation now.')
            
        if action_counts.get('decode_attempt', 0) > 10:
            hints.append('Multiple decode attempts detected. Consider chain decoding.')
            
        if user_progress.get('time_spent', 0) > 45:
            hints.append('Consider stepping back and reviewing the overall traffic flow.')
            
        return hints
    
    def _generate_contextual_hints(self, challenge_context: Dict[str, Any]) -> List[str]:
        """Generate hints based on challenge analysis context"""
        hints = []
        
        if challenge_context.get('vulnerabilities'):
            vuln_types = [v.get('type') for v in challenge_context['vulnerabilities']]
            if 'sql_injection' in vuln_types:
                hints.append('SQL injection detected. Try UNION-based attacks.')
            if 'xss' in vuln_types:
                hints.append('XSS vulnerability found. Look for session hijacking opportunities.')
                
        if challenge_context.get('encoding_chains'):
            max_depth = max([len(c.get('encoding_chain', [])) for c in challenge_context['encoding_chains']], default=0)
            if max_depth > 2:
                hints.append(f'Multi-layer encoding detected ({max_depth} layers). Decode systematically.')
                
        return hints

class AdaptiveFilter:
    """Adaptive filtering system to reduce false positives"""
    
    def __init__(self):
        self.filter_rules = {
            'confidence_threshold': 70,
            'context_weights': {
                'web': 1.2,
                'network': 1.0,
                'crypto': 1.3,
                'forensics': 1.1
            }
        }
        
    def filter_findings(self, findings: List[Dict], user_context: Dict[str, Any]) -> List[Dict]:
        """Apply adaptive filtering based on context and user behavior"""
        filtered_findings = []
        
        try:
            challenge_type = user_context.get('challenge_type', 'forensics')
            user_skill_level = user_context.get('skill_level', 'intermediate')
            
            for finding in findings:
                # Apply confidence threshold filtering
                confidence = finding.get('confidence', 0)
                adjusted_confidence = self._adjust_confidence_for_context(confidence, challenge_type, finding)
                
                # Apply skill level adjustment
                if user_skill_level == 'beginner':
                    adjusted_confidence += 5  # Be more lenient for beginners
                elif user_skill_level == 'expert':
                    adjusted_confidence -= 5  # Be more strict for experts
                    
                # Check if finding passes filter
                if adjusted_confidence >= self.filter_rules['confidence_threshold']:
                    finding['filtered_confidence'] = adjusted_confidence
                    finding['filter_applied'] = True
                    filtered_findings.append(finding)
                    
        except Exception as e:
            # If filtering fails, return original findings
            return findings
            
        return filtered_findings
    
    def _adjust_confidence_for_context(self, confidence: int, challenge_type: str, finding: Dict) -> int:
        """Adjust confidence score based on challenge context"""
        weight = self.filter_rules['context_weights'].get(challenge_type, 1.0)
        
        # Type-specific adjustments
        finding_type = finding.get('type', '')
        
        if challenge_type == 'web' and finding_type in ['sql_injection', 'xss', 'auth_bypass']:
            weight += 0.1
        elif challenge_type == 'crypto' and 'crypto' in finding_type:
            weight += 0.2
        elif challenge_type == 'network' and finding_type in ['covert_channels', 'protocol_anomaly']:
            weight += 0.15
            
        return int(confidence * weight)