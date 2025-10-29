"""
Tactical Analysis Modes: Red Team (Offensive) and Blue Team (Defensive)
Provides specialized analysis perspectives for different security teams
"""

import re
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum

class AnalysisMode(Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team" 
    PURPLE_TEAM = "purple_team"

@dataclass
class TacticalFinding:
    """Represents a tactical finding with team-specific context"""
    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    recommendations: List[str]
    tools_suggested: List[str]
    confidence: float

class RedTeamAnalyzer:
    """Red Team (Offensive) perspective analyzer"""
    
    def __init__(self):
        self.attack_vectors = {
            'credential_exposure': self._analyze_credential_exposure,
            'service_enumeration': self._analyze_service_enumeration,
            'privilege_escalation': self._analyze_privilege_escalation
        }
        
    def analyze_from_red_perspective(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze findings from red team perspective"""
        
        red_analysis = {
            'attack_surface': {},
            'exploitation_opportunities': [],
            'prioritized_targets': [],
            'tools_and_techniques': {},
            'executive_summary': ''
        }
        
        # Analyze attack vectors
        for vector_name, analyzer_func in self.attack_vectors.items():
            try:
                vector_results = analyzer_func(findings, packets_data)
                if vector_results:
                    red_analysis['attack_surface'][vector_name] = vector_results
            except Exception:
                continue
        
        # Generate exploitation opportunities
        red_analysis['exploitation_opportunities'] = self._generate_exploitation_opportunities(findings)
        red_analysis['prioritized_targets'] = self._prioritize_targets(findings)
        red_analysis['tools_and_techniques'] = self._suggest_attack_tools(findings)
        
        return red_analysis
    
    def _analyze_credential_exposure(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze credential exposure opportunities"""
        
        credential_analysis = {
            'exposed_credentials': [],
            'attack_recommendations': []
        }
        
        for finding in findings:
            if finding.get('type') in ['credential', 'token']:
                data = finding.get('data', '')
                
                if any(keyword in data.lower() for keyword in ['username', 'password', 'admin', 'root']):
                    credential_analysis['exposed_credentials'].append({
                        'credential': data,
                        'protocol': finding.get('protocol', 'Unknown'),
                        'exploitation_difficulty': 'Low',
                        'attack_vectors': ['Password spraying', 'Credential stuffing', 'Direct login']
                    })
        
        if credential_analysis['exposed_credentials']:
            credential_analysis['attack_recommendations'] = [
                "Attempt credential reuse across multiple services",
                "Use tools like Hydra for password spraying",
                "Check for privilege escalation opportunities"
            ]
        
        return credential_analysis
    
    def _analyze_service_enumeration(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze service enumeration opportunities"""
        
        enumeration_analysis = {
            'discovered_services': {},
            'enumeration_targets': []
        }
        
        services_found = defaultdict(list)
        for finding in findings:
            protocol = finding.get('protocol', 'Unknown')
            if protocol != 'Unknown':
                services_found[protocol].append(finding)
        
        # Generate enumeration recommendations
        for protocol, instances in services_found.items():
            if protocol == 'HTTP':
                enumeration_analysis['enumeration_targets'].append({
                    'service': 'HTTP',
                    'tools': ['dirb', 'gobuster', 'nikto'],
                    'vectors': ['Directory traversal', 'File inclusion', 'Web shells']
                })
            elif protocol == 'FTP':
                enumeration_analysis['enumeration_targets'].append({
                    'service': 'FTP',
                    'tools': ['nmap ftp scripts', 'hydra'],
                    'vectors': ['Anonymous access', 'Brute force']
                })
        
        enumeration_analysis['discovered_services'] = dict(services_found)
        return enumeration_analysis
    
    def _analyze_privilege_escalation(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze privilege escalation opportunities"""
        
        privesc_analysis = {
            'escalation_vectors': [],
            'vulnerable_services': []
        }
        
        for finding in findings:
            data = finding.get('data', '').lower()
            
            if any(keyword in data for keyword in ['sudo', 'root', 'administrator']):
                privesc_analysis['escalation_vectors'].append({
                    'vector': 'Administrative access detected',
                    'evidence': finding.get('data', ''),
                    'tools': ['sudo -l', 'whoami', 'id']
                })
        
        return privesc_analysis
    
    def _generate_exploitation_opportunities(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized exploitation opportunities"""
        
        opportunities = []
        
        credential_findings = [f for f in findings if f.get('type') in ['credential', 'token']]
        if credential_findings:
            opportunities.append({
                'priority': 'Critical',
                'opportunity': 'Credential Exploitation',
                'description': f'Found {len(credential_findings)} credential findings',
                'steps': [
                    'Validate discovered credentials',
                    'Attempt credential reuse',
                    'Escalate privileges'
                ],
                'tools': ['hydra', 'crackmapexec'],
                'success_probability': 'High'
            })
        
        return opportunities
    
    def _prioritize_targets(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize targets based on exploitation potential"""
        
        targets = []
        host_scores = defaultdict(int)
        
        for finding in findings:
            dst = finding.get('dst', '')
            if dst:
                if finding.get('type') == 'credential':
                    host_scores[dst] += 10
                elif finding.get('type') == 'flag':
                    host_scores[dst] += 8
                else:
                    host_scores[dst] += 1
        
        sorted_targets = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)
        
        for i, (host, score) in enumerate(sorted_targets[:3]):
            targets.append({
                'rank': i + 1,
                'target': host,
                'score': score,
                'priority': 'Critical' if score >= 10 else 'High'
            })
        
        return targets
    
    def _suggest_attack_tools(self, findings: List[Dict]) -> Dict[str, List[str]]:
        """Suggest appropriate attack tools"""
        
        tools = {
            'reconnaissance': ['nmap', 'masscan'],
            'exploitation': ['metasploit', 'searchsploit'],
            'credential_attacks': ['hydra', 'crackmapexec']
        }
        
        protocols = set(f.get('protocol', '') for f in findings)
        
        if 'HTTP' in protocols:
            tools['web_testing'] = ['burp_suite', 'sqlmap', 'dirb']
        if 'FTP' in protocols:
            tools['ftp_testing'] = ['hydra', 'ncrack']
        
        return tools

class BlueTeamAnalyzer:
    """Blue Team (Defensive) perspective analyzer"""
    
    def __init__(self):
        self.defensive_checks = {
            'security_misconfigurations': self._analyze_misconfigurations,
            'monitoring_gaps': self._analyze_monitoring_gaps,
            'hardening_opportunities': self._analyze_hardening
        }
    
    def analyze_from_blue_perspective(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze from blue team perspective"""
        
        blue_analysis = {
            'security_posture': {},
            'hardening_recommendations': [],
            'monitoring_improvements': [],
            'incident_indicators': []
        }
        
        # Run defensive checks
        for check_name, check_func in self.defensive_checks.items():
            try:
                results = check_func(findings, packets_data)
                if results:
                    blue_analysis['security_posture'][check_name] = results
            except Exception:
                continue
        
        blue_analysis['hardening_recommendations'] = self._generate_hardening_recommendations(findings)
        blue_analysis['monitoring_improvements'] = self._generate_monitoring_recommendations(findings)
        
        return blue_analysis
    
    def _analyze_misconfigurations(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze security misconfigurations"""
        
        misconfigs = {
            'cleartext_protocols': [],
            'weak_authentication': []
        }
        
        for finding in findings:
            protocol = finding.get('protocol', '').upper()
            data = finding.get('data', '')
            
            if protocol in ['FTP', 'TELNET', 'HTTP'] and 'password' in data.lower():
                misconfigs['cleartext_protocols'].append({
                    'protocol': protocol,
                    'severity': 'High',
                    'recommendation': f'Replace {protocol} with secure alternatives'
                })
        
        return misconfigs
    
    def _analyze_monitoring_gaps(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze monitoring gaps"""
        
        monitoring = {
            'logging_coverage': {},
            'detection_gaps': []
        }
        
        protocols = set(f.get('protocol', '') for f in findings)
        
        for protocol in protocols:
            if protocol == 'HTTP':
                monitoring['logging_coverage']['web_traffic'] = {
                    'recommendation': 'Implement WAF logging',
                    'tools': ['ModSecurity', 'Cloudflare']
                }
        
        return monitoring
    
    def _analyze_hardening(self, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Analyze hardening opportunities"""
        
        hardening = {
            'protocol_hardening': [],
            'encryption_recommendations': []
        }
        
        protocols = set(f.get('protocol', '') for f in findings)
        
        if 'FTP' in protocols:
            hardening['protocol_hardening'].append({
                'service': 'FTP',
                'recommendation': 'Replace with SFTP',
                'priority': 'High'
            })
        
        return hardening
    
    def _generate_hardening_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate hardening recommendations"""
        
        recommendations = []
        protocols = set(f.get('protocol', '') for f in findings)
        
        if 'HTTP' in protocols:
            recommendations.append({
                'category': 'Encryption',
                'recommendation': 'Implement HTTPS with TLS 1.3',
                'priority': 'High'
            })
        
        if any(f.get('type') == 'credential' for f in findings):
            recommendations.append({
                'category': 'Authentication',
                'recommendation': 'Implement multi-factor authentication',
                'priority': 'Critical'
            })
        
        return recommendations
    
    def _generate_monitoring_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate monitoring recommendations"""
        
        monitoring = []
        
        if any(f.get('type') == 'credential' for f in findings):
            monitoring.append({
                'category': 'Credential Monitoring',
                'recommendation': 'Implement DLP for credential patterns',
                'tools': ['Splunk', 'ELK Stack']
            })
        
        return monitoring

class TacticalAnalysisEngine:
    """Main engine for tactical analysis modes"""
    
    def __init__(self):
        self.red_team_analyzer = RedTeamAnalyzer()
        self.blue_team_analyzer = BlueTeamAnalyzer()
    
    def analyze_with_mode(self, mode: AnalysisMode, findings: List[Dict], packets_data: List[Dict]) -> Dict[str, Any]:
        """Perform analysis with specified tactical mode"""
        
        if mode == AnalysisMode.RED_TEAM:
            return self.red_team_analyzer.analyze_from_red_perspective(findings, packets_data)
        elif mode == AnalysisMode.BLUE_TEAM:
            return self.blue_team_analyzer.analyze_from_blue_perspective(findings, packets_data)
        elif mode == AnalysisMode.PURPLE_TEAM:
            # Combined analysis
            red_results = self.red_team_analyzer.analyze_from_red_perspective(findings, packets_data)
            blue_results = self.blue_team_analyzer.analyze_from_blue_perspective(findings, packets_data)
            
            return {
                'red_team_perspective': red_results,
                'blue_team_perspective': blue_results,
                'combined_recommendations': self._generate_purple_team_recommendations(red_results, blue_results)
            }
        
        return {}
    
    def _generate_purple_team_recommendations(self, red_results: Dict, blue_results: Dict) -> List[Dict]:
        """Generate combined purple team recommendations"""
        
        recommendations = []
        
        # Combine high-priority items from both perspectives
        red_opportunities = red_results.get('exploitation_opportunities', [])
        blue_hardening = blue_results.get('hardening_recommendations', [])
        
        for opportunity in red_opportunities:
            if opportunity.get('priority') == 'Critical':
                recommendations.append({
                    'type': 'Critical Vulnerability',
                    'red_perspective': opportunity['description'],
                    'blue_response': 'Immediate patching and monitoring required',
                    'priority': 'Critical'
                })
        
        return recommendations

# Factory function
def create_tactical_analyzer() -> TacticalAnalysisEngine:
    """Create tactical analysis engine"""
    return TacticalAnalysisEngine()