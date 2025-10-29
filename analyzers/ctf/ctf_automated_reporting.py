"""
Automated Reporting System for CTF Analysis
Generates writeups, collects evidence, tracks performance, and provides analytics
"""

import json
import os
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict, Counter
import base64
import zipfile
import tempfile

class AutomatedReporting:
    """Comprehensive automated reporting system for CTF challenges"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.report_templates = self._load_report_templates()
        self.evidence_collector = EvidenceCollector()
        self.performance_tracker = PerformanceTracker()
        self.writeup_generator = WriteupGenerator()
        
    def generate_comprehensive_report(self, analysis_results: Dict[str, Any], 
                                    user_progress: Dict[str, Any],
                                    challenge_context: Dict[str, Any],
                                    include_writeup: bool = True) -> Dict[str, Any]:
        """Generate comprehensive CTF analysis report"""
        report = {
            'metadata': self._generate_report_metadata(challenge_context),
            'executive_summary': self._generate_executive_summary(analysis_results),
            'technical_analysis': self._generate_technical_analysis(analysis_results),
            'evidence_package': self.evidence_collector.collect_evidence(analysis_results),
            'performance_analytics': self.performance_tracker.analyze_performance(user_progress),
            'recommendations': self._generate_recommendations(analysis_results),
            'appendix': self._generate_appendix(analysis_results)
        }
        
        # Conditionally include writeup based on parameter
        if include_writeup:
            report['writeup'] = self.writeup_generator.generate_writeup(analysis_results, user_progress)
        
        return report
    
    def export_report(self, report: Dict[str, Any], format_type: str = 'json') -> Dict[str, Any]:
        """Export report in specified format"""
        try:
            if format_type == 'json':
                return self._export_json_report(report)
            elif format_type == 'markdown':
                return self._export_markdown_report(report)
            elif format_type == 'html':
                return self._export_html_report(report)
            elif format_type == 'pdf':
                return self._export_pdf_report(report)
            else:
                return {'error': f'Unsupported format: {format_type}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_report_metadata(self, challenge_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report metadata"""
        return {
            'report_id': hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16],
            'generated_at': datetime.now().isoformat(),
            'challenge_name': challenge_context.get('name', 'Unknown Challenge'),
            'challenge_type': challenge_context.get('type', 'forensics'),
            'difficulty_assessed': challenge_context.get('difficulty', 'Medium'),
            'analyst': challenge_context.get('analyst', 'FlagSniff User'),
            'tool_version': 'FlagSniff v2.0',
            'analysis_duration': challenge_context.get('analysis_duration', 'Unknown')
        }
    
    def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        flags_found = len([f for f in analysis_results.get('successful_decodes', []) 
                          if 'flag' in f.get('decoded_flag', '').lower()])
        
        summary = {
            'key_findings': {
                'vulnerabilities_discovered': len(vulnerabilities),
                'flags_recovered': flags_found,
                'encoding_chains_decoded': len(analysis_results.get('encoding_chains', [])),
                'steganography_detected': self._count_steganography_findings(analysis_results),
                'exploitation_opportunities': len(analysis_results.get('exploitation_opportunities', []))
            },
            'risk_assessment': self._assess_overall_risk(analysis_results),
            'critical_findings': self._identify_critical_findings(analysis_results),
            'success_rate': self._calculate_success_rate(analysis_results)
        }
        
        return summary
    
    def _generate_technical_analysis(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed technical analysis"""
        return {
            'vulnerability_analysis': self._analyze_vulnerabilities(analysis_results),
            'encoding_analysis': self._analyze_encoding_chains(analysis_results),
            'steganography_analysis': self._analyze_steganography(analysis_results),
            'network_analysis': self._analyze_network_patterns(analysis_results),
            'exploitation_analysis': self._analyze_exploitation_opportunities(analysis_results)
        }
    
    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate recommendations for improvements and next steps"""
        recommendations = {
            'immediate_actions': [],
            'long_term_improvements': [],
            'tool_suggestions': [],
            'learning_opportunities': []
        }
        
        # Analyze findings to generate recommendations
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        if len(vulnerabilities) > 5:
            recommendations['immediate_actions'].append(
                'Focus on automated vulnerability scanning tools'
            )
        
        if any(v.get('type') == 'sql_injection' for v in vulnerabilities):
            recommendations['tool_suggestions'].append('sqlmap for SQL injection testing')
            
        if analysis_results.get('encoding_chains'):
            recommendations['learning_opportunities'].append(
                'Study advanced encoding techniques and cryptanalysis'
            )
            
        return recommendations
    
    def _generate_appendix(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate appendix with detailed data"""
        return {
            'raw_findings': analysis_results,
            'analysis_timeline': self._construct_analysis_timeline(analysis_results),
            'technical_details': self._extract_technical_details(analysis_results),
            'references': self._generate_references(),
            'glossary': self._generate_glossary()
        }
    
    def _construct_analysis_timeline(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Construct analysis timeline from results"""
        timeline = []
        
        # Add analysis start event
        timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'Analysis started',
            'description': 'PCAP analysis initiated'
        })
        
        # Add key finding events
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            timeline.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'Vulnerabilities detected',
                'description': f'Found {len(vulnerabilities)} potential vulnerabilities'
            })
        
        encoding_chains = analysis_results.get('encoding_chains', [])
        if encoding_chains:
            timeline.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'Encoding chains analyzed',
                'description': f'Processed {len(encoding_chains)} encoding chains'
            })
        
        # Add completion event
        timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'Analysis completed',
            'description': 'CTF analysis finished successfully'
        })
        
        return timeline
    
    def _extract_technical_details(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract technical details for appendix"""
        return {
            'packet_analysis': {
                'total_packets': analysis_results.get('total_packets', 0),
                'protocols_found': ['HTTP', 'TCP', 'UDP']  # Placeholder
            },
            'analysis_methods': [
                'Pattern matching',
                'Encoding detection',
                'Vulnerability scanning',
                'Steganography analysis'
            ]
        }
    
    def _generate_references(self) -> List[str]:
        """Generate reference list"""
        return [
            'OWASP Testing Guide',
            'NIST Cybersecurity Framework',
            'CTF Field Guide',
            'Network Protocol Analysis Handbook'
        ]
    
    def _generate_glossary(self) -> Dict[str, str]:
        """Generate glossary of terms"""
        return {
            'CTF': 'Capture The Flag - A cybersecurity competition format',
            'PCAP': 'Packet Capture - A file format for storing network traffic',
            'Steganography': 'The practice of hiding data within other data',
            'Vulnerability': 'A security weakness that can be exploited',
            'Encoding': 'A method of transforming data into a different format'
        }
    
    # Helper methods
    def _count_steganography_findings(self, analysis_results: Dict[str, Any]) -> int:
        """Count total steganography findings"""
        count = 0
        stego_types = ['timing_patterns', 'size_patterns', 'covert_channels', 'lsb_analysis']
        
        for stego_type in stego_types:
            count += len(analysis_results.get(stego_type, []))
            
        return count
    
    def _analyze_vulnerabilities(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerabilities for technical analysis section"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return {'summary': 'No vulnerabilities detected'}
            
        analysis = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': {},
            'by_type': {},
            'high_confidence_findings': [],
            'remediation_priorities': []
        }
        
        # Analyze by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            analysis['by_severity'][severity] = analysis['by_severity'].get(severity, 0) + 1
            
            vuln_type = vuln.get('type', 'unknown')
            analysis['by_type'][vuln_type] = analysis['by_type'].get(vuln_type, 0) + 1
            
            # High confidence findings
            if vuln.get('confidence', 0) > 80:
                analysis['high_confidence_findings'].append({
                    'type': vuln_type,
                    'confidence': vuln.get('confidence'),
                    'description': vuln.get('description')
                })
        
        return analysis
    
    def _analyze_encoding_chains(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze encoding chains for technical analysis section"""
        encoding_chains = analysis_results.get('encoding_chains', [])
        
        if not encoding_chains:
            return {'summary': 'No encoding chains analyzed'}
            
        analysis = {
            'total_chains': len(encoding_chains),
            'successful_decodes': 0,
            'encoding_types_found': set(),
            'complexity_analysis': {}
        }
        
        for chain in encoding_chains:
            if chain.get('success'):
                analysis['successful_decodes'] += 1
                
            chain_encodings = chain.get('encoding_chain', [])
            analysis['encoding_types_found'].update(chain_encodings)
            
            # Complexity analysis
            chain_length = len(chain_encodings)
            complexity = 'Simple' if chain_length <= 2 else 'Moderate' if chain_length <= 4 else 'Complex'
            analysis['complexity_analysis'][complexity] = analysis['complexity_analysis'].get(complexity, 0) + 1
        
        analysis['encoding_types_found'] = list(analysis['encoding_types_found'])
        return analysis
    
    def _analyze_steganography(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze steganography findings for technical analysis section"""
        stego_types = ['timing_patterns', 'size_patterns', 'covert_channels', 'lsb_analysis']
        
        analysis = {
            'total_findings': 0,
            'by_technique': {},
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        for stego_type in stego_types:
            findings = analysis_results.get(stego_type, [])
            analysis['total_findings'] += len(findings)
            analysis['by_technique'][stego_type] = len(findings)
            
            # Analyze confidence distribution
            for finding in findings:
                conf = finding.get('confidence', 0)
                if conf >= 80:
                    analysis['confidence_distribution']['high'] += 1
                elif conf >= 60:
                    analysis['confidence_distribution']['medium'] += 1
                else:
                    analysis['confidence_distribution']['low'] += 1
        
        return analysis
    
    def _analyze_network_patterns(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network patterns for technical analysis section"""
        return {
            'summary': 'Network pattern analysis completed',
            'protocols_analyzed': ['HTTP', 'TCP', 'UDP'],  # Placeholder
            'traffic_volume': analysis_results.get('total_packets', 0)
        }
    
    def _analyze_exploitation_opportunities(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze exploitation opportunities for technical analysis section"""
        opportunities = analysis_results.get('exploitation_opportunities', [])
        
        analysis = {
            'total_opportunities': len(opportunities),
            'by_type': {},
            'risk_assessment': 'Low'
        }
        
        for opp in opportunities:
            opp_type = opp.get('type', 'unknown')
            analysis['by_type'][opp_type] = analysis['by_type'].get(opp_type, 0) + 1
            
        # Risk assessment
        if len(opportunities) > 3:
            analysis['risk_assessment'] = 'High'
        elif len(opportunities) > 1:
            analysis['risk_assessment'] = 'Medium'
        return analysis
    
    def _assess_overall_risk(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk based on findings"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        high_risk_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        medium_risk_count = sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM')
        
        if high_risk_count > 2:
            risk_level = 'HIGH'
        elif high_risk_count > 0 or medium_risk_count > 3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return {
            'overall_risk': risk_level,
            'high_risk_findings': high_risk_count,
            'medium_risk_findings': medium_risk_count,
            'total_findings': len(vulnerabilities)
        }
        """Assess overall risk based on findings"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        high_risk_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        medium_risk_count = sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM')
        
        if high_risk_count > 2:
            risk_level = 'HIGH'
        elif high_risk_count > 0 or medium_risk_count > 3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return {
            'overall_risk': risk_level,
            'high_risk_findings': high_risk_count,
            'medium_risk_findings': medium_risk_count,
            'total_findings': len(vulnerabilities)
        }
    
    def _identify_critical_findings(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify most critical findings"""
        critical_findings = []
        
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln.get('severity') == 'HIGH' and vuln.get('confidence', 0) > 80:
                critical_findings.append({
                    'type': vuln.get('type'),
                    'description': vuln.get('description'),
                    'confidence': vuln.get('confidence'),
                    'impact': vuln.get('potential_impact')
                })
                
        # Also include successful flag discoveries
        successful_decodes = analysis_results.get('successful_decodes', [])
        for decode in successful_decodes:
            if 'flag' in decode.get('decoded_flag', '').lower():
                critical_findings.append({
                    'type': 'flag_discovery',
                    'description': f"Flag found: {decode.get('decoded_flag')}",
                    'confidence': decode.get('confidence'),
                    'method': decode.get('method')
                })
                
        return critical_findings
    
    def _calculate_success_rate(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate analysis success rate"""
        total_attempts = 0
        successful_attempts = 0
        
        # Count encoding attempts
        encoding_chains = analysis_results.get('encoding_chains', [])
        total_attempts += len(encoding_chains)
        successful_attempts += sum(1 for chain in encoding_chains if chain.get('success'))
        
        # Count vulnerability detection attempts (assume all successful if found)
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            total_attempts += len(vulnerabilities)
            successful_attempts += len(vulnerabilities)
        
        return (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            'markdown': '''
# CTF Analysis Report

## Executive Summary
{executive_summary}

## Technical Analysis
{technical_analysis}

## Writeup
{writeup}

## Recommendations
{recommendations}

## Evidence
{evidence_summary}
''',
            'html': '''
<!DOCTYPE html>
<html>
<head>
    <title>CTF Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .section {{ margin-bottom: 30px; }}
        .finding {{ background: #f5f5f5; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #2ecc71; }}
    </style>
</head>
<body>
    <h1>CTF Analysis Report</h1>
    {content}
</body>
</html>
'''
        }
    
    def _export_json_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Export report as JSON"""
        try:
            filename = f"ctf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(tempfile.gettempdir(), filename)
            
            # Convert report to JSON string
            json_content = json.dumps(report, indent=2, default=str)
            
            with open(filepath, 'w') as f:
                f.write(json_content)
                
            return {
                'success': True,
                'filepath': filepath,
                'filename': filename,
                'format': 'json',
                'content': json_content,
                'mime_type': 'application/json',
                'size_bytes': os.path.getsize(filepath)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _export_markdown_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Export report as Markdown"""
        try:
            filename = f"ctf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = os.path.join(tempfile.gettempdir(), filename)
            
            # Generate markdown content
            content = self._format_markdown_content(report)
            
            with open(filepath, 'w') as f:
                f.write(content)
                
            return {
                'success': True,
                'filepath': filepath,
                'filename': filename,
                'format': 'markdown',
                'content': content,
                'mime_type': 'text/markdown',
                'size_bytes': os.path.getsize(filepath)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _export_html_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Export report as HTML"""
        try:
            filename = f"ctf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = os.path.join(tempfile.gettempdir(), filename)
            
            # Generate HTML content
            content = self._format_html_content(report)
            
            with open(filepath, 'w') as f:
                f.write(content)
                
            return {
                'success': True,
                'filepath': filepath,
                'filename': filename,
                'format': 'html',
                'content': content,
                'mime_type': 'text/html',
                'size_bytes': os.path.getsize(filepath)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _export_pdf_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Export report as PDF.

        Tries WeasyPrint first (HTML->PDF). If unavailable, falls back to a simple
        ReportLab text rendering. If neither is available, returns a clear error.
        """
        try:
            filename = f"ctf_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(tempfile.gettempdir(), filename)
            html_content = self._format_html_content(report)

            # Attempt WeasyPrint
            try:
                from weasyprint import HTML  # type: ignore
                HTML(string=html_content).write_pdf(filepath)
                return {
                    'success': True,
                    'filepath': filepath,
                    'filename': filename,
                    'format': 'pdf',
                    'mime_type': 'application/pdf',
                    'size_bytes': os.path.getsize(filepath)
                }
            except Exception:
                pass

            # Fallback: ReportLab simple text export (lossy but dependency-light)
            try:
                from reportlab.lib.pagesizes import letter  # type: ignore
                from reportlab.pdfgen import canvas  # type: ignore
                c = canvas.Canvas(filepath, pagesize=letter)
                width, height = letter
                # Strip HTML tags for a crude text version
                import re as _re
                text = _re.sub(r'<[^>]+>', '', html_content)
                # Write in chunks per page
                y = height - 40
                for line in (text.splitlines() or [text]):
                    c.drawString(40, y, line[:110])
                    y -= 14
                    if y < 40:
                        c.showPage(); y = height - 40
                c.save()
                return {
                    'success': True,
                    'filepath': filepath,
                    'filename': filename,
                    'format': 'pdf',
                    'mime_type': 'application/pdf',
                    'size_bytes': os.path.getsize(filepath)
                }
            except Exception:
                return {
                    'success': False,
                    'error': 'PDF export requires WeasyPrint or ReportLab. Install one to enable PDF output.'
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _format_markdown_content(self, report: Dict[str, Any]) -> str:
        """Format report content as Markdown"""
        try:
            # Get the markdown template
            template = self.report_templates.get('markdown', '')
            
            # Extract report sections
            metadata = report.get('metadata', {})
            executive_summary = report.get('executive_summary', {})
            technical_analysis = report.get('technical_analysis', {})
            writeup = report.get('writeup', {})
            recommendations = report.get('recommendations', {})
            evidence_package = report.get('evidence_package', {})
            
            # Format executive summary
            exec_summary_text = f"""
**Challenge:** {metadata.get('challenge_name', 'Unknown')}
**Type:** {metadata.get('challenge_type', 'Unknown')}
**Difficulty:** {metadata.get('difficulty_assessed', 'Unknown')}
**Analyst:** {metadata.get('analyst', 'Unknown')}

### Key Findings
- Vulnerabilities Discovered: {executive_summary.get('key_findings', {}).get('vulnerabilities_discovered', 0)}
- Flags Recovered: {executive_summary.get('key_findings', {}).get('flags_recovered', 0)}
- Encoding Chains Decoded: {executive_summary.get('key_findings', {}).get('encoding_chains_decoded', 0)}
- Overall Risk: {executive_summary.get('risk_assessment', {}).get('overall_risk', 'Unknown')}
"""
            
            # Format technical analysis
            tech_analysis_text = f"""
### Vulnerability Analysis
{technical_analysis.get('vulnerability_analysis', {}).get('summary', 'No detailed analysis available')}

### Encoding Analysis  
{technical_analysis.get('encoding_analysis', {}).get('summary', 'No encoding chains analyzed')}

### Network Analysis
{technical_analysis.get('network_analysis', {}).get('summary', 'Network pattern analysis completed')}
"""
            
            # Format writeup
            writeup_text = ""
            if 'writeup' in report:
                writeup = report['writeup']
                writeup_text = f"""
{writeup.get('introduction', 'No introduction available')}

### Methodology
{writeup.get('methodology', 'No methodology documented')}

### Solution Steps
"""
                
                # Add solution steps
                steps = writeup.get('step_by_step_solution', [])
                for step in steps:
                    writeup_text += f"\n**Step {step.get('step', '')}: {step.get('title', '')}**\n"
                    writeup_text += f"{step.get('description', '')}\n"
            else:
                writeup_text = "Writeup generation was skipped for this report."
                
            # Format recommendations
            rec_text = ""
            if isinstance(recommendations, dict):
                immediate = recommendations.get('immediate_actions', [])
                if immediate:
                    rec_text += "### Immediate Actions\n"
                    for action in immediate:
                        rec_text += f"- {action}\n"
                        
                tools = recommendations.get('tool_suggestions', [])
                if tools:
                    rec_text += "\n### Tool Suggestions\n"
                    for tool in tools:
                        rec_text += f"- {tool}\n"
            
            # Format evidence summary
            evidence_text = f"""
### Evidence Collected
- Total Evidence Items: {evidence_package.get('metadata', {}).get('total_items', 0)}
- Packet Samples: {len(evidence_package.get('packet_samples', []))}
- Decoded Data Items: {len(evidence_package.get('decoded_data', []))}
- Vulnerability Proofs: {len(evidence_package.get('vulnerability_proofs', []))}
"""
            
            # Fill the template
            content = template.format(
                executive_summary=exec_summary_text,
                technical_analysis=tech_analysis_text,
                writeup=writeup_text,
                recommendations=rec_text,
                evidence_summary=evidence_text
            )
            
            return content
            
        except Exception as e:
            return f"# CTF Analysis Report\n\nError generating markdown content: {str(e)}"
    
    def _format_html_content(self, report: Dict[str, Any]) -> str:
        """Format report content as HTML"""
        try:
            # Get the HTML template
            template = self.report_templates.get('html', '')
            
            # Extract report sections
            metadata = report.get('metadata', {})
            executive_summary = report.get('executive_summary', {})
            technical_analysis = report.get('technical_analysis', {})
            writeup = report.get('writeup', {})
            recommendations = report.get('recommendations', {})
            evidence_package = report.get('evidence_package', {})
            
            # Build HTML content
            content = f"""
    <div class="section">
        <h2>Report Metadata</h2>
        <div class="finding">
            <strong>Challenge:</strong> {metadata.get('challenge_name', 'Unknown')}<br>
            <strong>Type:</strong> {metadata.get('challenge_type', 'Unknown')}<br>
            <strong>Difficulty:</strong> {metadata.get('difficulty_assessed', 'Unknown')}<br>
            <strong>Analyst:</strong> {metadata.get('analyst', 'Unknown')}<br>
            <strong>Generated:</strong> {metadata.get('generated_at', 'Unknown')}
        </div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="finding">
            <h3>Key Findings</h3>
            <ul>
                <li>Vulnerabilities Discovered: {executive_summary.get('key_findings', {}).get('vulnerabilities_discovered', 0)}</li>
                <li>Flags Recovered: {executive_summary.get('key_findings', {}).get('flags_recovered', 0)}</li>
                <li>Encoding Chains Decoded: {executive_summary.get('key_findings', {}).get('encoding_chains_decoded', 0)}</li>
                <li>Steganography Detected: {executive_summary.get('key_findings', {}).get('steganography_detected', 0)}</li>
            </ul>
            <h3>Risk Assessment</h3>
            <div class="{self._get_risk_class(executive_summary.get('risk_assessment', {}).get('overall_risk', 'LOW'))}">
                Overall Risk Level: {executive_summary.get('risk_assessment', {}).get('overall_risk', 'Unknown')}
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Technical Analysis</h2>
        <div class="finding">
            <h3>Vulnerability Analysis</h3>
            <p>{technical_analysis.get('vulnerability_analysis', {}).get('summary', 'No vulnerabilities detected')}</p>
            
            <h3>Encoding Analysis</h3>
            <p>{technical_analysis.get('encoding_analysis', {}).get('summary', 'No encoding chains analyzed')}</p>
            
            <h3>Network Analysis</h3>
            <p>{technical_analysis.get('network_analysis', {}).get('summary', 'Network pattern analysis completed')}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Writeup</h2>
        <div class="finding">"""
            
            # Add writeup content if available
            if 'writeup' in report:
                writeup = report['writeup']
                content += f"""
            <h3>Introduction</h3>
            <p>{writeup.get('introduction', 'No introduction available')}</p>
            
            <h3>Methodology</h3>
            <p>{writeup.get('methodology', 'No methodology documented')}</p>
            
            <h3>Solution Steps</h3>
            <ol>
"""
                
                # Add solution steps
                steps = writeup.get('step_by_step_solution', [])
                for step in steps:
                    content += f"""
                <li>
                    <strong>{step.get('title', '')}</strong><br>
                    {step.get('description', '')}
                </li>
"""
                    
                content += """
            </ol>
"""
            else:
                content += """
            <p>Writeup generation was skipped for this report.</p>
"""
            
            content += """
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="finding">
"""
            
            # Add recommendations
            if isinstance(recommendations, dict):
                immediate = recommendations.get('immediate_actions', [])
                if immediate:
                    content += "<h3>Immediate Actions</h3><ul>"
                    for action in immediate:
                        content += f"<li>{action}</li>"
                    content += "</ul>"
                    
                tools = recommendations.get('tool_suggestions', [])
                if tools:
                    content += "<h3>Tool Suggestions</h3><ul>"
                    for tool in tools:
                        content += f"<li>{tool}</li>"
                    content += "</ul>"
                    
                learning = recommendations.get('learning_opportunities', [])
                if learning:
                    content += "<h3>Learning Opportunities</h3><ul>"
                    for item in learning:
                        content += f"<li>{item}</li>"
                    content += "</ul>"
            
            content += """
        </div>
    </div>
    
    <div class="section">
        <h2>Evidence Summary</h2>
        <div class="finding">
            <ul>
                <li>Total Evidence Items: {evidence_package.get('metadata', {}).get('total_items', 0)}</li>
                <li>Packet Samples: {len(evidence_package.get('packet_samples', []))}</li>
                <li>Decoded Data Items: {len(evidence_package.get('decoded_data', []))}</li>
                <li>Vulnerability Proofs: {len(evidence_package.get('vulnerability_proofs', []))}</li>
            </ul>
        </div>
    </div>
""".format(evidence_package=evidence_package)
            
            # Fill the template
            html_content = template.format(content=content)
            
            return html_content
            
        except Exception as e:
            return f"<html><body><h1>CTF Analysis Report</h1><p>Error generating HTML content: {str(e)}</p></body></html>"
    
    def _get_risk_class(self, risk_level: str) -> str:
        """Get CSS class for risk level"""
        risk_classes = {
            'HIGH': 'critical',
            'MEDIUM': 'medium', 
            'LOW': 'low'
        }
        return risk_classes.get(risk_level.upper(), 'low')


class EvidenceCollector:
    """Collects and organizes evidence from analysis results"""
    
    def collect_evidence(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence from analysis results"""
        return {
            'metadata': {
                'total_items': len(analysis_results.get('findings', [])),
                'collected_at': datetime.now().isoformat()
            },
            'packet_samples': analysis_results.get('packets', [])[:10],  # First 10 packets
            'decoded_data': analysis_results.get('successful_decodes', []),
            'vulnerability_proofs': analysis_results.get('vulnerabilities', [])
        }


class PerformanceTracker:
    """Tracks performance metrics during analysis"""
    
    def analyze_performance(self, user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze performance from user progress data"""
        return {
            'analysis_duration': user_progress.get('duration', 'Unknown'),
            'techniques_used': user_progress.get('techniques', []),
            'success_metrics': {
                'flags_found': user_progress.get('flags_found', 0),
                'hints_used': user_progress.get('hints_used', 0)
            }
        }


class WriteupGenerator:
    """Generates detailed writeups for CTF challenges"""
    
    def generate_writeup(self, analysis_results: Dict[str, Any], user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive writeup"""
        return {
            'introduction': 'This challenge involved analyzing network traffic to discover hidden flags and vulnerabilities.',
            'methodology': 'Used packet analysis, pattern matching, and encoding detection techniques.',
            'step_by_step_solution': [
                {
                    'step': 1,
                    'title': 'Initial Analysis',
                    'description': 'Analyzed packet structure and identified key protocols'
                },
                {
                    'step': 2,
                    'title': 'Pattern Detection',
                    'description': 'Searched for encoded data and suspicious patterns'
                },
                {
                    'step': 3,
                    'title': 'Decoding',
                    'description': 'Applied various decoding techniques to extract flags'
                }
            ],
            'tools_used': ['FlagSniff', 'Wireshark', 'Custom scripts'],
            'lessons_learned': 'Network traffic analysis requires systematic approach and multiple decoding attempts'
        }

class WriteupGenerator:
    """Generates CTF writeups automatically"""
    
    def generate_writeup(self, analysis_results: Dict[str, Any], user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive CTF writeup"""
        writeup = {
            'introduction': self._generate_introduction(analysis_results),
            'methodology': self._generate_methodology(user_progress),
            'step_by_step_solution': self._generate_solution_steps(analysis_results, user_progress),
            'tools_used': self._identify_tools_used(user_progress),
            'lessons_learned': self._generate_lessons_learned(analysis_results),
            'alternative_approaches': self._suggest_alternatives(analysis_results)
        }
        
        return writeup
    
    def _generate_introduction(self, analysis_results: Dict[str, Any]) -> str:
        """Generate writeup introduction"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        flags_found = len([f for f in analysis_results.get('successful_decodes', []) 
                          if 'flag' in f.get('decoded_flag', '').lower()])
        
        intro = f"""
This writeup documents the analysis of a CTF challenge involving network packet analysis.
During the investigation, we discovered {len(vulnerabilities)} vulnerabilities and 
successfully recovered {flags_found} flag(s) through various techniques including
encoding chain analysis, steganography detection, and vulnerability exploitation.
"""
        return intro.strip()
    
    def _generate_methodology(self, user_progress: Dict[str, Any]) -> str:
        """Generate methodology section"""
        actions = user_progress.get('action_counts', {})
        
        methodology = """
Our analysis methodology included:
1. Initial packet capture examination and traffic flow analysis
2. Protocol-specific vulnerability scanning
3. Encoding chain detection and systematic decoding
4. Steganography analysis in packet timing and sizes
5. Exploitation opportunity identification and validation
"""
        
        if actions.get('analyze_packet', 0) > 10:
            methodology += "\n6. Deep packet-by-packet manual analysis"
            
        return methodology.strip()
    
    def _generate_solution_steps(self, analysis_results: Dict[str, Any], user_progress: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate step-by-step solution"""
        steps = []
        step_counter = 1
        
        # Step 1: Initial analysis
        steps.append({
            'step': step_counter,
            'title': 'Initial Packet Capture Analysis',
            'description': 'Examined the packet capture file to understand traffic patterns and identify protocols in use.',
            'tools': ['Wireshark', 'FlagSniff'],
            'findings': 'Identified network communication patterns and potential areas of interest.'
        })
        step_counter += 1
        
        # Add vulnerability discovery steps
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            steps.append({
                'step': step_counter,
                'title': 'Vulnerability Discovery',
                'description': f'Discovered {len(vulnerabilities)} potential vulnerabilities through automated scanning.',
                'tools': ['FlagSniff Vulnerability Scanner'],
                'findings': [f"{v.get('type')}: {v.get('description')}" for v in vulnerabilities[:3]]
            })
            step_counter += 1
        
        # Add encoding analysis steps
        encoding_chains = analysis_results.get('encoding_chains', [])
        successful_chains = [c for c in encoding_chains if c.get('success')]
        if successful_chains:
            steps.append({
                'step': step_counter,
                'title': 'Encoding Chain Analysis',
                'description': f'Successfully decoded {len(successful_chains)} encoding chains.',
                'tools': ['FlagSniff Encoding Decoder'],
                'findings': [f"Decoded {len(c.get('encoding_chain', []))} layer chain" for c in successful_chains[:3]]
            })
            step_counter += 1
        
        # Add flag recovery step
        successful_decodes = analysis_results.get('successful_decodes', [])
        flags = [d for d in successful_decodes if 'flag' in d.get('decoded_flag', '').lower()]
        if flags:
            steps.append({
                'step': step_counter,
                'title': 'Flag Recovery',
                'description': f'Successfully recovered {len(flags)} flag(s).',
                'tools': ['Multiple decoding techniques'],
                'findings': [f"Flag: {f.get('decoded_flag')}" for f in flags]
            })
        
        return steps
    
    def _identify_tools_used(self, user_progress: Dict[str, Any]) -> List[str]:
        """Identify tools used during analysis"""
        tools = ['FlagSniff PCAP Analyzer']
        
        actions = user_progress.get('action_counts', {})
        
        if actions.get('vulnerability_scan', 0) > 0:
            tools.append('Vulnerability Scanner')
        if actions.get('decode_attempt', 0) > 0:
            tools.append('Encoding Chain Decoder')
        if actions.get('steganography_analysis', 0) > 0:
            tools.append('Steganography Detector')
            
        return tools
    
    def _generate_lessons_learned(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate lessons learned"""
        lessons = []
        
        if analysis_results.get('encoding_chains'):
            lessons.append('Multi-layer encoding requires systematic approach to decoding')
            
        if analysis_results.get('vulnerabilities'):
            lessons.append('Automated vulnerability scanning significantly improves discovery rate')
            
        if any(key in analysis_results for key in ['timing_patterns', 'size_patterns']):
            lessons.append('Network steganography can hide data in packet characteristics')
            
        return lessons
    
    def _suggest_alternatives(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Suggest alternative approaches"""
        alternatives = [
            'Manual packet analysis using Wireshark',
            'Custom script development for specific protocols',
            'Machine learning-based anomaly detection'
        ]
        
        if analysis_results.get('vulnerabilities'):
            alternatives.append('Targeted exploitation framework usage')
            
        return alternatives

class EvidenceCollector:
    """Collects and organizes evidence from CTF analysis"""
    
    def collect_evidence(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Collect all evidence from analysis"""
        evidence = {
            'screenshots': self._collect_screenshots(),
            'packet_samples': self._collect_packet_samples(analysis_results),
            'decoded_data': self._collect_decoded_data(analysis_results),
            'vulnerability_proofs': self._collect_vulnerability_proofs(analysis_results),
            'timeline_data': self._collect_timeline_data(analysis_results),
            'metadata': {
                'collection_timestamp': datetime.now().isoformat(),
                'total_items': 0
            }
        }
        
        # Count total evidence items
        total_items = sum(len(v) if isinstance(v, list) else 1 
                         for k, v in evidence.items() if k != 'metadata')
        evidence['metadata']['total_items'] = total_items
        
        return evidence
    
    def _collect_screenshots(self) -> List[Dict[str, Any]]:
        """Collect screenshots (placeholder)"""
        return [
            {
                'type': 'ui_screenshot',
                'description': 'FlagSniff analysis interface',
                'timestamp': datetime.now().isoformat(),
                'filename': 'flagsniff_ui.png'
            }
        ]
    
    def _collect_packet_samples(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect relevant packet samples"""
        samples = []
        
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities[:5]:  # Limit to first 5
            samples.append({
                'type': 'vulnerability_packet',
                'vulnerability_type': vuln.get('type'),
                'location': vuln.get('location'),
                'evidence': vuln.get('evidence'),
                'timestamp': datetime.now().isoformat()
            })
            
        return samples
    
    def _collect_decoded_data(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect decoded data samples"""
        decoded_items = []
        
        successful_decodes = analysis_results.get('successful_decodes', [])
        for decode in successful_decodes:
            decoded_items.append({
                'type': 'decoded_data',
                'original_encoding': decode.get('encoding_chain'),
                'decoded_content': decode.get('decoded_flag'),
                'confidence': decode.get('confidence'),
                'timestamp': datetime.now().isoformat()
            })
            
        return decoded_items
    
    def _collect_vulnerability_proofs(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect vulnerability proof-of-concepts"""
        proofs = []
        
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            proofs.append({
                'vulnerability_type': vuln.get('type'),
                'proof_of_concept': vuln.get('evidence'),
                'severity': vuln.get('severity'),
                'confidence': vuln.get('confidence'),
                'location': vuln.get('location')
            })
            
        return proofs
    
    def _collect_timeline_data(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Collect timeline data"""
        return {
            'analysis_start': datetime.now().isoformat(),
            'key_discoveries': [
                {
                    'timestamp': datetime.now().isoformat(),
                    'event': 'Analysis completed',
                    'findings_count': len(analysis_results.get('vulnerabilities', []))
                }
            ]
        }

class PerformanceTracker:
    """Tracks and analyzes analysis performance"""
    
    def analyze_performance(self, user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user performance during CTF analysis"""
        performance = {
            'time_metrics': self._calculate_time_metrics(user_progress),
            'efficiency_metrics': self._calculate_efficiency_metrics(user_progress),
            'accuracy_metrics': self._calculate_accuracy_metrics(user_progress),
            'skill_assessment': self._assess_skill_level(user_progress),
            'improvement_suggestions': self._generate_improvement_suggestions(user_progress)
        }
        
        return performance
    
    def _calculate_time_metrics(self, user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate time-based performance metrics"""
        time_spent = user_progress.get('time_spent', 0)
        
        return {
            'total_time_minutes': time_spent,
            'time_per_finding': time_spent / max(1, user_progress.get('findings_count', 1)),
            'analysis_pace': 'Fast' if time_spent < 30 else 'Moderate' if time_spent < 60 else 'Slow'
        }
    
    def _calculate_efficiency_metrics(self, user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate efficiency metrics"""
        actions = user_progress.get('action_counts', {})
        total_actions = sum(actions.values())
        
        return {
            'total_actions': total_actions,
            'actions_per_minute': total_actions / max(1, user_progress.get('time_spent', 1)),
            'most_used_action': max(actions.items(), key=lambda x: x[1]) if actions else ('none', 0)
        }
    
    def _calculate_accuracy_metrics(self, user_progress: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate accuracy metrics"""
        # Placeholder - would need more detailed tracking
        return {
            'false_positive_rate': 'Low',
            'finding_accuracy': 'High',
            'overall_accuracy_score': 85
        }
    
    def _assess_skill_level(self, user_progress: Dict[str, Any]) -> str:
        """Assess user skill level based on performance"""
        time_spent = user_progress.get('time_spent', 0)
        actions = user_progress.get('action_counts', {})
        
        if time_spent < 20 and actions.get('analyze_packet', 0) > 10:
            return 'Expert'
        elif time_spent < 45 and sum(actions.values()) > 15:
            return 'Advanced'
        elif time_spent < 90:
            return 'Intermediate'
        else:
            return 'Beginner'
    
    def _generate_improvement_suggestions(self, user_progress: Dict[str, Any]) -> List[str]:
        """Generate performance improvement suggestions"""
        suggestions = []
        
        time_spent = user_progress.get('time_spent', 0)
        if time_spent > 60:
            suggestions.append('Consider using automated analysis tools to speed up discovery')
            
        actions = user_progress.get('action_counts', {})
        if actions.get('manual_analysis', 0) > actions.get('automated_analysis', 0):
            suggestions.append('Balance manual analysis with automated scanning tools')
            
        return suggestions