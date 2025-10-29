"""
Visual Analysis Tools for CTF Challenges
Provides protocol flow diagrams, flag discovery timeline, attack surface mapping, and correlation graphs
"""

import json
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import streamlit as st

class VisualAnalysisTools:
    """Comprehensive visual analysis tools for CTF challenges"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.color_schemes = {
            'protocols': {
                'HTTP': '#FF6B6B',
                'HTTPS': '#4ECDC4',
                'FTP': '#45B7D1',
                'SSH': '#96CEB4',
                'DNS': '#FFEAA7',
                'SMTP': '#DDA0DD',
                'TCP': '#98D8C8',
                'UDP': '#F7DC6F',
                'ICMP': '#BB8FCE'
            },
            'severity': {
                'HIGH': '#E74C3C',
                'MEDIUM': '#F39C12',
                'LOW': '#F4D03F',
                'INFO': '#AED6F1'
            },
            'confidence': {
                'high': '#27AE60',
                'medium': '#F39C12',
                'low': '#E74C3C'
            }
        }
        
    def create_protocol_flow_diagram(self, packets: List[Any], packet_data_list: List[Dict]) -> Dict[str, Any]:
        """Create interactive protocol flow diagram"""
        try:
            # Extract flow data
            flows = self._extract_protocol_flows(packet_data_list)
            
            # Create network graph
            G = nx.DiGraph()
            
            # Add nodes and edges
            for flow in flows:
                source = flow.get('source', 'Unknown')
                destination = flow.get('destination', 'Unknown')
                protocol = flow.get('protocol', 'Unknown')
                packet_count = flow.get('packet_count', 1)
                
                # Add nodes
                G.add_node(source, type='host')
                G.add_node(destination, type='host')
                
                # Add edge with protocol and count
                if G.has_edge(source, destination):
                    G[source][destination]['protocols'].append(protocol)
                    G[source][destination]['packet_count'] += packet_count
                else:
                    G.add_edge(source, destination, 
                             protocols=[protocol], 
                             packet_count=packet_count)
            
            # Generate positions
            pos = nx.spring_layout(G, k=3, iterations=50)
            
            # Create Plotly figure
            fig = self._create_network_plot(G, pos)
            
            return {
                'figure': fig,
                'graph_data': {
                    'nodes': len(G.nodes()),
                    'edges': len(G.edges()),
                    'protocols': list(set([p for edge in G.edges(data=True) 
                                         for p in edge[2]['protocols']]))
                },
                'flow_summary': flows
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Protocol flow diagram creation failed: {str(e)}")
            return {'error': str(e)}
    
    def create_flag_discovery_timeline(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create chronological timeline of flag discoveries and analysis events"""
        try:
            events = []
            
            # Extract findings as timeline events
            findings = analysis_results.get('findings', [])
            for finding in findings:
                timestamp = datetime.now()
                if 'timestamp' in finding:
                    try:
                        if isinstance(finding['timestamp'], str):
                            timestamp = datetime.fromisoformat(finding['timestamp'].replace('Z', '+00:00'))
                        elif isinstance(finding['timestamp'], (int, float)):
                            timestamp = datetime.fromtimestamp(finding['timestamp'])
                    except:
                        pass
                
                events.append({
                    'timestamp': timestamp,
                    'type': finding.get('display_type', 'Finding'),
                    'title': f"{finding.get('display_type', 'Finding')}: {finding.get('data', '')[:50]}",
                    'confidence': finding.get('confidence', 50),
                    'severity': self._map_confidence_to_severity(finding.get('confidence', 50)),
                    'description': finding.get('data', '')[:200]
                })
            
            # Extract timeline events if available
            timeline_events = analysis_results.get('timeline', [])
            for event in timeline_events:
                timestamp = datetime.now()
                if 'timestamp' in event:
                    try:
                        if isinstance(event['timestamp'], str):
                            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                        elif isinstance(event['timestamp'], (int, float)):
                            timestamp = datetime.fromtimestamp(event['timestamp'])
                    except:
                        pass
                
                events.append({
                    'timestamp': timestamp,
                    'type': event.get('type', 'Event'),
                    'title': event.get('description', 'Timeline Event'),
                    'confidence': 70,
                    'severity': 'INFO',
                    'description': event.get('description', '')
                })
            
            # Extract additional analysis events
            events.extend(self._extract_vulnerability_events(analysis_results))
            events.extend(self._extract_encoding_events(analysis_results))
            events.extend(self._extract_steganography_events(analysis_results))
            events.extend(self._extract_exploitation_events(analysis_results))
            
            # Sort events by timestamp
            events.sort(key=lambda x: x.get('timestamp', datetime.now()))
            
            # Create timeline visualization
            fig = self._create_timeline_plot(events)
            
            return {
                'figure': fig,
                'events': events,
                'timeline_stats': {
                    'total_events': len(events),
                    'event_types': Counter([e['type'] for e in events]),
                    'time_span': self._calculate_time_span(events)
                }
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Timeline creation failed: {str(e)}")
            return {'error': str(e)}
    
    def create_attack_surface_map(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create visual representation of potential attack vectors and vulnerabilities"""
        try:
            # Extract attack surface data
            attack_vectors = self._extract_attack_vectors(analysis_results)
            
            # Create hierarchical structure
            attack_tree = self._build_attack_tree(attack_vectors)
            
            # Create visualization
            fig = self._create_attack_surface_plot(attack_tree)
            
            return {
                'figure': fig,
                'attack_vectors': attack_vectors,
                'attack_tree': attack_tree,
                'risk_assessment': self._assess_attack_surface_risk(attack_vectors)
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Attack surface map creation failed: {str(e)}")
            return {'error': str(e)}
    
    def create_correlation_graph(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create correlation graph showing relationships between findings"""
        try:
            # Extract findings and correlations
            findings = self._extract_all_findings(analysis_results)
            correlations = self._calculate_correlations(findings)
            
            # Create correlation network
            G = nx.Graph()
            
            # Add finding nodes
            for finding in findings:
                G.add_node(finding['id'], 
                          type=finding['type'], 
                          confidence=finding['confidence'],
                          severity=finding.get('severity', 'LOW'))
            
            # Add correlation edges
            for corr in correlations:
                if corr['strength'] > 0.3:  # Only show significant correlations
                    G.add_edge(corr['finding1'], corr['finding2'], 
                             weight=corr['strength'],
                             correlation_type=corr['type'])
            
            # Generate positions
            pos = nx.spring_layout(G, k=2, iterations=100)
            
            # Create visualization
            fig = self._create_correlation_plot(G, pos, findings)
            
            return {
                'figure': fig,
                'correlations': correlations,
                'findings_count': len(findings),
                'correlation_stats': self._calculate_correlation_stats(correlations)
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Correlation graph creation failed: {str(e)}")
            return {'error': str(e)}
    
    def create_comprehensive_dashboard(self, analysis_results: Dict[str, Any], packets: List[Any], packet_data_list: List[Dict]) -> Dict[str, Any]:
        """Create comprehensive visual dashboard combining all analysis tools"""
        try:
            dashboard = {
                'protocol_flow': self.create_protocol_flow_diagram(packets, packet_data_list),
                'timeline': self.create_flag_discovery_timeline(analysis_results),
                'attack_surface': self.create_attack_surface_map(analysis_results),
                'correlations': self.create_correlation_graph(analysis_results),
                'summary_stats': self._generate_dashboard_summary(analysis_results)
            }
            
            return dashboard
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Dashboard creation failed: {str(e)}")
            return {'error': str(e)}
    
    # Helper methods for data extraction
    def _extract_protocol_flows(self, packet_data_list: List[Dict]) -> List[Dict]:
        """Extract protocol flow information from packets"""
        flows = []
        flow_map = defaultdict(lambda: {'packet_count': 0, 'protocols': set()})
        
        for packet in packet_data_list:
            if not isinstance(packet, dict):
                continue
                
            # Try multiple field names for source and destination
            source = (packet.get('src_ip') or 
                     packet.get('src') or 
                     packet.get('source') or 
                     'Unknown')
            
            destination = (packet.get('dst_ip') or 
                          packet.get('dst') or 
                          packet.get('destination') or 
                          'Unknown')
            
            protocol = (packet.get('protocol') or 
                       packet.get('proto') or 
                       'Unknown')
            
            # Skip if we couldn't extract meaningful data
            if source == 'Unknown' and destination == 'Unknown':
                continue
            
            # Create flow key
            flow_key = f"{source}->{destination}"
            flow_map[flow_key]['packet_count'] += 1
            flow_map[flow_key]['protocols'].add(protocol)
            flow_map[flow_key]['source'] = source
            flow_map[flow_key]['destination'] = destination
        
        # Convert to list format
        for flow_key, flow_data in flow_map.items():
            protocols_list = list(flow_data['protocols'])
            flows.append({
                'source': flow_data['source'],
                'destination': flow_data['destination'],
                'protocol': protocols_list[0] if protocols_list else 'Unknown',
                'protocols': protocols_list,
                'packet_count': flow_data['packet_count']
            })
        
        return flows
    
    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map confidence score to severity level"""
        if confidence >= 90:
            return 'HIGH'
        elif confidence >= 70:
            return 'MEDIUM'
        elif confidence >= 50:
            return 'LOW'
        else:
            return 'INFO'
    
    def _extract_vulnerability_events(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract vulnerability discovery events"""
        events = []
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        for i, vuln in enumerate(vulnerabilities):
            events.append({
                'timestamp': datetime.now() - timedelta(minutes=len(vulnerabilities)-i),
                'type': 'vulnerability_discovered',
                'title': f"{vuln.get('type', 'Unknown')} Vulnerability",
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity', 'MEDIUM'),
                'confidence': vuln.get('confidence', 50),
                'details': vuln
            })
        
        return events
    
    def _extract_encoding_events(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract encoding chain discovery events"""
        events = []
        encoding_chains = analysis_results.get('encoding_chains', [])
        
        for i, chain in enumerate(encoding_chains):
            if chain.get('success'):
                events.append({
                    'timestamp': datetime.now() - timedelta(minutes=len(encoding_chains)-i),
                    'type': 'encoding_decoded',
                    'title': f"Encoding Chain Decoded",
                    'description': f"Decoded {len(chain.get('encoding_chain', []))} layer chain",
                    'severity': 'INFO',
                    'confidence': chain.get('confidence', 70),
                    'details': chain
                })
        
        return events
    
    def _extract_steganography_events(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract steganography discovery events"""
        events = []
        
        # Check different steganography types
        stego_types = ['timing_patterns', 'size_patterns', 'covert_channels', 'lsb_analysis']
        
        for stego_type in stego_types:
            findings = analysis_results.get(stego_type, [])
            for i, finding in enumerate(findings):
                events.append({
                    'timestamp': datetime.now() - timedelta(minutes=len(findings)-i),
                    'type': 'steganography_found',
                    'title': f"Steganography: {finding.get('method', stego_type)}",
                    'description': finding.get('evidence', ''),
                    'severity': 'MEDIUM',
                    'confidence': finding.get('confidence', 60),
                    'details': finding
                })
        
        return events
    
    def _extract_exploitation_events(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract exploitation opportunity events"""
        events = []
        opportunities = analysis_results.get('exploitation_opportunities', [])
        
        for i, opp in enumerate(opportunities):
            events.append({
                'timestamp': datetime.now() - timedelta(minutes=len(opportunities)-i),
                'type': 'exploitation_opportunity',
                'title': f"Exploitation: {opp.get('type', 'Unknown')}",
                'description': opp.get('description', ''),
                'severity': 'HIGH',
                'confidence': opp.get('confidence', 75),
                'details': opp
            })
        
        return events
    
    def _extract_attack_vectors(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract attack vectors from analysis results"""
        attack_vectors = []
        
        # From vulnerabilities
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            attack_vectors.append({
                'type': 'vulnerability',
                'category': vuln.get('type', 'unknown'),
                'severity': vuln.get('severity', 'MEDIUM'),
                'confidence': vuln.get('confidence', 50),
                'impact': vuln.get('potential_impact', 'Unknown'),
                'location': vuln.get('location', 'Unknown')
            })
        
        # From exploitation opportunities
        opportunities = analysis_results.get('exploitation_opportunities', [])
        for opp in opportunities:
            attack_vectors.append({
                'type': 'exploitation',
                'category': opp.get('type', 'unknown'),
                'severity': 'HIGH',
                'confidence': opp.get('confidence', 75),
                'impact': 'System compromise',
                'difficulty': opp.get('difficulty', 'Medium')
            })
        
        return attack_vectors
    
    def _extract_all_findings(self, analysis_results: Dict[str, Any]) -> List[Dict]:
        """Extract all findings for correlation analysis"""
        findings = []
        finding_id = 0
        
        # Vulnerabilities
        for vuln in analysis_results.get('vulnerabilities', []):
            findings.append({
                'id': f"vuln_{finding_id}",
                'type': 'vulnerability',
                'subtype': vuln.get('type', 'unknown'),
                'confidence': vuln.get('confidence', 50),
                'severity': vuln.get('severity', 'MEDIUM'),
                'location': vuln.get('location', ''),
                'data': vuln
            })
            finding_id += 1
        
        # Encoding chains
        for chain in analysis_results.get('encoding_chains', []):
            if chain.get('success'):
                findings.append({
                    'id': f"encoding_{finding_id}",
                    'type': 'encoding',
                    'subtype': 'chain_decoded',
                    'confidence': chain.get('confidence', 70),
                    'severity': 'INFO',
                    'location': f"Packet {chain.get('source_packet', 'Unknown')}",
                    'data': chain
                })
                finding_id += 1
        
        # Steganography
        stego_types = ['timing_patterns', 'size_patterns', 'covert_channels']
        for stego_type in stego_types:
            for finding in analysis_results.get(stego_type, []):
                findings.append({
                    'id': f"stego_{finding_id}",
                    'type': 'steganography',
                    'subtype': finding.get('type', stego_type),
                    'confidence': finding.get('confidence', 60),
                    'severity': 'MEDIUM',
                    'location': finding.get('evidence', ''),
                    'data': finding
                })
                finding_id += 1
        
        return findings
    
    # Visualization creation methods
    def _create_network_plot(self, G: nx.DiGraph, pos: Dict) -> go.Figure:
        """Create network plot for protocol flows"""
        # Extract edge traces
        edge_x = []
        edge_y = []
        edge_info = []
        
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
            protocols = ', '.join(edge[2]['protocols'])
            edge_info.append(f"{edge[0]} → {edge[1]}<br>Protocols: {protocols}<br>Packets: {edge[2]['packet_count']}")
        
        edge_trace = go.Scatter(x=edge_x, y=edge_y,
                               line=dict(width=2, color='#888'),
                               hoverinfo='none',
                               mode='lines')
        
        # Extract node traces
        node_x = []
        node_y = []
        node_text = []
        node_info = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            
            # Node info
            adjacencies = list(G.neighbors(node))
            node_info.append(f"Host: {node}<br>Connections: {len(adjacencies)}")
        
        node_trace = go.Scatter(x=node_x, y=node_y,
                               mode='markers+text',
                               hoverinfo='text',
                               text=node_text,
                               textposition="middle center",
                               hovertext=node_info,
                               marker=dict(size=30,
                                         color='lightblue',
                                         line=dict(width=2, color='black')))
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Network Protocol Flow Diagram',
                           title_font_size=16,
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           annotations=[ dict(
                               text="Interactive protocol flow visualization",
                               showarrow=False,
                               xref="paper", yref="paper",
                               x=0.005, y=-0.002,
                               xanchor="left", yanchor="bottom",
                               font=dict(color="#888", size=12)
                           )],
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                       )
        
        return fig
    
    def _create_timeline_plot(self, events: List[Dict]) -> go.Figure:
        """Create timeline visualization"""
        # Prepare data
        df_events = pd.DataFrame(events)
        
        if df_events.empty:
            # Return empty figure if no events
            fig = go.Figure()
            fig.add_annotation(text="No events to display", 
                             xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            return fig
        
        # Create timeline
        fig = px.timeline(df_events, 
                         x_start="timestamp", 
                         x_end="timestamp",
                         y="type",
                         color="severity",
                         hover_data=["title", "confidence"],
                         title="Flag Discovery Timeline")
        
        # Update layout
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Event Type",
            showlegend=True
        )
        
        return fig
    
    def _create_attack_surface_plot(self, attack_tree: Dict) -> go.Figure:
        """Create attack surface visualization"""
        # Create treemap
        labels = []
        parents = []
        values = []
        colors = []
        
        def add_tree_nodes(node, parent=""):
            for key, value in node.items():
                labels.append(key)
                parents.append(parent)
                
                if isinstance(value, dict):
                    values.append(0)  # Parent nodes have 0 value
                    colors.append(0.5)  # Neutral color for parents
                    add_tree_nodes(value, key)
                else:
                    values.append(value.get('risk_score', 1))
                    colors.append(value.get('risk_score', 1))
        
        add_tree_nodes(attack_tree)
        
        fig = go.Figure(go.Treemap(
            labels=labels,
            parents=parents,
            values=values,
            marker_colorscale='RdYlGn_r',
            marker_colorbar=dict(title="Risk Level"),
            textinfo="label+value"
        ))
        
        fig.update_layout(title="Attack Surface Map")
        
        return fig
    
    def _create_correlation_plot(self, G: nx.Graph, pos: Dict, findings: List[Dict]) -> go.Figure:
        """Create correlation graph visualization"""
        # Similar to network plot but for correlations
        edge_x = []
        edge_y = []
        
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(x=edge_x, y=edge_y,
                               line=dict(width=1, color='#888'),
                               hoverinfo='none',
                               mode='lines')
        
        # Node traces with finding information
        node_x = []
        node_y = []
        node_text = []
        node_colors = []
        node_sizes = []
        
        finding_map = {f['id']: f for f in findings}
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            finding = finding_map.get(node, {})
            node_text.append(f"{finding.get('type', 'Unknown')}<br>Confidence: {finding.get('confidence', 0)}")
            node_colors.append(finding.get('confidence', 50))
            node_sizes.append(max(10, finding.get('confidence', 50) / 3))
        
        node_trace = go.Scatter(x=node_x, y=node_y,
                               mode='markers',
                               hoverinfo='text',
                               text=node_text,
                               marker=dict(size=node_sizes,
                                         color=node_colors,
                                         colorscale='Viridis',
                                         line=dict(width=1, color='black')))
        
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(title='Finding Correlation Graph',
                                       showlegend=False,
                                       hovermode='closest',
                                       margin=dict(b=20,l=5,r=5,t=40),
                                       xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                       yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))
        
        return fig
    
    # Additional helper methods
    def _calculate_correlations(self, findings: List[Dict]) -> List[Dict]:
        """Calculate correlations between findings"""
        correlations = []
        
        for i, finding1 in enumerate(findings):
            for j, finding2 in enumerate(findings[i+1:], i+1):
                # Calculate correlation strength based on various factors
                strength = self._calculate_correlation_strength(finding1, finding2)
                
                if strength > 0.1:  # Only include meaningful correlations
                    correlations.append({
                        'finding1': finding1['id'],
                        'finding2': finding2['id'],
                        'strength': strength,
                        'type': self._determine_correlation_type(finding1, finding2)
                    })
        
        return correlations
    
    def _calculate_correlation_strength(self, finding1: Dict, finding2: Dict) -> float:
        """Calculate correlation strength between two findings"""
        strength = 0.0
        
        # Same type correlation
        if finding1['type'] == finding2['type']:
            strength += 0.3
        
        # Location proximity
        if finding1.get('location') == finding2.get('location'):
            strength += 0.4
        
        # Confidence similarity
        conf_diff = abs(finding1['confidence'] - finding2['confidence'])
        if conf_diff < 20:
            strength += 0.2
        
        # Severity correlation
        if finding1.get('severity') == finding2.get('severity'):
            strength += 0.1
        
        return min(1.0, strength)
    
    def _determine_correlation_type(self, finding1: Dict, finding2: Dict) -> str:
        """Determine the type of correlation between findings"""
        if finding1['type'] == finding2['type']:
            return 'same_type'
        elif finding1.get('location') == finding2.get('location'):
            return 'location_based'
        else:
            return 'general'
    
    def _build_attack_tree(self, attack_vectors: List[Dict]) -> Dict:
        """Build hierarchical attack tree structure"""
        tree = defaultdict(lambda: defaultdict(dict))
        
        for vector in attack_vectors:
            category = vector.get('category', 'unknown')
            severity = vector.get('severity', 'LOW')
            
            if category not in tree:
                tree[category] = {}
            
            tree[category][f"{severity}_{len(tree[category])}"] = {
                'risk_score': self._calculate_risk_score(vector),
                'details': vector
            }
        
        return dict(tree)
    
    def _calculate_risk_score(self, vector: Dict) -> float:
        """Calculate risk score for attack vector"""
        severity_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5}
        confidence = vector.get('confidence', 50) / 100
        severity = severity_weights.get(vector.get('severity', 'LOW'), 1)
        
        return confidence * severity
    
    def _assess_attack_surface_risk(self, attack_vectors: List[Dict]) -> Dict[str, Any]:
        """Assess overall attack surface risk"""
        if not attack_vectors:
            return {'overall_risk': 'LOW', 'risk_score': 0}
        
        total_risk = sum(self._calculate_risk_score(vector) for vector in attack_vectors)
        avg_risk = total_risk / len(attack_vectors)
        
        if avg_risk < 1:
            risk_level = 'LOW'
        elif avg_risk < 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'
        
        return {
            'overall_risk': risk_level,
            'risk_score': round(avg_risk, 2),
            'vector_count': len(attack_vectors),
            'high_risk_vectors': sum(1 for v in attack_vectors if v.get('severity') == 'HIGH')
        }
    
    def _calculate_time_span(self, events: List[Dict]) -> str:
        """Calculate time span of events"""
        if not events:
            return "No events"
        
        timestamps = [e['timestamp'] for e in events if 'timestamp' in e]
        if not timestamps:
            return "No timestamps"
        
        earliest = min(timestamps)
        latest = max(timestamps)
        span = latest - earliest
        
        return f"{span.total_seconds() / 60:.1f} minutes"
    
    def _calculate_correlation_stats(self, correlations: List[Dict]) -> Dict[str, Any]:
        """Calculate correlation statistics"""
        if not correlations:
            return {'strong_correlations': 0, 'average_strength': 0}
        
        strengths = [c['strength'] for c in correlations]
        
        return {
            'total_correlations': len(correlations),
            'strong_correlations': sum(1 for s in strengths if s > 0.7),
            'average_strength': round(sum(strengths) / len(strengths), 2),
            'correlation_types': Counter([c['type'] for c in correlations])
        }
    
    def _generate_dashboard_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics for dashboard"""
        return {
            'total_vulnerabilities': len(analysis_results.get('vulnerabilities', [])),
            'encoding_chains_found': len(analysis_results.get('encoding_chains', [])),
            'steganography_findings': sum([
                len(analysis_results.get('timing_patterns', [])),
                len(analysis_results.get('size_patterns', [])),
                len(analysis_results.get('covert_channels', []))
            ]),
            'exploitation_opportunities': len(analysis_results.get('exploitation_opportunities', [])),
            'analysis_timestamp': datetime.now().isoformat()
        }