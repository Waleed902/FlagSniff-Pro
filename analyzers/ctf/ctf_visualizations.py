#!/usr/bin/env python3
"""
Advanced CTF Visualizations
Interactive charts and graphs for CTF analysis
"""

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, List, Any
import numpy as np

# Optional networkx import for network topology
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

class CTFVisualizer:
    """Create advanced visualizations for CTF analysis inspired by PcapXray"""
    
    def __init__(self):
        self.color_scheme = {
            'primary': '#00f5ff',
            'secondary': '#ff00ff',
            'success': '#00ff88',
            'warning': '#ffaa00',
            'danger': '#ff4444',
            'background': '#1a1a2e',
            'network': '#4CAF50',
            'protocol': '#2196F3',
            'malicious': '#F44336',
            'suspicious': '#FF9800'
        }
    
    def create_findings_distribution(self, findings: List[Dict]) -> go.Figure:
        """Create a pie chart of findings by type"""
        if not findings:
            return self._create_empty_chart("No findings to display")
        
        # Count findings by type
        type_counts = {}
        for finding in findings:
            finding_type = finding.get('type', 'Unknown').replace('_', ' ').title()
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        # Create pie chart
        fig = go.Figure(data=[go.Pie(
            labels=list(type_counts.keys()),
            values=list(type_counts.values()),
            hole=0.4,
            marker_colors=[self.color_scheme['primary'], self.color_scheme['secondary'], 
                          self.color_scheme['success'], self.color_scheme['warning'], 
                          self.color_scheme['danger']][:len(type_counts)],
            marker=dict(
                colors=[self.color_scheme['primary'], self.color_scheme['secondary'], 
                       self.color_scheme['success'], self.color_scheme['warning'],
                       self.color_scheme['danger']] * (len(type_counts) // 5 + 1)
            )
        )])
        
        fig.update_layout(
            title="Findings Distribution by Type",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            showlegend=True
        )
        
        return fig
    
    def create_confidence_heatmap(self, findings: List[Dict]) -> go.Figure:
        """Create a heatmap showing confidence levels by finding type"""
        if not findings:
            return self._create_empty_chart("No findings to display")
        
        # Prepare data for heatmap
        data = []
        for finding in findings:
            data.append({
                'type': finding.get('type', 'Unknown').replace('_', ' ').title(),
                'confidence': finding.get('confidence', 50),
                'index': len(data)
            })
        
        df = pd.DataFrame(data)
        
        # Group by type and calculate statistics
        heatmap_data = df.groupby('type')['confidence'].agg(['mean', 'count', 'std']).fillna(0)
        
        fig = go.Figure(data=go.Heatmap(
            z=[heatmap_data['mean'].values],
            x=heatmap_data.index,
            y=['Confidence'],
            colorscale='Viridis',
            text=[[f"{val:.1f}%" for val in heatmap_data['mean'].values]],
            texttemplate="%{text}",
            textfont={"size": 12},
            hoverongaps=False
        ))
        
        fig.update_layout(
            title="Confidence Levels by Finding Type",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Finding Type",
            yaxis_title=""
        )
        
        return fig
    
    def create_protocol_analysis_chart(self, findings: List[Dict]) -> go.Figure:
        """Create a bar chart showing findings by protocol"""
        if not findings:
            return self._create_empty_chart("No protocol data to display")
        
        # Count findings by protocol
        protocol_counts = {}
        for finding in findings:
            protocol = finding.get('protocol', 'Unknown')
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Create bar chart
        fig = go.Figure(data=[
            go.Bar(
                x=list(protocol_counts.keys()),
                y=list(protocol_counts.values()),
                marker_color=self.color_scheme['primary'],
                text=list(protocol_counts.values()),
                textposition='auto'
            )
        ])
        
        fig.update_layout(
            title="Findings by Protocol",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Protocol",
            yaxis_title="Number of Findings",
            xaxis=dict(color='white'),
            yaxis=dict(color='white')
        )
        
        return fig
    
    def create_timeline_chart(self, findings: List[Dict]) -> go.Figure:
        """Create a timeline of findings"""
        if not findings:
            return self._create_empty_chart("No timeline data to display")
        
        # Prepare timeline data
        timeline_data = []
        for i, finding in enumerate(findings):
            timeline_data.append({
                'index': i,
                'type': finding.get('type', 'Unknown'),
                'confidence': finding.get('confidence', 50),
                'timestamp': finding.get('timestamp', i)
            })
        
        df = pd.DataFrame(timeline_data)
        
        # Create scatter plot timeline
        fig = px.scatter(
            df, 
            x='index', 
            y='confidence',
            color='type',
            size='confidence',
            hover_data=['type', 'confidence'],
            title="Findings Timeline"
        )
        
        fig.update_layout(
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Finding Index",
            yaxis_title="Confidence Level",
            xaxis=dict(color='white'),
            yaxis=dict(color='white')
        )
        
        return fig
    
    def create_network_topology(self, packets) -> go.Figure:
        """Create a network topology visualization"""
        if not HAS_NETWORKX:
            return self._create_empty_chart("Network topology requires networkx package\nInstall with: pip install networkx")
        
        # Create a simple network graph
        G = nx.Graph()
        
        # Add nodes and edges based on packet data
        connections = {}
        for packet in packets[:100]:  # Limit for performance
            packet_str = str(packet)
            # Mock IP extraction
            if 'src=' in packet_str and 'dst=' in packet_str:
                src = packet_str.split('src=')[1].split()[0] if 'src=' in packet_str else f"node_{len(G.nodes)}"
                dst = packet_str.split('dst=')[1].split()[0] if 'dst=' in packet_str else f"node_{len(G.nodes)+1}"
                
                G.add_edge(src, dst)
                key = f"{src}-{dst}"
                connections[key] = connections.get(key, 0) + 1
        
        if len(G.nodes) == 0:
            return self._create_empty_chart("No network data to display")
        
        # Calculate layout
        pos = nx.spring_layout(G)
        
        # Create edge traces
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=2, color=self.color_scheme['primary']),
            hoverinfo='none',
            mode='lines'
        )
        
        # Create node traces
        node_x = []
        node_y = []
        node_text = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="middle center",
            marker=dict(
                size=20,
                color=self.color_scheme['success'],
                line=dict(width=2, color='white')
            )
        )
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title="Network Topology",
            titlefont_size=16,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[ dict(
                text="Network connections based on packet analysis",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002,
                xanchor='left', yanchor='bottom',
                font=dict(color='white', size=12)
            )],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig
    
    def create_steganography_analysis(self, stego_findings: List[Dict]) -> go.Figure:
        """Create visualization for steganography analysis"""
        if not stego_findings:
            return self._create_empty_chart("No steganography data found")
        
        # Prepare data for visualization
        methods = []
        confidences = []
        data_lengths = []
        
        for finding in stego_findings:
            if 'stego' in finding.get('type', '').lower():
                methods.append(finding.get('method', 'Unknown'))
                confidences.append(finding.get('confidence', 50))
                data_lengths.append(len(finding.get('data', '')))
        
        if not methods:
            return self._create_empty_chart("No steganography findings")
        
        # Create bubble chart
        fig = go.Figure(data=go.Scatter(
            x=methods,
            y=confidences,
            mode='markers',
            marker=dict(
                size=data_lengths,
                sizemode='diameter',
                sizeref=2.*max(data_lengths)/(40.**2) if data_lengths else 1,
                sizemin=4,
                color=confidences,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Confidence")
            ),
            text=[f"Method: {m}<br>Confidence: {c}%<br>Data Length: {d}" 
                  for m, c, d in zip(methods, confidences, data_lengths)],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Steganography Analysis",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Detection Method",
            yaxis_title="Confidence Level",
            xaxis=dict(color='white'),
            yaxis=dict(color='white')
        )
        
        return fig
    
    def create_credential_analysis(self, credential_findings: List[Dict]) -> go.Figure:
        """Create visualization for credential analysis"""
        if not credential_findings:
            return self._create_empty_chart("No credentials found")
        
        # Count credentials by type
        cred_types = {}
        for finding in credential_findings:
            if 'credential' in finding.get('type', '').lower():
                cred_type = finding.get('method', 'Unknown')
                cred_types[cred_type] = cred_types.get(cred_type, 0) + 1
        
        if not cred_types:
            return self._create_empty_chart("No credential data")
        
        # Create donut chart
        fig = go.Figure(data=[go.Pie(
            labels=list(cred_types.keys()),
            values=list(cred_types.values()),
            hole=0.6,
            marker=dict(
                colors=[self.color_scheme['danger'], self.color_scheme['warning'], 
                       self.color_scheme['primary'], self.color_scheme['secondary']]
            )
        )])
        
        fig.update_layout(
            title="Credentials Found by Type",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            annotations=[dict(text='Credentials', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )
        
        return fig
    
    def create_suspicious_packets_chart(self, suspicious_packets: List[Dict]) -> go.Figure:
        """Create visualization for suspicious packets"""
        if not suspicious_packets:
            return self._create_empty_chart("No suspicious packets found")
        
        # Prepare data
        indices = [p.get('packet_index', i) for i, p in enumerate(suspicious_packets)]
        scores = [p.get('suspicion_score', 0) for p in suspicious_packets]
        reasons = [', '.join(p.get('reasons', [])) for p in suspicious_packets]
        
        # Create bar chart
        fig = go.Figure(data=[
            go.Bar(
                x=indices,
                y=scores,
                marker_color=self.color_scheme['danger'],
                text=scores,
                textposition='auto',
                hovertext=reasons,
                hovertemplate='Packet %{x}<br>Suspicion Score: %{y}<br>Reasons: %{hovertext}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Suspicious Packets Analysis",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Packet Index",
            yaxis_title="Suspicion Score",
            xaxis=dict(color='white'),
            yaxis=dict(color='white')
        )
        
        return fig
    
    def create_protocol_distribution(self, packets_data: List) -> go.Figure:
        """Create protocol distribution visualization inspired by PcapXray"""
        if not packets_data:
            return self._create_empty_chart("No packet data available")
        
        # Count protocols
        protocol_counts = {}
        for packet in packets_data:
            protocol = packet.get('protocol', 'Unknown')
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Create bar chart
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        
        fig = go.Figure(data=[
            go.Bar(
                x=protocols,
                y=counts,
                marker_color=[self.color_scheme['protocol'], self.color_scheme['network'], 
                             self.color_scheme['success'], self.color_scheme['warning']][:len(protocols)],
                text=counts,
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title="Protocol Distribution Analysis",
            xaxis_title="Protocol",
            yaxis_title="Packet Count",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        
        return fig
    
    def create_traffic_timeline(self, packets_data: List) -> go.Figure:
        """Create traffic timeline visualization"""
        if not packets_data:
            return self._create_empty_chart("No packet data available")
        
        # Extract timestamps and create timeline
        timestamps = []
        packet_sizes = []
        protocols = []
        
        for packet in packets_data:
            if 'timestamp' in packet:
                timestamps.append(packet['timestamp'])
                packet_sizes.append(packet.get('size', 0))
                protocols.append(packet.get('protocol', 'Unknown'))
        
        if not timestamps:
            return self._create_empty_chart("No timestamp data available")
        
        # Create scatter plot
        fig = go.Figure()
        
        # Group by protocol for different colors
        protocol_groups = {}
        for i, protocol in enumerate(protocols):
            if protocol not in protocol_groups:
                protocol_groups[protocol] = {'timestamps': [], 'sizes': []}
            protocol_groups[protocol]['timestamps'].append(timestamps[i])
            protocol_groups[protocol]['sizes'].append(packet_sizes[i])
        
        colors = [self.color_scheme['protocol'], self.color_scheme['network'], 
                 self.color_scheme['success'], self.color_scheme['warning']]
        
        for i, (protocol, data) in enumerate(protocol_groups.items()):
            fig.add_trace(go.Scatter(
                x=data['timestamps'],
                y=data['sizes'],
                mode='markers',
                name=protocol,
                marker=dict(
                    color=colors[i % len(colors)],
                    size=8,
                    opacity=0.7
                ),
                hovertemplate=f"<b>{protocol}</b><br>" +
                             "Time: %{x}<br>" +
                             "Size: %{y} bytes<br>" +
                             "<extra></extra>"
            ))
        
        fig.update_layout(
            title="Traffic Timeline Analysis",
            xaxis_title="Time",
            yaxis_title="Packet Size (bytes)",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            hovermode='closest'
        )
        
        return fig
    
    def create_port_analysis(self, sessions: Dict) -> go.Figure:
        """Create port usage analysis inspired by PcapXray"""
        if not sessions:
            return self._create_empty_chart("No session data available")
        
        port_counts = {}
        port_protocols = {}
        
        for session_data in sessions.values():
            src_port = session_data.get('src_port')
            dst_port = session_data.get('dst_port')
            protocol = session_data.get('protocol', 'Unknown')
            
            for port in [src_port, dst_port]:
                if port and isinstance(port, int):
                    port_counts[port] = port_counts.get(port, 0) + 1
                    port_protocols[port] = protocol
        
        if not port_counts:
            return self._create_empty_chart("No port data available")
        
        # Sort by usage
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        
        ports = [str(p[0]) for p in sorted_ports]
        counts = [p[1] for p in sorted_ports]
        colors = []
        
        for port_num, _ in sorted_ports:
            protocol = port_protocols.get(port_num, 'Unknown')
            if protocol == 'TCP':
                colors.append(self.color_scheme['protocol'])
            elif protocol == 'UDP':
                colors.append(self.color_scheme['network'])
            else:
                colors.append(self.color_scheme['primary'])
        
        fig = go.Figure(data=[
            go.Bar(
                x=ports,
                y=counts,
                marker_color=colors,
                text=counts,
                textposition='auto',
                hovertemplate="Port: %{x}<br>Usage: %{y}<extra></extra>"
            )
        ])
        
        fig.update_layout(
            title="Top 20 Port Usage Analysis",
            xaxis_title="Port Number",
            yaxis_title="Usage Count",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        
        return fig
    
    def create_geolocation_map(self, ip_locations: Dict) -> go.Figure:
        """Create geolocation map of IP addresses"""
        if not ip_locations:
            return self._create_empty_chart("No geolocation data available")
        
        lats, lons, texts, colors = [], [], [], []
        
        for ip, location in ip_locations.items():
            if 'lat' in location and 'lon' in location:
                lats.append(location['lat'])
                lons.append(location['lon'])
                
                country = location.get('country', 'Unknown')
                city = location.get('city', 'Unknown')
                texts.append(f"IP: {ip}<br>Location: {city}, {country}")
                
                # Color based on threat level
                threat_level = location.get('threat_level', 'low')
                if threat_level == 'high':
                    colors.append(self.color_scheme['danger'])
                elif threat_level == 'medium':
                    colors.append(self.color_scheme['warning'])
                else:
                    colors.append(self.color_scheme['success'])
        
        if not lats:
            return self._create_empty_chart("No valid geolocation coordinates")
        
        fig = go.Figure(data=go.Scattergeo(
            lon=lons,
            lat=lats,
            text=texts,
            mode='markers',
            marker=dict(
                size=12,
                color=colors,
                line=dict(width=1, color='white'),
                opacity=0.8
            ),
            hovertemplate="%{text}<extra></extra>"
        ))
        
        fig.update_layout(
            title="Geographic Distribution of IP Addresses",
            geo=dict(
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                coastlinecolor='rgb(204, 204, 204)',
            ),
            font=dict(color='white')
        )
        
        return fig
    
    def create_malware_analysis_chart(self, malware_findings: List[Dict]) -> go.Figure:
        """Create malware analysis visualization"""
        if not malware_findings:
            return self._create_empty_chart("No malware findings")
        
        # Prepare data
        malware_types = {}
        threat_levels = {}
        
        for finding in malware_findings:
            malware_type = finding.get('malware_type', 'Unknown')
            threat_level = finding.get('threat_level', 'low')
            
            malware_types[malware_type] = malware_types.get(malware_type, 0) + 1
            threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
        
        # Create subplot with two charts
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('Malware Types', 'Threat Levels'),
            specs=[[{'type': 'domain'}, {'type': 'domain'}]]
        )
        
        # Malware types pie chart
        fig.add_trace(go.Pie(
            labels=list(malware_types.keys()),
            values=list(malware_types.values()),
            name="Malware Types",
            marker_colors=[self.color_scheme['danger'], self.color_scheme['warning'], 
                          self.color_scheme['suspicious']][:len(malware_types)]
        ), 1, 1)
        
        # Threat levels pie chart
        fig.add_trace(go.Pie(
            labels=list(threat_levels.keys()),
            values=list(threat_levels.values()),
            name="Threat Levels",
            marker_colors=[self.color_scheme['success'], self.color_scheme['warning'], 
                          self.color_scheme['danger']][:len(threat_levels)]
        ), 1, 2)
        
        fig.update_layout(
            title="Malware Analysis Overview",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig
    
    def create_file_extraction_summary(self, extracted_files: List[Dict]) -> go.Figure:
        """Create file extraction summary visualization"""
        if not extracted_files:
            return self._create_empty_chart("No extracted files")
        
        # Count files by type
        file_types = {}
        file_sizes = []
        
        for file_info in extracted_files:
            file_type = file_info.get('ext', 'unknown')
            file_size = file_info.get('size', 0)
            
            file_types[file_type] = file_types.get(file_type, 0) + 1
            file_sizes.append(file_size)
        
        # Create treemap
        fig = go.Figure(go.Treemap(
            labels=list(file_types.keys()),
            values=list(file_types.values()),
            parents=[""] * len(file_types),
            textinfo="label+value",
            marker_colorscale='Viridis'
        ))
        
        fig.update_layout(
            title="Extracted Files by Type",
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig

    def _create_empty_chart(self, message: str) -> go.Figure:
        """Create an empty chart with a message"""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=16, color='white')
        )
        fig.update_layout(
            font=dict(color='white'),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(visible=False),
            yaxis=dict(visible=False)
        )
        return fig