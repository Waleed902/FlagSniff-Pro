"""
AI Monitor - Real-time monitoring of XBOW Agent activities
"""

import streamlit as st
import time
from datetime import datetime
from typing import List, Dict, Any

class AIActivityMonitor:
    """Monitor and display AI agent activities in real-time"""
    
    def __init__(self):
        self.activities = []
        self.current_phase = "Idle"
        self.progress = 0.0
        self.start_time = None
    
    def start_monitoring(self, mode: str):
        """Start monitoring AI activities"""
        self.start_time = datetime.now()
        self.current_phase = f"Initializing {mode} Mode"
        self.progress = 0.0
        self.activities = []
        
        self.log_activity("🤖 XBOW Agent starting up...", "system")
        self.log_activity(f"🎯 Mode selected: {mode}", "info")
    
    def log_activity(self, message: str, activity_type: str = "info"):
        """Log an AI activity"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        activity = {
            "timestamp": timestamp,
            "message": message,
            "type": activity_type,
            "phase": self.current_phase
        }
        
        self.activities.append(activity)
        
        # Keep only last 20 activities
        if len(self.activities) > 20:
            self.activities = self.activities[-20:]
    
    def update_phase(self, phase: str, progress: float):
        """Update current phase and progress"""
        self.current_phase = phase
        self.progress = progress
        self.log_activity(f"📍 Phase: {phase}", "phase")
    
    def display_monitor(self, container):
        """Display the AI monitor in a Streamlit container"""
        
        with container:
            # Header with current status
            st.markdown("### 🤖 XBOW Agent Live Monitor")
            
            # Status bar
            status_cols = st.columns([2, 1, 1])
            
            with status_cols[0]:
                st.markdown(f"**Current Phase:** {self.current_phase}")
                st.progress(self.progress)
            
            with status_cols[1]:
                if self.start_time:
                    elapsed = datetime.now() - self.start_time
                    st.metric("⏱️ Elapsed", f"{elapsed.seconds}s")
                else:
                    st.metric("⏱️ Elapsed", "0s")
            
            with status_cols[2]:
                st.metric("📊 Progress", f"{int(self.progress * 100)}%")
            
            # Activity log
            st.markdown("**📋 Activity Log:**")
            
            # Create scrollable activity log
            log_container = st.container()
            with log_container:
                # Display activities in reverse order (newest first)
                for activity in reversed(self.activities[-10:]):  # Show last 10
                    timestamp = activity["timestamp"]
                    message = activity["message"]
                    activity_type = activity["type"]
                    
                    # Style based on activity type
                    if activity_type == "system":
                        st.success(f"[{timestamp}] {message}")
                    elif activity_type == "error":
                        st.error(f"[{timestamp}] {message}")
                    elif activity_type == "warning":
                        st.warning(f"[{timestamp}] {message}")
                    elif activity_type == "phase":
                        st.info(f"[{timestamp}] {message}")
                    else:
                        st.text(f"[{timestamp}] {message}")
    
    def display_chat_interface(self, container):
        """Display AI activities as a chat interface"""
        
        with container:
            st.markdown("### 💬 XBOW Agent Communication")
            
            # Display activities as chat messages
            for activity in self.activities[-5:]:  # Show last 5 activities
                message = activity["message"]
                activity_type = activity["type"]
                timestamp = activity["timestamp"]
                
                # Choose avatar based on activity type
                if activity_type == "system":
                    avatar = "🤖"
                elif activity_type == "phase":
                    avatar = "🎯"
                elif activity_type == "error":
                    avatar = "❌"
                elif activity_type == "warning":
                    avatar = "⚠️"
                else:
                    avatar = "💭"
                
                with st.chat_message("assistant", avatar=avatar):
                    st.write(f"**{timestamp}** - {message}")
                    
                    # Add progress bar for phase updates
                    if activity_type == "phase":
                        st.progress(self.progress)
    
    def simulate_deep_hunt_activity(self):
        """Simulate deep hunt activities for demo"""
        activities = [
            ("🔍 Scanning packet headers for encoded data...", 0.1),
            ("🧩 Found 3 base64 strings, analyzing...", 0.2),
            ("🔓 Decoding: ZmxhZ3tiNHMzNjRfMW5fZG41X3F1M3J5fQ==", 0.3),
            ("✅ Decoded to: flag{b4s364_1n_dn5_qu3ry}", 0.4),
            ("🕵️ Analyzing packet timing patterns...", 0.5),
            ("📊 Detected unusual 50ms intervals between packets", 0.6),
            ("🔍 Converting timing to ASCII: 67 84 70...", 0.7),
            ("✅ Timing pattern reveals: CTF{t1m1ng_4tt4ck}", 0.8),
            ("🌐 Scanning DNS queries for tunneling...", 0.9),
            ("✅ Deep hunt analysis complete!", 1.0)
        ]
        
        return activities
    
    def simulate_protocol_analysis_activity(self):
        """Simulate protocol analysis activities for demo"""
        activities = [
            ("🔬 Analyzing HTTP authentication methods...", 0.1),
            ("🚨 ALERT: Basic Auth over unencrypted HTTP detected", 0.2),
            ("🔍 Examining FTP traffic for credentials...", 0.3),
            ("⚠️ WARNING: Plaintext FTP credentials found", 0.4),
            ("🕳️ Checking for covert channels in TCP...", 0.5),
            ("📊 Analyzing TCP window sizes for anomalies...", 0.6),
            ("🔍 Scanning DNS queries for data exfiltration...", 0.7),
            ("🚨 SUSPICIOUS: DNS queries to malware.example.com", 0.8),
            ("📋 Generating security assessment report...", 0.9),
            ("✅ Protocol security analysis complete!", 1.0)
        ]
        
        return activities
    
    def simulate_enhancement_activity(self):
        """Simulate enhancement activities for demo"""
        activities = [
            ("🧠 Loading findings into AI context...", 0.1),
            ("🎯 Calculating confidence scores...", 0.2),
            ("📊 flag{h3ll0_w0rld_fr0m_p4ck3t5} - 100% confidence", 0.3),
            ("📊 HTB{n3tw0rk_f0r3ns1cs_m4st3r} - 100% confidence", 0.4),
            ("🔍 Cross-referencing with CTF patterns...", 0.5),
            ("💡 Generating contextual insights...", 0.6),
            ("🎮 Applying CTF-specific analysis...", 0.7),
            ("📝 Creating detailed explanations...", 0.8),
            ("💡 Generating actionable recommendations...", 0.9),
            ("✅ Enhancement analysis complete!", 1.0)
        ]
        
        return activities

def create_ai_monitor():
    """Factory function to create AI monitor"""
    return AIActivityMonitor()

def display_ai_thinking_process(mode: str, container):
    """Display what the AI is thinking during analysis"""
    
    with container:
        st.markdown("### 🧠 XBOW Agent Thought Process")
        
        if mode == "AI Deep Hunt":
            thoughts = [
                "🤔 I need to look beyond obvious patterns...",
                "🔍 Let me check for base64 in unusual places...",
                "💡 DNS queries look suspicious - checking for tunneling...",
                "🧩 These packet timings seem too regular...",
                "🎯 Found something! This looks like a hidden flag...",
                "✅ High confidence - this matches CTF patterns!"
            ]
        elif mode == "Protocol Analysis":
            thoughts = [
                "🔬 Analyzing protocol security posture...",
                "🚨 This HTTP Basic Auth is concerning...",
                "🕳️ Checking for covert communication channels...",
                "📊 These TCP patterns are unusual...",
                "⚠️ Multiple security issues detected...",
                "📋 Preparing comprehensive security report..."
            ]
        else:  # Standard + AI
            thoughts = [
                "🧠 Enhancing standard findings with AI...",
                "🎯 These flags look legitimate - high confidence...",
                "🔍 Cross-checking against known CTF patterns...",
                "💡 I can provide better context for these findings...",
                "🎮 This looks like a network forensics challenge...",
                "✅ Enhanced analysis with actionable insights!"
            ]
        
        # Display thoughts as chat messages
        for i, thought in enumerate(thoughts):
            with st.chat_message("assistant", avatar="💭"):
                st.write(thought)
                if i < len(thoughts) - 1:
                    st.caption("*thinking...*")

def display_ai_performance_metrics(results: Dict[str, Any], container):
    """Display AI performance metrics"""
    
    with container:
        st.markdown("### 📊 XBOW Performance Metrics")
        
        # Calculate metrics
        total_findings = len(results.get('findings', []))
        ai_findings = len(results.get('ai_findings', []))
        high_conf_ai = len([f for f in results.get('ai_findings', []) 
                           if f.get('confidence', 0) >= 80])
        
        # Performance dashboard
        perf_cols = st.columns(4)
        
        with perf_cols[0]:
            st.metric(
                "🎯 Discovery Rate",
                f"{ai_findings}/{total_findings + ai_findings}",
                delta=f"+{ai_findings} hidden flags"
            )
        
        with perf_cols[1]:
            accuracy = (high_conf_ai / max(ai_findings, 1)) * 100 if ai_findings > 0 else 0
            st.metric(
                "🎯 Accuracy",
                f"{accuracy:.0f}%",
                delta=f"{high_conf_ai} high confidence"
            )
        
        with perf_cols[2]:
            enhancement_score = 100 if 'ai_analysis' in results else 0
            st.metric(
                "🧠 Enhancement",
                f"{enhancement_score}%",
                delta="All findings enhanced" if enhancement_score > 0 else "No enhancement"
            )
        
        with perf_cols[3]:
            suggestions = len(results.get('ai_suggestions', []))
            st.metric(
                "💡 Actionability",
                f"{suggestions} items",
                delta="Recommendations generated" if suggestions > 0 else "No suggestions"
            )
        
        # Performance chart
        if ai_findings > 0:
            st.markdown("**🎯 AI Discovery Breakdown:**")
            
            confidence_ranges = {
                "High (80-100%)": len([f for f in results.get('ai_findings', []) 
                                     if f.get('confidence', 0) >= 80]),
                "Medium (60-79%)": len([f for f in results.get('ai_findings', []) 
                                      if 60 <= f.get('confidence', 0) < 80]),
                "Low (0-59%)": len([f for f in results.get('ai_findings', []) 
                                  if f.get('confidence', 0) < 60])
            }
            
            # Display as columns
            conf_cols = st.columns(3)
            for i, (range_name, count) in enumerate(confidence_ranges.items()):
                with conf_cols[i]:
                    color = "🟢" if "High" in range_name else "🟡" if "Medium" in range_name else "🔴"
                    st.metric(f"{color} {range_name}", count)