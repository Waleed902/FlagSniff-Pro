# -*- coding: utf-8 -*-
"""
FlagSniff Pro - Modern Web Interface
A next-generation PCAP analysis tool with AI capabilities
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
from datetime import datetime
import json
import html
import tempfile
import os

# Import enhanced analyzer and AI agent
try:
    from apps.web_analyzer import WebPcapAnalyzer, analyze_sample_pcap
    from ai.ai_agent import create_agent, AgentConfig
    from ai.flagsniff_ai import setup_ai_agent, analyze_with_ai
    from features.advanced_features import MultiAgentSystem, FlagHunterAgent, ForensicsAgent, CryptoAgent, NetworkSecurityAgent, MalwareAnalysisAgent
    from ai.ai_monitor import AIActivityMonitor
    from analyzers.ctf.ctf_visualizations import CTFVisualizer
    from analyzers.ctf.ctf_analyzer import CTFAnalyzer, NetworkTrafficDecoder, EncodingDecoder, PatternExtractor
    from ai.workflow_orchestrator import WorkflowOrchestrator, WorkflowStep, create_network_ctf_workflow
    from ai.multi_agent_system import MultiAgentCoordinator, NetworkAnalysisAgent, CryptoAnalysisAgent, WebAnalysisAgent, BinaryAnalysisAgent, create_multi_agent_system
    IMPORTS_OK = True
except ImportError as e:
    st.error(f"Import error: {e}")
    IMPORTS_OK = False

# Add rate limit handling
import time
import random
from typing import Optional, Dict, Any

class RateLimitHandler:
    """Handles API rate limiting with exponential backoff and fallback models"""
    
    def __init__(self):
        self.rate_limit_errors = {}
        self.fallback_models = [
            "LongCat-Flash-Chat",
            "gpt-3.5-turbo",
            "gpt-4-turbo"
        ]
        self.current_model_index = 0
    
    def handle_rate_limit(self, model: str, error_msg: str) -> Optional[str]:
        """Handle rate limit error and suggest fallback model"""
        self.rate_limit_errors[model] = {
            'timestamp': time.time(),
            'error': error_msg
        }
        
        # Try next fallback model
        if self.current_model_index < len(self.fallback_models) - 1:
            self.current_model_index += 1
            return self.fallback_models[self.current_model_index]
        
        return None
    
    def get_available_models(self) -> list:
        """Get list of models that haven't hit rate limits recently"""
        current_time = time.time()
        available = []
        
        for model in self.fallback_models:
            if model not in self.rate_limit_errors:
                available.append(model)
            elif current_time - self.rate_limit_errors[model]['timestamp'] > 300:  # 5 minutes
                available.append(model)
        
        return available
    
    def reset_errors(self):
        """Reset rate limit errors"""
        self.rate_limit_errors.clear()
        self.current_model_index = 0

# Page config (must be the first Streamlit call on the page)
st.set_page_config(
    page_title="FlagSniff Pro",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize rate limit handler
if 'rate_limit_handler' not in st.session_state:
    st.session_state.rate_limit_handler = RateLimitHandler()

# Initialize session state
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'analyzer'
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'ai_monitor' not in st.session_state:
    st.session_state.ai_monitor = AIActivityMonitor() if IMPORTS_OK else None
if 'ctf_visualizer' not in st.session_state:
    st.session_state.ctf_visualizer = CTFVisualizer() if IMPORTS_OK else None
if 'multi_agent_system' not in st.session_state:
    st.session_state.multi_agent_system = None
if 'workflow_orchestrator' not in st.session_state:
    st.session_state.workflow_orchestrator = None

def get_theme_styles():
    """Get CSS styles based on current theme"""
    if st.session_state.theme == 'dark':
        return """
        <style>
        .stApp {
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
            color: white;
        }
        
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        /* Keep header visible so the sidebar toggle remains accessible */
        header {visibility: visible;}

        /* Move sidebar to the right and style like a docked Copilot panel */
        [data-testid="stSidebar"] {
            visibility: visible !important;
            transform: none !important;
            min-width: 320px !important;
            width: 420px !important;
            max-width: 600px !important;
            position: fixed !important;
            right: 0;
            left: auto !important;
            top: 0;
            height: 100vh !important;
            border-left: 2px solid rgba(255,255,255,0.12);
            background: linear-gradient(180deg, rgba(17,24,39,0.95) 0%, rgba(17,24,39,0.85) 100%) !important;
            z-index: 9999;
            display: block !important;
            overflow: auto !important;
            resize: horizontal;
        }
        [data-testid="stSidebar"] > div:first-child {
            /* Ensure inner wrapper allows our panel to render fully */
            overflow: auto !important;
            height: 100%;
        }
        [data-testid="stSidebar"] [data-testid="stSidebarNav"] {
            display: none !important;
        }
        /* Give main content room on the right */
        main .block-container, .block-container { padding-right: 440px !important; }
        body { overflow-x: hidden; }

        @media (max-width: 1200px) {
            [data-testid="stSidebar"] { min-width: 280px !important; width: 320px !important; }
            main .block-container, .block-container { padding-right: 340px !important; }
        }

        /* Copilot panel visuals */
        .copilot-panel h2, .copilot-panel h3, .copilot-panel h4 { margin-top: 0; }
        .copilot-panel { 
            padding: 0; 
            display: flex; 
            flex-direction: column; 
            height: 100vh; 
            box-sizing: border-box; 
            overflow: hidden;
        }
        .copilot-header-section {
            position: sticky;
            top: 0;
            background: linear-gradient(180deg, rgba(17,24,39,0.98) 0%, rgba(17,24,39,0.95) 100%);
            padding: 12px 10px 8px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            z-index: 10;
        }
        .copilot-header {
            display: flex; align-items: center; gap: 10px;
            font-weight: 700; font-size: 1.05rem;
            color: #e5e7eb;
            margin-bottom: 6px;
        }
        .copilot-sub { color: #9ca3af; font-size: 0.85rem; margin-bottom: 8px; }
        .toolbar { display:flex; gap:8px; align-items:center; margin-top: 8px; }
        .btn-pill button { border-radius:999px !important; padding:6px 14px !important; font-weight:600; }
        
        .copilot-history { 
            flex: 1; 
            min-height: 0; 
            overflow-y: auto; 
            padding: 12px 10px; 
            display: flex; 
            flex-direction: column; 
            gap: 8px;
        }
    .copilot-msg-user { background:#1f2937; border:1px solid #374151; border-radius: 12px; padding:8px 10px; margin:6px 0; color:#e5e7eb; }
    .copilot-msg-assistant { background:#111827; border:1px solid #374151; border-radius: 12px; padding:8px 10px; margin:6px 0; color:#d1d5db; }
    .copilot-meta { font-size: 0.72rem; color:#9ca3af; margin-top:4px; }
        .copilot-input-area { 
            position: sticky; 
            bottom: 0; 
            padding: 12px 10px; 
            background: linear-gradient(180deg, rgba(17,24,39,0.0) 0%, rgba(17,24,39,0.9) 30%, rgba(17,24,39,0.98) 100%); 
            border-top: 1px solid rgba(255,255,255,0.08);
            z-index: 10;
        }
        .copilot-input-area label { color:#9ca3af; font-size:0.85rem; }

        /* Toolbar chips */
        .chip-group { display:flex; justify-content:flex-end; align-items:center; gap:6px; flex-wrap:nowrap; white-space:nowrap; }
        .chip { display:inline-flex; align-items:center; padding:3px 8px; border-radius:999px; font-size:0.78rem; line-height:1.2; }
        .chip-success { background:rgba(0,255,153,0.12); border:1px solid rgba(0,255,153,0.35); color:#bbf7d0; }
        .chip-neutral { background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.12); color:#e5e7eb; }

        /* Cards and suggestions */
        .copilot-card { background:#0f172a; border:1px solid #283144; border-radius:12px; padding:10px 12px; color:#e5e7eb; }
        .suggestions { display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
        .chip-suggest { background:#111827; border:1px solid #374151; padding:4px 8px; border-radius:999px; font-size:0.78rem; color:#d1d5db; }
        .mini-table { background:#0f172a; border:1px solid #283144; border-radius:12px; padding:8px 10px; }
        .mini-table h4 { margin:0 0 6px 0; font-size:0.9rem; color:#e5e7eb; }
        .mini-row { display:flex; justify-content:space-between; font-size:0.82rem; padding:4px 0; border-top:1px dashed #1f2937; }
        .mini-row:first-child { border-top:none; }
        
        .nav-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 1rem 2rem;
            margin: 1rem 0 2rem 0;
            text-align: center;
        }
        
        .nav-brand {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(45deg, #00f5ff, #ff00ff, #ffff00);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .glass-card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 2rem;
            margin: 1rem 0;
        }
        
        .feature-card {
            background: linear-gradient(135deg, rgba(0, 245, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 2rem;
            text-align: center;
            margin: 1rem 0;
        }
        </style>
        """
    else:
        return """
        <style>
        .stApp {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 50%, #bae6fd 100%);
            color: #1e293b;
        }
        
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        /* Keep header visible so the sidebar toggle remains accessible */
        header {visibility: visible;}

        /* Move sidebar to the right and style */
        [data-testid="stSidebar"] {
            visibility: visible !important;
            transform: none !important;
            min-width: 320px !important;
            width: 420px !important;
            max-width: 600px !important;
            position: fixed !important;
            right: 0;
            left: auto !important;
            top: 0;
            height: 100vh !important;
            border-left: 2px solid rgba(0,0,0,0.12);
            background: rgba(255,255,255,0.98) !important;
            z-index: 9999;
            display: block !important;
            overflow: auto !important;
            resize: horizontal;
        }
        [data-testid="stSidebar"] > div:first-child {
            /* Ensure inner wrapper allows our panel to render fully */
            overflow: auto !important;
            height: 100%;
        }
        [data-testid="stSidebar"] [data-testid="stSidebarNav"] {
            display: none !important;
        }
        main .block-container, .block-container { padding-right: 440px !important; }
        body { overflow-x: hidden; }
        @media (max-width: 1200px) {
            [data-testid="stSidebar"] { min-width: 280px !important; width: 320px !important; }
            main .block-container, .block-container { padding-right: 340px !important; }
        }
        
        .copilot-panel { 
            padding: 0; 
            display: flex; 
            flex-direction: column; 
            height: 100vh; 
            box-sizing: border-box; 
            overflow: hidden;
        }
        .copilot-header-section {
            position: sticky;
            top: 0;
            background: rgba(255,255,255,0.98);
            padding: 12px 10px 8px 10px;
            border-bottom: 1px solid rgba(0,0,0,0.08);
            z-index: 10;
        }
        .copilot-header { display:flex; align-items:center; gap:10px; font-weight:700; font-size:1.05rem; color:#111827; margin-bottom: 6px; }
        .copilot-sub { color:#4b5563; font-size:0.85rem; margin-bottom:8px; }
        .toolbar { display:flex; gap:8px; align-items:center; margin-top: 8px; }
        .btn-pill button { border-radius:999px !important; padding:6px 14px !important; font-weight:600; }
        
        .copilot-history { 
            flex: 1; 
            min-height: 0; 
            overflow-y: auto; 
            padding: 12px 10px; 
            display: flex; 
            flex-direction: column; 
            gap: 8px;
        }
    .copilot-msg-user { background:#eef2ff; border:1px solid #c7d2fe; border-radius:12px; padding:8px 10px; margin:6px 0; color:#1e3a8a; }
    .copilot-msg-assistant { background:#f1f5f9; border:1px solid #e2e8f0; border-radius:12px; padding:8px 10px; margin:6px 0; color:#0f172a; }
    .copilot-meta { font-size: 0.72rem; color:#64748b; margin-top:4px; }
        .copilot-input-area { 
            position: sticky; 
            bottom: 0; 
            padding: 12px 10px; 
            background: linear-gradient(180deg, rgba(255,255,255,0.0) 0%, rgba(255,255,255,0.9) 30%, rgba(255,255,255,0.98) 100%); 
            border-top: 1px solid rgba(0,0,0,0.08);
            z-index: 10;
        }
        .copilot-input-area label { color:#4b5563; font-size:0.85rem; }

    /* Toolbar chips (light) */
    .chip-group { display:flex; justify-content:flex-end; align-items:center; gap:6px; flex-wrap:nowrap; white-space:nowrap; }
    .chip { display:inline-flex; align-items:center; padding:3px 8px; border-radius:999px; font-size:0.78rem; line-height:1.2; }
    .chip-success { background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.35); color:#065f46; }
    .chip-neutral { background:rgba(2,6,23,0.06); border:1px solid rgba(2,6,23,0.08); color:#0f172a; }

    /* Cards and suggestions (light) */
    .copilot-card { background:#f1f5f9; border:1px solid #e2e8f0; border-radius:12px; padding:10px 12px; color:#0f172a; }
    .suggestions { display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
    .chip-suggest { background:#e5e7eb; border:1px solid #cbd5e1; padding:4px 8px; border-radius:999px; font-size:0.78rem; color:#0f172a; }
    .mini-table { background:#f1f5f9; border:1px solid #e2e8f0; border-radius:12px; padding:8px 10px; }
    .mini-table h4 { margin:0 0 6px 0; font-size:0.9rem; color:#0f172a; }
    .mini-row { display:flex; justify-content:space-between; font-size:0.82rem; padding:4px 0; border-top:1px dashed #cbd5e1; }
    .mini-row:first-child { border-top:none; }
        
        .nav-container {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(0, 0, 0, 0.1);
            border-radius: 20px;
            padding: 1rem 2rem;
            margin: 1rem 0 2rem 0;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }
        
        .nav-brand {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(45deg, #3b82f6, #8b5cf6, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .glass-card {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 20px;
            padding: 2rem;
            margin: 1rem 0;
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.15);
        }
        
        .feature-card {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(139, 92, 246, 0.15) 100%);
            border: 1px solid rgba(0, 0, 0, 0.2);
            border-radius: 20px;
            padding: 2rem;
            text-align: center;
        }
        </style>
        """

def render_navigation():
    """Render navigation bar"""
    theme_icon = "🌙" if st.session_state.theme == 'light' else "☀️"
    
    st.markdown("""
    <div class="nav-container">
        <div class="nav-brand">🔍 FlagSniff Pro</div>
    </div>
    """, unsafe_allow_html=True)
    
    nav_cols = st.columns([1, 1, 1, 1, 1, 1])
    
    with nav_cols[0]:
        if st.button("🔍 Analyzer", key="nav_analyzer", width="stretch", 
                      type="primary" if st.session_state.current_page == 'analyzer' else "secondary"):
            st.session_state.current_page = 'analyzer'
            st.rerun()
    
    with nav_cols[1]:
        if st.button("🤖 AI Config", key="nav_ai_config", width="stretch",
                      type="primary" if st.session_state.current_page == 'ai_config' else "secondary"):
            st.session_state.current_page = 'ai_config'
            st.rerun()
    
    with nav_cols[2]:
        if st.button("📊 Results", key="nav_results", width="stretch",
                      type="primary" if st.session_state.current_page == 'results' else "secondary"):
            st.session_state.current_page = 'results'
            st.rerun()
    
    with nav_cols[3]:
        if st.button("🚀 Advanced", key="nav_advanced", width="stretch",
                      type="primary" if st.session_state.current_page == 'advanced' else "secondary"):
            st.session_state.current_page = 'advanced'
            st.rerun()
    
    with nav_cols[4]:
        if st.button("ℹ️ About", key="nav_about", width="stretch",
                      type="primary" if st.session_state.current_page == 'about' else "secondary"):
            st.session_state.current_page = 'about'
            st.rerun()
    
    with nav_cols[5]:
        if st.button(f"{theme_icon} Theme", key="theme_toggle", width="stretch"):
            st.session_state.theme = 'light' if st.session_state.theme == 'dark' else 'dark'
            st.rerun()
    
    st.markdown("<br>", unsafe_allow_html=True)

def render_copilot_sidebar():
    """Render the Copilot chat assistant reliably using pure Streamlit widgets.
    This avoids fragile HTML/CSS-only layouts that can break with Streamlit updates.
    """
    try:
        # Ensure sidebar shows something even if styles fail
        st.sidebar.write(":mag: Copilot sidebar rendering…")

        # Lightweight, self-scoped styles to improve visuals without depending on internal Streamlit classes
        st.sidebar.markdown(
            """
            <style>
            .sb-card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 10px 12px; margin: 6px 0; }
            .sb-row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
            .sb-chip { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:0.78rem; border:1px solid rgba(255,255,255,0.12); background: rgba(255,255,255,0.06); }
            .sb-chip.green { border-color:#16a34a; background: rgba(22,163,74,0.15); color:#bbf7d0; }
            .sb-chip.blue  { border-color:#06b6d4; background: rgba(6,182,212,0.15); color:#a5f3fc; }
            .sb-chip.amber { border-color:#f59e0b; background: rgba(245,158,11,0.15); color:#fde68a; }
            .sb-msg { border-radius:12px; padding:10px 12px; margin:6px 0; }
            .sb-msg.user { background: rgba(59,130,246,0.12); border:1px solid rgba(59,130,246,0.35); }
            .sb-msg.assistant { background: rgba(99,102,241,0.12); border:1px solid rgba(99,102,241,0.35); }
            .sb-meta { font-size:0.72rem; opacity:0.75; margin-top:4px; }
            .sb-section-title { font-size:0.85rem; opacity:0.85; margin: 8px 0 6px; }
            </style>
            """,
            unsafe_allow_html=True,
        )

        # Try to read model/key status (best-effort)
        try:
            cfg = AgentConfig.load_config()
            model_name = (cfg.get('model') or 'offline').split('/')[-1]
            api_key_present = bool(cfg.get('longcat_api_key') or cfg.get('openrouter_api_key'))
        except Exception:
            model_name = 'offline'
            api_key_present = False

        # Initialize chat state
        if 'copilot_history' not in st.session_state:
            st.session_state.copilot_history = []  # [{role, content, ts}]

    # Helper to handle a query (used by Send and suggestions)
        def _handle_query(user_query: str):
            if not user_query:
                return
            st.session_state.copilot_history.append({'role': 'user', 'content': user_query, 'ts': time.time()})
            results = st.session_state.get('analysis_results')
            if not results:
                st.session_state.copilot_history.append({'role': 'assistant', 'content': "Please run an analysis first.", 'ts': time.time()})
                st.rerun()
            agent = None
            try:
                cfg_local = AgentConfig.load_config()
                api_key = cfg_local.get('longcat_api_key') or cfg_local.get('openrouter_api_key')
                model = cfg_local.get('model', 'LongCat-Flash-Chat')
                rate_handler = st.session_state.rate_limit_handler
                if model not in rate_handler.rate_limit_errors:
                    agent = create_agent(api_key, model)
            except Exception:
                agent = None
            if agent:
                plan = agent.plan_actions(user_query, results)
                answer = plan.get('answer') or ""
                actions = plan.get('actions') or []
            else:
                answer = "I'll run local searches over your results."
                actions = []
                ql = user_query.lower()
                if 'flag' in ql:
                    actions.append({'type': 'show_ctf_flags', 'params': {}})
                if 'verify' in ql and 'flag' in ql:
                    actions.append({'type': 'verify_flags', 'params': {}})
                if 'decoded' in ql or 'decode' in ql:
                    actions.append({'type': 'show_decoded', 'params': {}})
                if 'findings' in ql:
                    actions.append({'type': 'list_findings', 'params': {'limit': 10}})
            outputs = _execute_copilot_actions(actions, results, agent)
            ai_text = None
            if agent:
                try:
                    resp = agent.answer_query(user_query, results)
                    ai_text = (resp or {}).get('text')
                except Exception:
                    ai_text = None
            text_out = (ai_text or answer or '').strip()
            if outputs:
                text_out = (text_out + "\n\n" + "\n".join(outputs[:6])).strip()
            st.session_state.copilot_history.append({'role': 'assistant', 'content': text_out, 'ts': time.time()})
            st.rerun()

        # Header card with status
        st.sidebar.markdown(
            f"""
            <div class="sb-card">
                <div class="sb-row" style="justify-content:space-between;">
                    <div style="font-weight:700;">🤝 Copilot</div>
                    <span class="sb-chip {'green' if api_key_present else 'amber'}">{'Online' if api_key_present else 'Offline'}</span>
                </div>
                <div class="sb-row" style="margin-top:4px;">
                    <span class="sb-chip blue">Model: <code>{model_name}</code></span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Quick metrics when results exist
        _res_preview = st.session_state.get('analysis_results') or {}
        if _res_preview:
            f_cnt = len(_res_preview.get('findings', []) or [])
            d_cnt = len(_res_preview.get('decoded_data', []) or [])
            flags = (_res_preview.get('ctf_analysis', {}) or {}).get('flag_candidates', []) or []
            fl_cnt = len(flags)
            st.sidebar.markdown(
                f"""
                <div class="sb-card">
                  <div class="sb-row">
                    <span class="sb-chip">Findings: {f_cnt}</span>
                    <span class="sb-chip">Decoded: {d_cnt}</span>
                    <span class="sb-chip">Flags: {fl_cnt}</span>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Toolbar
        tool_cols = st.sidebar.columns([1, 1])
        if tool_cols[0].button("➕ New Chat", key="copilot_new"):
            st.session_state.copilot_history = []
            st.rerun()
        if tool_cols[1].button("🧹 Clear", key="copilot_clear"):
            st.session_state.copilot_history = []
            st.rerun()

        # History
        hist_container = st.sidebar.container()
        if st.session_state.copilot_history:
            for msg in st.session_state.copilot_history[-20:]:
                role = msg.get('role')
                prefix = "🧑‍💻" if role == 'user' else "🤖"
                ts = msg.get('ts')
                meta = ''
                if ts:
                    try:
                        meta = datetime.fromtimestamp(float(ts)).strftime('%H:%M')
                    except Exception:
                        meta = ''
                safe_text = str(msg.get('content','')).replace('<','&lt;').replace('>','&gt;')
                cls = 'user' if role == 'user' else 'assistant'
                hist_container.markdown(
                    f"""
                    <div class="sb-msg {cls}">
                        <div><strong>{prefix} {meta}</strong></div>
                        <div style="margin-top:6px;">{safe_text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            hist_container.info("Hello! I'm your PCAP Copilot. Ask me about findings, decoded data, or streams.")
            # Quick suggestions
            suggestions = ["Summarize the analysis", "List flag candidates", "Verify flags"]
            results = st.session_state.get('analysis_results') or {}
            streams = (results.get('reconstructed_streams') or {})
            if streams:
                first_id = list(streams.keys())[0]
                suggestions.append(f"Explain stream {first_id}")
            scols = hist_container.columns(min(3, max(1, len(suggestions))))
            for i, s in enumerate(suggestions):
                if scols[i % len(scols)].button(s, key=f"sugg_{i}"):
                    _handle_query(s)

        # Input
        st.sidebar.markdown('<div class="sb-section-title">Ask about this PCAP…</div>', unsafe_allow_html=True)
        q = st.sidebar.text_input("Ask about this PCAP…", key="copilot_input", placeholder="e.g., list probable flags, explain stream")
        send_cols = st.sidebar.columns([3, 1])
        if send_cols[1].button("Send", key="copilot_send"):
            _handle_query(st.session_state.get('copilot_input',''))
    except Exception as e:
        st.sidebar.error(f"Copilot error: {e}")

def _execute_copilot_actions(actions, results, agent=None):
    """Execute a small set of whitelisted actions against the current results.
    Returns a list of brief output strings for the chat.
    """
    outs = []
    actions = actions or []
    try:
        for a in actions[:6]:
            at = a.get('type')
            p = a.get('params') or {}
            if at == 'list_findings':
                limit = int(p.get('limit', 10))
                fs = results.get('findings', [])[:limit]
                outs.append(f"Findings (top {len(fs)}):")
                for f in fs:
                    outs.append(f"- {f.get('display_type', f.get('type',''))} [{f.get('confidence',0)}%]: {str(f.get('data',''))[:80]}")
            elif at == 'show_decoded':
                dec = results.get('decoded_data', [])[:10]
                outs.append(f"Decoded items (top {len(dec)}):")
                for d in dec:
                    chain = ' -> '.join(d.get('chain', [])) if d.get('chain') else ''
                    txt = (d.get('decoded') or d.get('result',''))[:120]
                    outs.append(f"- {chain}: {txt}")
            elif at == 'search_decoded':
                q = str(p.get('q','')).strip()
                if q:
                    hits = []
                    for d in results.get('decoded_data', [])[:300]:
                        text = (d.get('decoded') or d.get('result','') or '')
                        if q.lower() in str(text).lower():
                            chain = ' -> '.join(d.get('chain', [])) if d.get('chain') else ''
                            hits.append(f"{chain}: {str(text)[:100]}")
                    outs.append(f"Search in decoded '{q}' found {len(hits)} matches. Top:")
                    outs.extend([f"- {h}" for h in hits[:5]])
            elif at == 'show_ctf_flags':
                flags = (results.get('ctf_analysis', {}).get('flag_candidates', []) or [])[:10]
                outs.append(f"Flag candidates (top {len(flags)}):")
                for c in flags:
                    outs.append(f"- [{c.get('confidence',0)}%] {c.get('flag')}")
            elif at == 'show_jwts':
                toks = results.get('jwt_tokens', [])[:10]
                outs.append(f"JWT tokens (top {len(toks)}):")
                for t in toks:
                    hdr = t.get('header') or {}
                    cl = t.get('claims') or {}
                    alg = hdr.get('alg')
                    iss = cl.get('iss')
                    sub = cl.get('sub')
                    exp = cl.get('exp')
                    summary = []
                    if alg: summary.append(f"alg={alg}")
                    if iss: summary.append(f"iss={iss}")
                    if sub: summary.append(f"sub={sub}")
                    if exp: summary.append(f"exp={exp}")
                    if summary:
                        outs.append("- " + ", ".join(summary))
                    else:
                        outs.append("- " + (t.get('token','')[:60] + ('…' if len(t.get('token',''))>60 else '')))
            elif at == 'explain_stream':
                sid = str(p.get('stream_id', '')).strip()
                streams = results.get('reconstructed_streams') or {}
                if sid in streams:
                    s = streams[sid]
                    preview = ''
                    data = s.get('data', b'')
                    if isinstance(data, (bytes, bytearray)):
                        preview = data[:1200].decode('utf-8', errors='ignore')
                    else:
                        preview = str(data)[:1200]
                    if agent:
                        resp = agent.explain_stream({
                            'src_ip': s.get('src_ip',''),
                            'dst_ip': s.get('dst_ip',''),
                            'protocol': s.get('protocol','TCP'),
                            'packet_count': len(s.get('packets',[])),
                            'http_counts': {'requests': len(s.get('http_requests',[])), 'responses': len(s.get('http_responses',[]))}
                        }, preview, results.get('ctf_context'))
                        outs.append(f"Stream {sid} explanation: {str(resp)[:800]}")
                    else:
                        outs.append(f"Stream {sid}: src {s.get('src_ip','')} -> {s.get('dst_ip','')}, proto {s.get('protocol','TCP')}")
                else:
                    outs.append(f"Stream id '{sid}' not found.")
            elif at == 'extract_stream_by_id':
                sid = str(p.get('stream_id','')).strip()
                s = (results.get('reconstructed_streams') or {}).get(sid)
                if s:
                    data = s.get('data', b'')
                    if isinstance(data, (bytes, bytearray)):
                        outs.append(data[:4000].decode('utf-8', errors='ignore'))
                    else:
                        outs.append(str(data)[:4000])
                else:
                    outs.append(f"Stream id '{sid}' not found.")
            elif at == 'search_text':
                q = str(p.get('q','')).strip()
                if q:
                    hits = []
                    for f in results.get('findings', [])[:200]:
                        if q.lower() in str(f.get('data','')).lower():
                            hits.append(str(f.get('data',''))[:100])
                    outs.append(f"Search '{q}' found {len(hits)} matches in findings. Top: ")
                    outs.extend([f"- {h}" for h in hits[:5]])
            elif at == 'list_sessions':
                limit = int(p.get('limit', 10))
                sessions = results.get('sessions') or {}
                # sort by packet_count desc
                items = list(sessions.items())
                items.sort(key=lambda kv: int(kv[1].get('packet_count', 0)), reverse=True)
                items = items[:limit]
                outs.append(f"Sessions (top {len(items)}):")
                for sid, s in items:
                    src = f"{s.get('src','')}:{s.get('src_port','')}"
                    dst = f"{s.get('dst','')}:{s.get('dst_port','')}"
                    proto = s.get('protocol','')
                    cnt = s.get('packet_count',0)
                    outs.append(f"- {src} -> {dst} [{proto}] packets={cnt}")
            elif at == 'verify_flags':
                try:
                    report = None
                    if agent:
                        report = agent.verify_findings(results)
                    else:
                        # minimal local verifier
                        import re as _re
                        flags = (results.get('ctf_analysis', {}).get('flag_candidates', []) or [])
                        strict = _re.compile(r"(?i)(flag|ctf|htb|ductf|picoctf)\{[^}]+\}")
                        verified = [c for c in flags if strict.search(c.get('flag') or '')]
                        report = {
                            'verification_report': {
                                'verified_count': len(verified),
                                'adjusted': 0,
                                'items': [{'flag': c.get('flag'), 'confidence_before': c.get('confidence'), 'confidence_after': c.get('confidence'), 'checks': ['pattern_ok']} for c in verified]
                            }
                        }
                    if isinstance(report, dict):
                        if report.get('ctf_analysis'):
                            results['ctf_analysis'] = report['ctf_analysis']
                        vr = report.get('verification_report') or {}
                        outs.append(f"Verification: {vr.get('verified_count',0)} verified, {vr.get('adjusted',0)} adjusted.")
                        for itm in (vr.get('items') or [])[:5]:
                            outs.append(f"- {itm.get('flag')} [{itm.get('confidence_after', itm.get('confidence_before'))}%]")
                except Exception as _e:
                    outs.append(f"Verification failed: {_e}")
            elif at == 'decode_text':
                # Try reusing analyzer's beam via a crafted packet
                try:
                    analyzer = WebPcapAnalyzer()
                    pkt = [{'data': p.get('data',''), 'protocol': 'CHAT', 'packet_index': 0}]
                    res = analyzer._decode_potential_data(pkt)
                    if res:
                        best = res[0]
                        outs.append(f"Decoded via {' -> '.join(best.get('chain',[]))}: {(best.get('decoded') or best.get('result',''))[:200]}")
                    else:
                        outs.append("No decode candidates found.")
                except Exception as e:
                    outs.append(f"Decode failed: {e}")
            elif at == 'reanalyze_full':
                # Safely re-run the main analyzer on the last uploaded PCAP using saved options
                try:
                    import os
                    last_path = st.session_state.get('last_pcap_path')
                    search_opts = st.session_state.get('last_search_options') or {}
                    custom_regex = st.session_state.get('last_custom_regex')
                    user_key = st.session_state.get('last_user_decrypt_key')
                    tls_keylog = st.session_state.get('last_tls_keylog_path')
                    if last_path and os.path.exists(last_path):
                        analyzer = WebPcapAnalyzer()
                        new_res = analyzer.analyze_file(last_path, search_opts, custom_regex, user_decrypt_key=user_key, tls_keylog_file=tls_keylog)
                        # Preserve CTF context if present
                        if st.session_state.get('analysis_results', {}).get('ctf_context'):
                            new_res['ctf_context'] = st.session_state['analysis_results']['ctf_context']
                        st.session_state.analysis_results = new_res
                        outs.append("Full re-analysis completed.")
                    else:
                        outs.append("No saved PCAP path available to reanalyze. Please upload and analyze a PCAP first.")
                except Exception as e:
                    outs.append(f"Re-analysis failed: {e}")
            elif at == 'tshark_summary':
                # Run the optional tshark pre-analysis only and merge into results
                try:
                    import os
                    from apps.tshark_ai import run_tshark_analysis, tshark_available
                    last_path = st.session_state.get('last_pcap_path')
                    if last_path and os.path.exists(last_path) and tshark_available():
                        tsh = run_tshark_analysis(last_path, ai_agent=agent)
                        results['tshark_summary'] = tsh
                        outs.append("tshark pre-analysis completed and added to results.")
                    else:
                        outs.append("tshark not available or no PCAP path saved.")
                except Exception as e:
                    outs.append(f"tshark run failed: {e}")
            elif at == 'auto_decode_hunt':
                # Run offline decode hunt to try more decoders; merge deduped results
                try:
                    from ai.ai_agent import FlagSniffAgent
                    local_agent = agent or FlagSniffAgent(api_key='offline', model='offline')
                    new_dec = local_agent.auto_decode_hunt(results) if hasattr(local_agent, 'auto_decode_hunt') else []
                    if new_dec:
                        seen_pairs = set((d.get('original',''), d.get('decoded','')) for d in results.get('decoded_data', []))
                        merged = 0
                        for d in new_dec:
                            key = (d.get('original',''), d.get('decoded',''))
                            if key not in seen_pairs and d.get('decoded'):
                                results.setdefault('decoded_data', []).append(d)
                                seen_pairs.add(key)
                                merged += 1
                        outs.append(f"Auto decode hunt added {merged} new decoded items.")
                    else:
                        outs.append("Auto decode hunt found no new decodes.")
                except Exception as e:
                    outs.append(f"Auto decode hunt failed: {e}")
            # else: silently ignore unknown types
    except Exception as e:
        outs.append(f"Execution error: {e}")
    return outs

def render_hero():
    """Render hero section"""
    st.markdown("""
    <div style="text-align: center; padding: 4rem 2rem; background: linear-gradient(135deg, rgba(0, 245, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%); border-radius: 30px; margin: 2rem 0;">
        <h1 style="font-size: 3.5rem; font-weight: 700; background: linear-gradient(45deg, #00f5ff, #ff00ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 1rem;">Next-Gen PCAP Analysis</h1>
        <p style="font-size: 1.3rem; margin-bottom: 0;">Powered by Advanced AI • Built for Security Professionals • Optimized for CTF</p>
    </div>
    """, unsafe_allow_html=True)

def render_analyzer_page():
    """Render main analyzer page"""
    
    # Rate limit status banner
    rate_handler = st.session_state.rate_limit_handler
    if rate_handler.rate_limit_errors:
        st.warning("⚠️ **AI Service Notice**: Some AI models are experiencing rate limits. Offline analysis features remain fully functional and will provide comprehensive results.")
        
        # Show quick status
        with st.expander("📊 AI Service Status", expanded=False):
            available_count = len(rate_handler.get_available_models())
            total_count = len(rate_handler.fallback_models)
            st.info(f"🟢 Available: {available_count}/{total_count} models")
            st.info("💡 Visit AI Config page to switch models or wait for rate limits to reset")
    
    # Feature cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🚩</div>
            <div style="font-size: 1.3rem; font-weight: 600; margin-bottom: 0.5rem;">Flag Hunter</div>
            <div style="font-size: 0.9rem;">Advanced pattern recognition for CTF flags</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🔐</div>
            <div style="font-size: 1.3rem; font-weight: 600; margin-bottom: 0.5rem;">Credential Extractor</div>
            <div style="font-size: 0.9rem;">Detect passwords, tokens, and API keys</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <div style="font-size: 3rem; margin-bottom: 1rem;">🤖</div>
            <div style="font-size: 1.3rem; font-weight: 600; margin-bottom: 0.5rem;">AI Analysis</div>
            <div style="font-size: 0.9rem;">Machine learning powered insights</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="feature-card">
            <div style="font-size: 3rem; margin-bottom: 1rem;">⚡</div>
            <div style="font-size: 1.3rem; font-weight: 600; margin-bottom: 0.5rem;">Real-time</div>
            <div style="font-size: 0.9rem;">Lightning fast processing</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Main analyzer interface
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    st.markdown("### 📁 Upload PCAP File")
    uploaded_file = st.file_uploader(
        "Choose your PCAP file",
        type=['pcap', 'pcapng'],
        help="Upload .pcap or .pcapng files for analysis"
    )
    
    st.markdown("### 🔍 Display Filter")
    display_filter = st.text_input(
        "Enter a display filter (e.g., 'ip.addr == 1.2.3.4')",
        placeholder="ip.addr == 1.2.3.4",
        help="Use Wireshark-like syntax to filter packets before analysis."
    )

    if uploaded_file:
        st.success(f"✅ File loaded: {uploaded_file.name} ({uploaded_file.size:,} bytes)")
        
        # Analysis options
        st.markdown("### ⚙️ Analysis Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🎯 Search Targets**")
            search_flags = st.checkbox("🚩 CTF Flags", value=True)
            search_creds = st.checkbox("🔐 Credentials", value=True)
            search_tokens = st.checkbox("🎫 API Tokens", value=True)
            search_emails = st.checkbox("📧 Email Addresses", value=False)
            search_hashes = st.checkbox("🔒 Hash Values", value=False)
            
            st.markdown("**🏆 Analysis Mode**")
            ctf_mode = st.checkbox("🎯 CTF Challenge Mode", value=True, help="Enable advanced CTF-specific analysis techniques")
        
        with col2:
            st.markdown("**🤖 AI Configuration**")
            
            if IMPORTS_OK:
                try:
                    current_api_key = AgentConfig.get_api_key()
                    ai_enabled = current_api_key is not None
                    
                    if ai_enabled:
                        current_config = AgentConfig.load_config()
                        current_model = current_config.get('model', 'LongCat-Flash-Chat')
                        
                        # Check rate limit status
                        rate_handler = st.session_state.rate_limit_handler
                        if current_model in rate_handler.rate_limit_errors:
                            st.error(f"🔴 AI Agent Rate Limited - Model: {current_model.split('/')[-1]}")
                            st.info("💡 Switch to another model in AI Config or use offline analysis")
                            st.info("🔄 Offline analysis will still provide comprehensive results with pattern matching and protocol analysis")
                            ai_enabled = False
                        else:
                            st.success(f"🟢 AI Agent Online - Model: {current_model.split('/')[-1]}")
                        
                        if ai_enabled:
                            ai_mode = st.selectbox(
                                "Analysis Mode",
                                [
                                    "🧠 Enhanced Analysis (Multi-Model Ensemble)", 
                                    "🎯 Deep Flag Hunt (Specialized Agent)", 
                                    "🔬 Protocol Analysis (Security Expert)", 
                                    "🔐 Credential Hunt (Auth Specialist)",
                                    "🧠 Behavioral Analysis (Anomaly Detection)",
                                    "📊 Standard Only"
                                ],
                                help="Choose your AI analysis strategy"
                            )
                            
                            confidence_threshold = st.slider("Confidence Threshold", 0, 100, 70)
                        else:
                            ai_mode = "📊 Standard Only"
                            confidence_threshold = 70
                    
                    else:
                        st.warning("🔴 AI Agent Offline - Configure API key to enable AI features")
                        ai_mode = "📊 Standard Only"
                        confidence_threshold = 70
                except Exception as e:
                    st.error(f"AI configuration error: {e}")
                    ai_enabled = False
                    ai_mode = "📊 Standard Only"
                    confidence_threshold = 70
            else:
                st.warning("🔴 AI features unavailable - Import error")
                ai_enabled = False
                ai_mode = "📊 Standard Only"
                confidence_threshold = 70
        
        # TLS decryption (Optional)
        st.markdown("**🔐 TLS Decryption (Optional)**")
        use_tls_keylog = st.checkbox(
            "Use TLS key log for decryption (SSLKEYLOGFILE)", value=False,
            help="Upload a NSS/SSL key log file to decrypt TLS in the PCAP (requires tshark/pyshark)."
        )
        tls_keylog_upload = None
        if use_tls_keylog:
            tls_keylog_upload = st.file_uploader(
                "Upload TLS key log file",
                type=["log", "txt", "keylog"],
                help="File containing lines like 'CLIENT_RANDOM <random> <secret>'"
            )

        # Custom regex
        st.markdown("### 🎯 Custom Pattern")
        custom_regex = st.text_input(
            "Custom Regex Pattern",
            placeholder="flag\\{.*?\\}",
            help="Enter your custom regex pattern for specialized searches"
        )

        # User-supplied decryption key/password
        st.markdown("### 🛡️ Decryption Key/Password (Optional)")
        user_decrypt_key = st.text_input(
            "Decryption Key or Password",
            placeholder="Enter key/password for encrypted data (optional)",
            help="If you suspect encrypted data, provide a key or password to attempt decryption."
        )

        # TLS Decryption (Optional)
        st.markdown("### 🔐 TLS Decryption (Optional)")
        st.caption("Provide a TLS key log (SSLKEYLOGFILE format) to attempt HTTPS decryption. Requires tshark/pyshark available on the system.")
        use_tls_keylog = st.checkbox("Use TLS key log for decryption", value=False)
        tls_keylog_upload = None
        if use_tls_keylog:
            tls_keylog_upload = st.file_uploader(
                "Upload TLS key log file",
                type=["log", "txt", "keylog"],
                help="A text file with lines like 'CLIENT_RANDOM <random> <secret>'."
            )

        # YARA Rules
        st.markdown("### 룰 YARA Rules (Optional)")
        yara_rules_upload = st.file_uploader(
            "Upload YARA rule files",
            type=['yar', 'yara'],
            accept_multiple_files=True,
            help="Upload .yar or .yara files for custom signature matching."
        )

        # Optional: AI-assisted TShark pre-analysis
        st.markdown("### 🦈 AI-Assisted TShark Pre-Analysis (Optional)")
        # Persist toggle in session state
        if 'use_tshark_ai' not in st.session_state:
            st.session_state.use_tshark_ai = False
        use_tshark_ai = st.checkbox(
            "Enable AI-assisted TShark pre-analysis (if installed)",
            value=st.session_state.use_tshark_ai,
            key="use_tshark_ai",
            help="Runs a brief, strictly sanitized tshark pass to summarize HTTP and DNS. Safe, JSON-only, and optional."
        )
        # Availability hint
        try:
            from apps.tshark_ai import tshark_available as _tshark_available
            _avail = _tshark_available()
            if _avail:
                st.caption("🟢 tshark detected")
            else:
                st.caption("🔴 tshark not found - this pre-analysis will be skipped")
        except Exception:
            st.caption("ℹ️ tshark availability unknown (module import issue)")
        
        # CTF Challenge Context
        st.markdown("### 🏆 CTF Challenge Context")
        col1, col2 = st.columns(2)
        
        with col1:
            challenge_description = st.text_area(
                "Challenge Description",
                placeholder="e.g., 'Find the hidden flag in network traffic. The admin mentioned something about DNS...'",
                help="Describe the CTF challenge, any hints, or context clues",
                height=100
            )
        
        with col2:
            challenge_hints = st.text_area(
                "Additional Hints/Clues",
                placeholder="e.g., 'Look for base64 encoding', 'Check HTTP headers', 'Steganography involved'",
                help="Any additional hints, clues, or specific techniques mentioned",
                height=100
            )
        
        challenge_category = st.selectbox(
            "Challenge Category (Optional)",
            [
                "🔍 General Analysis",
                "🌐 Web Exploitation", 
                "🔐 Cryptography",
                "🕵️ Steganography",
                "🌍 Network Analysis",
                "🔓 Reverse Engineering",
                "📡 Forensics",
                "🎭 Social Engineering"
            ],
            help="Select the challenge category to help AI focus its analysis"
        )
        
        # Analysis button
        st.markdown("---")
        
        # Analysis mode indicator
        if not ai_enabled and rate_handler.rate_limit_errors:
            st.info("🔄 **Analysis Mode**: Offline Analysis (AI services temporarily unavailable)")
        elif ai_enabled:
            st.success("🤖 **Analysis Mode**: AI-Enhanced Analysis")
        else:
            st.info("📊 **Analysis Mode**: Standard Analysis")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🚀 START ANALYSIS", key="analyze_btn", width="stretch"):
                if IMPORTS_OK:
                    ctf_context = {
                        'description': challenge_description,
                        'hints': challenge_hints,
                        'category': challenge_category
                    }
                    
                    yara_rule_paths = []
                    if yara_rules_upload:
                        for rule_file in yara_rules_upload:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.yar') as tmp_rule_file:
                                tmp_rule_file.write(rule_file.getvalue())
                                yara_rule_paths.append(tmp_rule_file.name)

                    run_analysis(uploaded_file, {
                        'flags': search_flags,
                        'credentials': search_creds,
                        'tokens': search_tokens,
                        'emails': search_emails,
                        'hashes': search_hashes,
                        'ctf_mode': ctf_mode,
                        'tshark_ai': use_tshark_ai
                    }, custom_regex, ai_mode, ai_enabled, confidence_threshold, ctf_context, user_decrypt_key, tls_keylog_upload, display_filter, yara_rule_paths)
                else:
                    st.error("Cannot run analysis - Import error detected")
    
    else:
        # Upload area
        st.markdown("""
        <div style="border: 2px dashed rgba(0, 245, 255, 0.5); border-radius: 20px; padding: 3rem; text-align: center; background: rgba(0, 245, 255, 0.05);">
            <div style="font-size: 3rem; margin-bottom: 1rem;">📁</div>
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">Drop your PCAP file here</div>
            <div style="color: rgba(255, 255, 255, 0.7);">Supports .pcap and .pcapng formats</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Offline analysis info
        if rate_handler.rate_limit_errors:
            st.info("💡 **Offline Analysis Available**: Even when AI services are rate limited, you can still analyze PCAP files with advanced pattern matching, protocol analysis, and CTF-specific detection algorithms.")
        
        # Demo buttons
        st.markdown("### 🎮 Try Demo")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🧪 Standard Demo", width="stretch"):
                if IMPORTS_OK:
                    run_demo_analysis(False)
                else:
                    st.error("Demo unavailable - Import error")
        
        with col2:
            if st.button("🤖 AI Demo", width="stretch", disabled=not IMPORTS_OK or not AgentConfig.get_api_key()):
                if IMPORTS_OK:
                    run_demo_analysis(True)
                else:
                    st.error("Demo unavailable - Import error")
        
        with col3:
            if st.button("🔍 Deep Hunt Demo", width="stretch", disabled=not IMPORTS_OK or not AgentConfig.get_api_key()):
                if IMPORTS_OK:
                    run_demo_analysis(True, "deep_hunt")
                else:
                    st.error("Demo unavailable - Import error")
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_ai_config_page():
    """Render AI configuration page"""
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    st.markdown("### 🤖 AI Agent Configuration")
    
    if not IMPORTS_OK:
        st.error("AI configuration unavailable - Import error detected")
        st.markdown('</div>', unsafe_allow_html=True)
        return
    
    # Rate limit status and handling
    rate_handler = st.session_state.rate_limit_handler
    available_models = rate_handler.get_available_models()
    
    if rate_handler.rate_limit_errors:
        st.warning("⚠️ Some AI models are experiencing rate limits. Available models are highlighted below.")
        
        # Show rate limit errors
        with st.expander("🚫 Rate Limit Status", expanded=False):
            for model, error_info in rate_handler.rate_limit_errors.items():
                time_since_error = int(time.time() - error_info['timestamp'])
                if time_since_error < 300:  # 5 minutes
                    st.error(f"❌ {model}: Rate limited ({300 - time_since_error}s until retry)")
                else:
                    st.info(f"✅ {model}: Available for retry")
        
        # Reset button
        if st.button("🔄 Reset Rate Limit Status"):
            rate_handler.reset_errors()
            st.rerun()
    
    # Free models highlight with availability status
    if available_models:
        st.success(f"🆓 FREE AI Models Available! {len(available_models)} models ready to use.")
    else:
        st.warning("⚠️ All free models are currently rate limited. Please wait a few minutes or use offline analysis.")
    
    # Current status
    try:
        current_config = AgentConfig.load_config()
        current_api_key = AgentConfig.get_api_key()
        current_model = current_config.get('model', 'LongCat-Flash-Chat')
        
        if current_api_key:
            # Check if current model is rate limited
            if current_model in rate_handler.rate_limit_errors:
                st.error(f"🔴 Current Model Rate Limited: {current_model}")
                st.info("💡 Switch to an available model below or wait for rate limit to reset.")
            else:
                st.success(f"🟢 AI Agent Configured - Model: {current_model}")
            
            # Model change section
            st.markdown("### 🔄 Change AI Model")
            
            model_options = {
                "LongCat-Flash-Chat": "⚡ LongCat Flash Chat - Fast & optimized (Default)",
                "gpt-3.5-turbo": "🚀 GPT-3.5 Turbo - Fast & efficient",
                "gpt-4-turbo": "🧠 GPT-4 Turbo - Advanced reasoning",
                "gpt-4o": "🎯 GPT-4o - Latest flagship model",
                "claude-3-opus": "🔍 Claude 3 Opus - Deep analysis"
            }
            
            # Filter models by availability
            available_model_keys = [key for key in model_options.keys() if key not in rate_handler.rate_limit_errors]
            
            if available_model_keys:
                selected_model = st.selectbox(
                    "Select AI Model",
                    available_model_keys,
                    format_func=lambda x: f"{model_options[x]} {'✅' if x not in rate_handler.rate_limit_errors else '❌'}",
                    index=available_model_keys.index(current_model) if current_model in available_model_keys else 0
                )
                
                # Show model status
                if selected_model in rate_handler.rate_limit_errors:
                    st.error(f"⚠️ This model is currently rate limited. Consider choosing another model.")
                
                if st.button("🔄 CHANGE MODEL", width="stretch", disabled=selected_model == current_model):
                    current_config['model'] = selected_model
                    current_config['setup_date'] = datetime.now().isoformat()
                    AgentConfig.save_config(current_config)
                    st.success(f"✅ Model changed to: {model_options[selected_model]}")
                    st.rerun()
            else:
                st.error("❌ All models are currently rate limited. Please wait a few minutes before trying again.")
                st.info("💡 You can still use offline analysis features while waiting.")
                
        else:
            st.warning("🔴 AI Agent Not Configured")
            
            # Initial setup form
            st.markdown("### ⚙️ Initial Setup")
            
            api_key_input = st.text_input(
                "LongCat API Key",
                type="password",
                value="",
                help="Get your API key from https://longcat.chat/platform/",
                placeholder="lc-..."
            )
            
            if api_key_input:
                if st.button("🧪 Test API Key"):
                    with st.spinner("Testing API connection..."):
                        try:
                            test_agent = create_agent(api_key_input, "LongCat-Flash-Chat")
                            if test_agent:
                                st.success("✅ API key is valid!")
                            else:
                                st.error("❌ API key test failed")
                        except Exception as e:
                            st.error(f"❌ Test failed: {str(e)}")
                
                if st.button("💾 SAVE API KEY", width="stretch"):
                    config = {
                        'longcat_api_key': api_key_input,
                        'model': 'LongCat-Flash-Chat',
                        'api_endpoint': 'https://api.longcat.chat/openai/v1/chat/completions',
                        'setup_date': datetime.now().isoformat(),
                        'version': '2.0',
                        'provider': 'longcat'
                    }
                    AgentConfig.save_config(config)
                    st.success("✅ Configuration saved successfully!")
                    st.rerun()
    
    except Exception as e:
        st.error(f"AI configuration error: {e}")
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_results_page():
    """Render results page"""
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        st.markdown("### 📊 Analysis Results")

        # Summary metrics
        col1, col2, col3, col4, col5, col6 = st.columns(6)

        with col1:
            st.metric("Total Packets", f"{results.get('total_packets', 0):,}")

        with col2:
            st.metric("Analyzed Packets", f"{results.get('analyzed_packets', 0):,}")

        with col3:
            findings_count = len(results.get('findings', []))
            st.metric("Standard Findings", findings_count)

        with col4:
            ctf_findings_count = len(results.get('ctf_findings', []))
            st.metric("CTF Findings", ctf_findings_count)

        # Decoding/decryption summary badges
        decoded_data = results.get('decoded_data') or []
        try:
            tls_count = sum(1 for d in decoded_data if str(d.get('type','')).lower() in ("tls_decrypted", "tls", "https_tls"))
            dns_exfil_count = sum(1 for d in decoded_data if str(d.get('type','')).lower() in ("dns_exfil", "dns-exfil", "dns_exfiltration"))
        except Exception:
            tls_count = 0
            dns_exfil_count = 0

        with col5:
            st.metric("Decrypted TLS", tls_count)
        with col6:
            st.metric("DNS exfil decoded", dns_exfil_count)
        
        # CTF Challenge Context Display
        if results.get('ctf_context'):
            ctf_ctx = results['ctf_context']
            if ctf_ctx.get('description') or ctf_ctx.get('hints'):
                st.markdown("---")
                st.markdown("### 🏆 CTF Challenge Context")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if ctf_ctx.get('description'):
                        st.info(f"📝 Challenge Description: {ctf_ctx['description']}")
                
                with col2:
                    if ctf_ctx.get('hints'):
                        st.info(f"💡 Hints & Clues: {ctf_ctx['hints']}")
        
        # Tracking Pixels panel moved into Findings tab

        # Tabbed layout for results
        st.markdown("---")
        tab_labels = [
            "🔍 Findings", "🔄 Streams", "🗣️ Sessions", "🧩 Protocols", "🤖 AI", "📈 Visuals",
            "🕒 Timeline", "🗂️ Files", "🔁 Replay", "🛡️ Crypto", "🎯 CTF Analysis", "🗄️ Database", "🦠 Malware", "🛡️ YARA", "📥 Export"
        ]
        tabs = st.tabs(tab_labels)
        
        # CTF Specific Analysis Tab
        with tabs[10]:
            if results.get('ctf_analysis'):
                st.markdown("### 🎯 CTF Analysis Results")
                
                # Get CTF-specific data
                ctf_findings = results['ctf_analysis'].get('flag_candidates', [])
                ctf_metadata = results['ctf_analysis'].get('metadata', {})
                ver_report = results.get('verification_report') or {}
                
                # Display metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Flags Found", len(ctf_findings))
                with col2:
                    unique_patterns = len(set(f.get('pattern', '') for f in ctf_findings))
                    st.metric("Patterns Identified", unique_patterns)
                with col3:
                    protocol = ctf_metadata.get('primary_protocol', 'N/A')
                    st.metric("Key Protocol", protocol)

                # Verification summary (if present)
                if ver_report:
                    vc = ver_report.get('verified_count', 0)
                    adj = ver_report.get('adjusted', 0)
                    st.info(f"✅ Verified flags: {vc}  •  🔧 Confidence adjusted: {adj}")
                
                # Display flag results
                if ctf_findings:
                    st.markdown("#### 🏁 Flag Candidates")
                    
                    for i, flag in enumerate(ctf_findings):
                        confidence = flag.get('confidence', 70)
                        
                        # Set colors based on confidence
                        bg_color = "#00ff8810" if confidence >= 85 else "#ffaa0010" if confidence >= 70 else "#ff444410"
                        border_color = "#00ff88" if confidence >= 85 else "#ffaa00" if confidence >= 70 else "#ff4444"
                        conf_text = "High Confidence" if confidence >= 85 else "Medium Confidence" if confidence >= 70 else "Potential Match"

                        # Chain chip + ops badge (if decoding_chain present)
                        chain = flag.get('decoding_chain') or []
                        chain_chip = ""
                        if chain:
                            chain_str = " → ".join(chain[:6]) + (" …" if len(chain) > 6 else "")
                            ops = len(chain)
                            border_rgb = '#00f5ff' if ops <= 1 else ('#1fe4a6' if ops == 2 else '#00d48c')
                            chain_chip = (
                                f"<span style='display:inline-block;background:rgba(0,245,255,0.12);"
                                f"border:1px solid {border_rgb};padding:2px 8px;border-radius:12px;"
                                f"font-size:0.75rem;margin-left:8px;'>chain: {chain_str}</span>"
                            )
                            ops_chip = (
                                f"<span style='display:inline-block;background:rgba(0,255,136,0.10);"
                                f"border:1px solid {border_rgb};padding:2px 6px;border-radius:10px;"
                                f"font-size:0.70rem;margin-left:6px;'>ops: {ops}</span>"
                            )
                            chain_chip = chain_chip + ops_chip

                        # Verification badge
                        ver = flag.get('verification') or {}
                        ver_badge = ""
                        if isinstance(ver, dict):
                            if ver.get('verified'):
                                ver_badge = (
                                    "<span style=\"display:inline-block;background:rgba(0,255,136,0.14);"
                                    "border:1px solid #00ff88;padding:2px 8px;border-radius:12px;"
                                    "font-size:0.75rem;margin-left:8px;\">Verified</span>"
                                )
                            else:
                                ver_badge = (
                                    "<span style=\"display:inline-block;background:rgba(255,255,255,0.08);"
                                    "border:1px solid rgba(255,255,255,0.25);padding:2px 8px;border-radius:12px;"
                                    "font-size:0.75rem;margin-left:8px;\">Unverified</span>"
                                )
                        
                        st.markdown(f"""
                        <div style="background: {bg_color}; border: 1px solid {border_color}; border-radius: 15px; padding: 1.2rem; margin: 1rem 0;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem;">
                                <div style="font-size: 1.2rem; font-weight: 600; word-break: break-all;">
                                    {flag.get('flag', 'No flag data')} {chain_chip} {ver_badge}
                                </div>
                                <div style="background: {border_color}44; padding: 0.3rem 0.8rem; border-radius: 15px; font-weight: 600;">
                                    {confidence}% Confidence
                                </div>
                            </div>
                            
                            <div style="color: rgba(255, 255, 255, 0.7); margin-bottom: 0.8rem;">
                                <strong>Pattern:</strong> {flag.get('pattern', 'N/A')} | 
                                <strong>Protocol:</strong> {flag.get('protocol', 'N/A')} | 
                                <strong>Packet:</strong> {flag.get('packet_number', 'N/A')}
                            </div>
                            
                            {f'<div style="background: rgba(0, 245, 255, 0.05); padding: 0.8rem; border-radius: 8px; margin-top: 0.8rem; border-left: 3px solid #00f5ff;">'
                              f'<div style="font-size: 0.9rem; color: #00f5ff; margin-bottom: 0.5rem;">AI Analysis</div>'
                              f'<div>{flag.get("ai_analysis", "")}</div>'
                              f'</div>' if flag.get('ai_analysis') else ''}
                        </div>
                        """, unsafe_allow_html=True)

                        # Verification details expander
                        if isinstance(ver, dict) and (ver.get('checks') or ver.get('evidence')):
                            with st.expander("Verification details"):
                                st.markdown("**Checks:**")
                                for c in (ver.get('checks') or []):
                                    st.write(f"- {c}")
                                if ver.get('evidence'):
                                    st.markdown("**Evidence:**")
                                    st.json(ver.get('evidence'))
                else:
                    st.info("🔍 No specific flags detected. Try adding challenge context for better CTF analysis.")
            else:
                st.info("CTF analysis results not available. Run analysis with CTF mode enabled.")

        # Findings Tab
        with tabs[0]:
            if results.get('findings'):
                st.markdown("### 🔍 Detected Findings")
                min_conf = st.slider("Minimum confidence to display", 0, 100, 20, key="findings_min_conf")
                filtered_findings = [f for f in results['findings'] if f.get('confidence', 90) >= min_conf]

                # Optional prioritization by decode-chain strength
                prioritize_chain = st.checkbox("Prioritize decode-chain findings", value=True, key="findings_prioritize_chain")
                if prioritize_chain:
                    def chain_strength(f):
                        chain = f.get('decoding_chain') or []
                        base = len(chain)
                        # Bonus if decoded confidence attached
                        bonus = f.get('decoded_confidence', 0) if isinstance(f.get('decoded_confidence'), (int, float)) else 0
                        return (1 if chain else 0, base, bonus)
                    filtered_findings = sorted(filtered_findings, key=lambda f: (chain_strength(f), f.get('confidence', 0)), reverse=True)
                else:
                    filtered_findings = sorted(filtered_findings, key=lambda f: f.get('confidence', 0), reverse=True)
                if not filtered_findings:
                    st.info("No findings at or above the selected confidence.")
                for i, finding in enumerate(filtered_findings[:20]):
                    confidence = finding.get('confidence', 50)
                    if confidence >= 80:
                        border_color = "#00ff88"
                    elif confidence >= 60:
                        border_color = "#ffaa00"
                    else:
                        border_color = "#ff4444"
                    # Compact chain chip if available
                    chain = finding.get('decoding_chain') or []
                    chain_chip = ""
                    if chain:
                        chain_str = " → ".join(chain[:6]) + (" …" if len(chain) > 6 else "")
                        # Simple chain-aware color (more ops = slightly greener border)
                        ops = len(chain)
                        border_rgb = '#00f5ff' if ops <= 1 else ('#1fe4a6' if ops == 2 else '#00d48c')
                        chain_chip = (
                            f"<span style='display:inline-block;background:rgba(0,245,255,0.12);"
                            f"border:1px solid {border_rgb};padding:2px 8px;border-radius:12px;"
                            f"font-size:0.75rem;margin-left:8px;'>chain: {chain_str}</span>"
                        )
                        # Add tiny ops badge
                        ops_chip = (
                            f"<span style='display:inline-block;background:rgba(0,255,136,0.10);"
                            f"border:1px solid {border_rgb};padding:2px 6px;border-radius:10px;"
                            f"font-size:0.70rem;margin-left:6px;'>ops: {ops}</span>"
                        )
                        chain_chip = chain_chip + ops_chip
                    # Source badge (e.g., tshark)
                    via_val = finding.get('via') or finding.get('source')
                    source_chip = ""
                    try:
                        if isinstance(via_val, str) and 'tshark' in via_val.lower():
                            source_chip = (
                                "<span style='display:inline-block;background:rgba(255,255,255,0.08);"
                                "border:1px solid rgba(255,255,255,0.25);padding:2px 6px;border-radius:10px;"
                                "font-size:0.70rem;margin-left:6px;'>tshark</span>"
                            )
                    except Exception:
                        source_chip = ""
                    safe_data = html.escape(str(finding.get('data', 'No data'))[:300])
                    ell = '...' if len(str(finding.get('data',''))) > 300 else ''
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, rgba(0, 255, 136, 0.08) 0%, rgba(0, 245, 255, 0.08) 100%); border: 1px solid {border_color}; border-radius: 15px; padding: 1.5rem; margin: 1rem 0; border-left: 4px solid {border_color};">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <div style="font-weight: 600; font-size: 1.1rem;">
                                {finding.get('icon', '🔍')} {finding.get('display_type', 'Finding')} {source_chip} {chain_chip}
                            </div>
                            <div style="background: rgba(0, 245, 255, 0.2); padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem;">
                                {confidence}% confidence
                            </div>
                        </div>
                        <div style="font-family: monospace; background: rgba(0, 0, 0, 0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0; white-space: pre-wrap;">
                            {safe_data}{ell}
                        </div>
                        <div style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.7);">
                            <strong>Protocol:</strong> {finding.get('protocol', 'Unknown')} | 
                            <strong>Source:</strong> {finding.get('src_ip', finding.get('src', 'N/A'))} → {finding.get('dst_ip', finding.get('dst', 'N/A'))}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if finding.get('stream_id'):
                        def follow_stream_callback(stream_id):
                            st.session_state.followed_stream = stream_id
                            st.session_state.current_page = 'results' # Ensure we are on the results page
                            st.rerun()

                        st.button("Follow Stream", key=f"follow_stream_{i}", on_click=follow_stream_callback, args=(finding['stream_id'],))

                    if finding.get('protocol') == 'HTTP':
                        with st.expander(f"HTTP Details for Finding #{i+1}"):
                            if finding.get('http_headers'):
                                st.markdown("**HTTP Headers:**")
                                st.code(finding['http_headers'], language="http")
                            if finding.get('http_body'):
                                st.markdown("**HTTP Body:**")
                                st.code(finding['http_body'], language="text")
                            if finding.get('http_method') or finding.get('http_path'):
                                st.markdown(f"**Request:** {finding.get('http_method', '')} {finding.get('http_path', '')}")
                            if finding.get('credentials'):
                                st.markdown("**Extracted Credentials:**")
                                for cred in finding['credentials']:
                                    st.json(cred)
                    if finding.get('decoded'):
                        with st.expander(f"Decoded/Decrypted Data for Finding #{i+1}"):
                            st.markdown("**Decoded/Decrypted Data:**")
                            st.code(finding['decoded'], language="text")
                            if finding.get('decode_method'):
                                st.markdown(f"**Method:** {finding['decode_method']}")
                    if finding.get('stream_id') or finding.get('tcp_stream'):
                        with st.expander(f"Stream Context for Finding #{i+1}"):
                            st.markdown(f"**Stream ID:** {finding.get('stream_id', finding.get('tcp_stream', 'N/A'))}")
                            if finding.get('stream_data'):
                                st.code(finding['stream_data'][:1000], language="text")
                    if finding.get('flag_chunks'):
                        with st.expander(f"Flag Reassembly for Finding #{i+1}"):
                            st.markdown("**Flag Chunks:**")
                            for chunk in finding['flag_chunks']:
                                st.code(chunk, language="text")
                            if finding.get('reassembled_flag'):
                                st.success(f"Reassembled Flag: {finding['reassembled_flag']}")
                    # PoC / Reproduction details
                    if finding.get('poc'):
                        with st.expander(f"🔧 PoC & Reproduction for Finding #{i+1}"):
                            poc = finding.get('poc') or {}
                            where = poc.get('where_found') or {}
                            steps = poc.get('extraction_steps') or []
                            if where:
                                st.markdown("**Where Found:**")
                                st.write(
                                    f"- Frame: {where.get('frame_number', (finding.get('packet_index', 0) or 0) + 1)}  "
                                    f"| Packet Index: {where.get('packet_index', finding.get('packet_index',''))}  "
                                    f"| Protocol: {where.get('protocol', finding.get('protocol','Unknown'))}  "
                                )
                                st.write(f"- Source → Dest: {where.get('src_ip', finding.get('src_ip',''))} → {where.get('dst_ip', finding.get('dst_ip',''))}")
                            if steps:
                                st.markdown("**Extraction Steps:**")
                                for si, step in enumerate(steps, 1):
                                    st.write(f"{si}. Method: `{step.get('method','')}`")
                                    cmd = step.get('command')
                                    if cmd:
                                        st.code(cmd, language='bash')

                # Compact Tracking Pixels section inside Findings tab
                try:
                    tp = results.get('tracking_pixels') or []
                    if tp:
                        st.markdown("---")
                        st.markdown("### 🧿 Tracking Pixels (compact)")
                        # Build a compact table with columns: time, host, path, hints, token decoded, CL, CT
                        # Map packet_index -> time from timeline if available
                        idx_to_time = {}
                        try:
                            for ev in (results.get('timeline') or []):
                                if isinstance(ev, dict) and ev.get('type') == 'packet' and 'packet_index' in ev:
                                    idx_to_time[ev['packet_index']] = ev.get('time')
                        except Exception:
                            pass
                        rows = []
                        for e in tp[:1000]:  # cap rows for UI
                            try:
                                pkt_idx = e.get('packet_index')
                                t = idx_to_time.get(pkt_idx)
                                # Hints summary
                                h = e.get('hints') or {}
                                hint_bits = []
                                if h.get('is_1x1'): hint_bits.append('1x1')
                                if h.get('css_hidden'): hint_bits.append('hidden')
                                if h.get('tracker_path'): hint_bits.append('tracker')
                                hints_s = ','.join(hint_bits) if hint_bits else ''
                                # Token decoded preview
                                toks = e.get('tokens') or []
                                decs = []
                                for tkn in toks:
                                    d = tkn.get('decoded')
                                    if d:
                                        decs.append(str(d)[:60])
                                tok_preview = '; '.join(decs[:2])
                                # Content-Length and Content-Type hints (per-response if available)
                                cl = e.get('response_content_length')
                                if cl is None:
                                    cl = e.get('response_smallest_content_length')
                                ct = e.get('response_content_type')
                                rows.append({
                                    'time': t,
                                    'host': e.get('host',''),
                                    'path': e.get('path',''),
                                    'hints': hints_s,
                                    'token_decoded': tok_preview,
                                    'CL': cl,
                                    'CT': ct
                                })
                            except Exception:
                                continue
                        try:
                            df = pd.DataFrame(rows, columns=['time','host','path','hints','token_decoded','CL','CT'])
                            st.dataframe(df, width='stretch', hide_index=True)
                        except Exception:
                            # Fallback simple list
                            for r in rows[:50]:
                                st.write(f"[{r.get('time','')}] {r.get('host','')} {r.get('path','')} | {r.get('hints','')} | {r.get('token_decoded','')} | CL={r.get('CL','')} | CT={r.get('CT','')}")
                except Exception:
                    pass

        # If a stream is being followed, switch to the streams tab
        if 'followed_stream' in st.session_state and st.session_state.followed_stream:
            default_tab_index = 1
        else:
            default_tab_index = 0

        # Streams Tab
        with tabs[1]:
            st.markdown("### 🔄 Reconstructed Streams")
            if results.get('reconstructed_streams'):
                hide_binary = st.checkbox("Hide binary/TLS-like streams", value=True, key="hide_binary_streams")
                view_mode = st.radio("View mode", ["Auto", "Printable", "Hex"], index=0, horizontal=True, key="stream_view_mode")
                
                stream_count = 0
                for stream_id, stream in results['reconstructed_streams'].items():
                    data = stream.get('data', b'')
                    if isinstance(data, str):
                        try:
                            data_bytes = data.encode('utf-8', errors='ignore')
                        except Exception:
                            data_bytes = data
                    else:
                        data_bytes = data or b''
                    
                    if not data_bytes:
                        continue
                        
                    printable = sum(1 for b in data_bytes[:2000] if 32 <= (b if isinstance(b, int) else ord(b)) < 127)
                    ratio = (printable / max(len(data_bytes[:2000]), 1)) if data_bytes else 0
                    if hide_binary and ratio < 0.2:
                        continue
                    
                    stream_count += 1
                    def to_hex_dump(b):
                        lines = []
                        for i in range(0, min(len(b), 1024), 16):
                            chunk = b[i:i+16]
                            hex_part = ' '.join(f"{x:02x}" for x in chunk)
                            asc_part = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
                            lines.append(f"{i:08x}  {hex_part:<47}  {asc_part}")
                        return "\n".join(lines)
                    if view_mode == "Hex":
                        preview = to_hex_dump(data_bytes)
                    elif view_mode == "Printable":
                        preview = ''.join(chr(x) if 32 <= x < 127 else '.' for x in data_bytes[:2000])
                    else:  # Auto
                        preview = ''.join(chr(x) if 32 <= x < 127 else '.' for x in data_bytes[:2000]) if ratio < 0.4 else (data if isinstance(data, str) else data_bytes[:2000].decode('utf-8', errors='ignore'))

                    expanded = st.session_state.get('followed_stream') == stream_id
                    with st.expander(f"Stream {stream_id}", expanded=expanded):
                        st.markdown(f"**Source:** {stream.get('src_ip', 'N/A')} → {stream.get('dst_ip', 'N/A')}")
                        st.markdown(f"**Protocol:** {stream.get('protocol', 'TCP')}")
                        st.code(preview, language="text")
                        if stream.get('http_requests') or stream.get('http_responses'):
                            st.markdown("**HTTP Messages in Stream:**")
                            if stream.get('http_requests'):
                                for req in stream['http_requests']:
                                    st.code(req, language="http")
                            if stream.get('http_responses'):
                                for resp in stream['http_responses']:
                                    st.code(resp, language="http")

                        # Ask AI about this stream
                        ai_cols = st.columns([1,1])
                        with ai_cols[0]:
                            if st.button("🧠 Ask AI about this stream", key=f"explain_stream_{stream_id}"):
                                try:
                                    config = AgentConfig.load_config()
                                    api_key = config.get('longcat_api_key') or config.get('openrouter_api_key')
                                    model = config.get('model', 'LongCat-Flash-Chat')

                                    # Rate-limit guard
                                    rate_handler = st.session_state.rate_limit_handler
                                    if model in rate_handler.rate_limit_errors:
                                        st.warning("⚠️ Current AI model is rate limited. Try again later or switch models in AI Config.")
                                    else:
                                        agent = create_agent(api_key, model)
                                        if agent is None:
                                            st.warning("AI agent not available. Configure API key on AI Config page.")
                                        else:
                                            summary = {
                                                'src_ip': stream.get('src_ip',''),
                                                'dst_ip': stream.get('dst_ip',''),
                                                'protocol': stream.get('protocol','TCP'),
                                                'packet_count': len(stream.get('packets',[])),
                                                'http_counts': {
                                                    'requests': len(stream.get('http_requests',[])),
                                                    'responses': len(stream.get('http_responses',[]))
                                                }
                                            }
                                            # Use the preview we computed above
                                            ctx = st.session_state.analysis_results.get('ctf_context') if st.session_state.analysis_results else None
                                            with st.spinner("Asking AI about this stream..."):
                                                resp = agent.explain_stream(summary, preview, ctx)
                                            st.markdown("**AI Stream Explanation:**")
                                            if isinstance(resp, dict):
                                                st.json(resp)
                                            else:
                                                st.write(str(resp))
                                except Exception as e:
                                    st.error(f"AI stream explanation failed: {e}")
                
                if stream_count == 0:
                    if results.get('reconstructed_streams'):
                        st.info("All streams are hidden by current filters. Try adjusting the 'Hide binary/TLS-like streams' option.")
                    else:
                        st.info("No streams were reconstructed from the traffic.")

                if 'followed_stream' in st.session_state:
                    del st.session_state['followed_stream']
            else:
                st.info("No TCP streams found in the capture. This may indicate UDP-only traffic or analysis issues.")

        # Sessions Tab
        with tabs[2]:
            st.markdown("### 🗣️ Session / Conversation Views")
            session_views = results.get('session_views') or {}
            if session_views:
                for proto, sessions in session_views.items():
                    with st.expander(f"{proto} Sessions ({len(sessions)})", expanded=False):
                        for sess_id, messages in sessions.items():
                            st.markdown(f"**Session:** `{sess_id}`")
                            for msg in messages:
                                # Ensure msg is a dict
                                if not isinstance(msg, dict):
                                    msg = {'content': str(msg), 'timestamp': '', 'direction': 'UNKNOWN'}
                                    
                                # Get message details with safe defaults
                                ts = msg.get('timestamp', '')
                                direction = msg.get('direction', 'UNKNOWN')
                                content = msg.get('content', '')
                                msg_type = msg.get('type', 'data')
                                
                                # Format the message based on its type
                                if msg_type in ['request', 'response']:
                                    st.write(f"[{ts}] **{direction}**")
                                else:
                                    st.write(f"[{ts}] {direction}")
                                    
                                # Display content safely
                                try:
                                    if isinstance(content, (dict, list)):
                                        st.json(content)
                                    else:
                                        st.code(str(content)[:2000], language="text")
                                except Exception as e:
                                    st.error(f"Error displaying content: {str(e)}")
                                    st.code(str(content)[:100] + "...", language="text")
                            st.markdown("---")
            else:
                # Fallback: raw sessions summary if available
                raw_sessions = results.get('sessions') or {}
                if raw_sessions:
                    st.info("No reconstructed conversations available. Showing raw session summary.")
                    for s_type, s_map in raw_sessions.items():
                        st.write(f"- {s_type}: {len(s_map)} sessions")
                else:
                    st.warning("No session data available. Run analysis on a PCAP with FTP/SMTP/IRC/chat traffic or enable parsing options.")

        # Protocols Tab
        with tabs[3]:
            st.markdown("### 🧩 Protocol-Specific Details")
            # Optional TShark pre-analysis summary (if enabled and available)
            try:
                ts = results.get('tshark_summary') if 'results' in locals() else (st.session_state.analysis_results or {}).get('tshark_summary')
            except Exception:
                ts = None
            if ts:
                with st.expander("🦈 TShark Pre-Analysis (HTTP/DNS summary)", expanded=False):
                    if not ts.get('available', True):
                        st.warning("tshark not installed or unavailable on this system.")
                    plans = ts.get('plans') or []
                    if plans:
                        st.markdown("**Plans executed:**")
                        for p in plans:
                            st.write(f"- {p}")
                    # Aggregate HTTP summary rows
                    http_rows = []
                    for s in (ts.get('summaries') or []):
                        summ = s.get('summary') or {}
                        for h in (summ.get('http') or [])[:1000]:
                            http_rows.append({
                                'frame': h.get('frame'),
                                'method': h.get('method'),
                                'uri': h.get('uri'),
                                'host': h.get('host'),
                                'code': h.get('code'),
                                'content_type': h.get('content_type')
                            })
                    if http_rows:
                        st.markdown("**HTTP summary (first 50)**")
                        try:
                            dfh = pd.DataFrame(http_rows)[:50]
                            st.dataframe(dfh, width='stretch', hide_index=True)
                        except Exception:
                            for r in http_rows[:10]:
                                st.write(f"[{r.get('frame')}] {r.get('method','')} {r.get('uri','')} ({r.get('code','')})")
                    # Aggregate DNS summary rows
                    dns_rows = []
                    for s in (ts.get('summaries') or []):
                        summ = s.get('summary') or {}
                        for d in (summ.get('dns') or [])[:1000]:
                            answers = d.get('answers') or []
                            dns_rows.append({
                                'frame': d.get('frame'),
                                'query': d.get('query'),
                                'answers': ','.join(answers) if isinstance(answers, list) else str(answers)
                            })
                    if dns_rows:
                        st.markdown("**DNS summary (first 50)**")
                        try:
                            dfd = pd.DataFrame(dns_rows)[:50]
                            st.dataframe(dfd, width='stretch', hide_index=True)
                        except Exception:
                            for r in dns_rows[:10]:
                                st.write(f"[{r.get('frame')}] {r.get('query','')} -> {r.get('answers','')}")
                    errs = ts.get('errors') or []
                    if errs:
                        with st.expander("TShark stderr (truncated)", expanded=False):
                            for e in errs[:3]:
                                st.code(str(e.get('stderr',''))[:500], language='text')
            proto_details = results.get('protocol_details') or []
            if proto_details:
                for item in proto_details[:50]:
                    proto = item.get('protocol', 'Unknown')
                    sni = item.get('sni')
                    summary = item.get('summary')
                    src = item.get('src_ip', '')
                    dst = item.get('dst_ip', '')
                    if sni:
                        st.write(f"- [{proto}] {src} → {dst} | SNI: `{sni}`")
                    elif summary:
                        st.write(f"- [{proto}] {src} → {dst} | {summary}")
                    else:
                        st.write(f"- [{proto}] {src} → {dst}")
            else:
                # Quick fallback summary by protocol counts
                findings = results.get('findings', [])
                if findings:
                    from collections import Counter
                    counts = Counter([f.get('protocol','Unknown') for f in findings])
                    st.info("No decoder details recorded. Showing protocol counts from findings.")
                    for proto, count in counts.most_common():
                        st.write(f"- {proto}: {count}")
                else:
                    st.warning("No protocol details available. Ensure analysis completed and protocol-specific parsing is enabled.")

            # Protocol Hierarchy
            st.markdown("---")
            st.markdown("### 🌳 Protocol Hierarchy")
            protocol_hierarchy = results.get('protocol_hierarchy')
            if protocol_hierarchy:
                def render_hierarchy(node, level=0):
                    if 'children' in node and node['children']:
                        with st.expander(f"{'  ' * level}{node['name']} ({node['value']} packets)"):
                            for child in node['children']:
                                render_hierarchy(child, level + 1)
                    else:
                        st.markdown(f"{'  ' * level}- {node['name']} ({node['value']} packets)")

                render_hierarchy(protocol_hierarchy)
            else:
                st.info("Protocol hierarchy data not available.")

            # TLS/SSL Certificates
            st.markdown("---")
            st.markdown("### 📜 TLS/SSL Certificates")
            tls_certificates = results.get('tls_certificates')
            if tls_certificates:
                for i, cert in enumerate(tls_certificates):
                    with st.expander(f"Certificate #{i+1}: {cert['subject']}"):
                        st.json(cert)
            else:
                st.info("No TLS certificates found in the capture.")

            # Advanced analyzers summary
            adv = results.get('advanced') or {}
            if adv:
                st.markdown("---")
                st.markdown("### 🧠 Advanced Analyzers Summary")
                # Show compact metrics grid
                c1, c2, c3, c4 = st.columns(4)
                try:
                    ipv6_total = (adv.get('ipv6') or {}).get('total_ipv6') or (adv.get('ipv6', {}).get('summary', {}) or {}).get('total_ipv6')
                    tunnels = len((adv.get('ipv6_tunnels') or {}).get('detected_tunnels', []) or [])
                    icmpv6 = ((adv.get('icmpv6') or {}).get('icmpv6_counts') or {}).get('total', 0)
                    c1.metric("IPv6 packets", f"{ipv6_total or 0}")
                    c2.metric("IPv6 tunnels", f"{tunnels}")
                    c3.metric("ICMPv6", f"{icmpv6}")
                except Exception:
                    pass
                try:
                    mining = ((adv.get('blockchain') or {}).get('mining') or {}).get('severity')
                    btc_tx = ((adv.get('blockchain') or {}).get('bitcoin') or {}).get('transactions', 0)
                    eth_tx = ((adv.get('blockchain') or {}).get('ethereum') or {}).get('transactions', 0)
                    c4.metric("Crypto mining", mining or 'n/a')
                    st.caption(f"BTC tx: {btc_tx} • ETH tx: {eth_tx}")
                except Exception:
                    pass

                # Industrial protocols
                try:
                    with st.expander("🏭 Industrial Protocols", expanded=False):
                        ind = adv.get('industrial') or {}
                        for k in ['dnp3','s7comm','bacnet','opcua','profinet']:
                            v = ind.get(k) or {}
                            risks = (v.get('security_analysis') or {}).get('identified_risks') or []
                            total = v.get('total_packets') or v.get('count') or v.get('summary', {}).get('total', 0)
                            st.write(f"- {k.upper()}: packets={total} risks={len(risks)}")
                except Exception:
                    pass

                # RF
                try:
                    with st.expander("📡 RF (Wi‑Fi/BLE/ZigBee)", expanded=False):
                        rf = adv.get('rf') or {}
                        wifi_aps = len((rf.get('wifi') or {}).get('aps', {}) or {})
                        ble_scans = len((rf.get('ble') or {}).get('scan_requests', {}) or {})
                        zig_profiles = len((rf.get('zigbee') or {}).get('app_profiles', {}) or {})
                        st.write(f"- Wi‑Fi APs: {wifi_aps}  •  BLE scans: {ble_scans}  •  ZigBee profiles: {zig_profiles}")
                except Exception:
                    pass

                # Databases
                try:
                    with st.expander("🗄️ Database Protocols", expanded=False):
                        db = adv.get('databases') or {}
                        for name in ['mysql','postgres','mongodb','redis','mssql']:
                            v = db.get(name) or {}
                            sessions = v.get('sessions') or v.get('connections') or 0
                            findings = len(v.get('findings', []) or [])
                            st.write(f"- {name.upper()}: sessions={sessions} findings={findings}")
                except Exception:
                    pass

                # Malware / DLP / Fingerprinting / Temporal
                try:
                    cols = st.columns(4)
                    mal = (adv.get('malware') or {}).get('suspicious_patterns') or []
                    cols[0].metric("Malware alerts", f"{len(mal)}")
                    dlp = (adv.get('dlp') or {}).get('results') or []
                    cols[1].metric("PII found", f"{len(dlp)}")
                    fp = adv.get('fingerprinting') or {}
                    cols[2].metric("OS guesses", f"{len(fp.get('os') or [])}")
                    flows = (adv.get('flows') or {}).get('count', 0)
                    cols[3].metric("Flows", f"{flows}")
                except Exception:
                    pass

                # ML anomalies quick view
                try:
                    ml = adv.get('ml_anomalies') or {}
                    if ml:
                        with st.expander("🧠 ML Anomalies", expanded=False):
                            st.json(ml)
                except Exception:
                    pass

        # AI Tab
        with tabs[4]:
            st.markdown("### 🤖 AI Analysis & Hints")
            if results.get('ai_status') or results.get('ai_findings') or results.get('ai_suggestions'):
                if results.get('ai_status'):
                    ai_status = results['ai_status']
                    status_map = {
                        'rate_limited': (st.warning, "⚠️ AI Analysis: Rate Limited - Offline analysis completed"),
                        'fallback_success': (st.success, f"✅ AI Analysis: Fallback Success - Used {results.get('ai_fallback_model','unknown')}`"),
                        'fallback_failed': (st.warning, "⚠️ AI Analysis: Fallback Failed - Offline analysis completed"),
                        'all_models_rate_limited': (st.warning, "⚠️ AI Analysis: All Models Rate Limited - Offline analysis completed"),
                        'error': (st.error, "❌ AI Analysis: Error Occurred"),
                        'failed': (st.error, "❌ AI Analysis: Failed"),
                    }
                    fn, msg = status_map.get(ai_status, (st.info, f"AI status: {ai_status}"))
                    fn(msg)
                    if results.get('ai_error'):
                        st.info(f"Details: {results['ai_error']}")
                if results.get('ai_findings'):
                    st.markdown("**AI Discoveries**")
                    ai_obj = results.get('ai_findings')
                    ai_list = []
                    if isinstance(ai_obj, list):
                        ai_list = ai_obj
                    elif isinstance(ai_obj, dict):
                        for key in ['flag_candidates', 'ai_findings', 'findings', 'enhanced_findings']:
                            val = ai_obj.get(key)
                            if isinstance(val, list):
                                ai_list = val
                                break
                        if not ai_list:
                            ai_list = [ai_obj]
                    for i, finding in enumerate(ai_list[:5]):
                        confidence = finding.get('confidence', 50) if isinstance(finding, dict) else 50
                        with st.expander(f"🚩 AI Discovery #{i+1} - {confidence}% Confidence", expanded=True):
                            if isinstance(finding, dict):
                                content_val = finding.get('flag_candidate') or finding.get('flag') or finding.get('data') or finding.get('result') or ''
                                st.code(str(content_val), language="text")
                                if finding.get('reasoning'):
                                    st.markdown("**🧠 Reasoning:**")
                                    st.markdown(str(finding['reasoning']))
                                if finding.get('poc'):
                                    st.markdown("**🔧 PoC:**")
                                    st.markdown(str(finding['poc']))
                            else:
                                st.code(str(finding), language="text")
                if results.get('ai_suggestions'):
                    st.markdown("**AI Suggestions**")
                    for s in results['ai_suggestions'][:5]:
                        st.write(f"- {s}")
                # Grounded summary (deterministic, offline)
                try:
                    with st.expander("Grounded Summary (deterministic)", expanded=False):
                        from ai.ai_agent import grounded_explain as _grounded
                        if st.button("📋 Generate grounded summary", key="btn_grounded_summary"):
                            try:
                                g = _grounded(results)
                                if isinstance(g, dict):
                                    st.json(g)
                                else:
                                    st.write(str(g))
                            except Exception as _e_g:
                                st.error(f"Grounded summary failed: {_e_g}")
                except Exception:
                    pass
                # Advanced analyzer hints and explanation
                adv_hints = results.get('advanced_ai_hints') or []
                adv = results.get('advanced') or {}
                if adv_hints or adv:
                    with st.expander("Advanced Analyzer Insights", expanded=False):
                        if adv_hints:
                            st.markdown("**Prioritized Hints (heuristic)**")
                            for h in adv_hints[:10]:
                                title = h.get('title','')
                                hint = h.get('hint','')
                                pr = h.get('priority','info')
                                conf = int(float(h.get('confidence',0))*100) if isinstance(h.get('confidence'), (int,float)) and h.get('confidence') <= 1 else int(h.get('confidence',0))
                                st.write(f"- [{pr.upper()} • {conf}%] {title}: {hint}")
                        # Optional AI explanation button
                        try:
                            from ai.ai_agent import AgentConfig, create_agent
                            cfg = AgentConfig.load_config()
                            api_key = cfg.get('longcat_api_key') or cfg.get('openrouter_api_key')
                            model = cfg.get('model','LongCat-Flash-Chat')
                            explain_cols = st.columns([1,1])
                            if explain_cols[0].button("🧠 Ask AI to explain advanced results"):
                                if not api_key:
                                    st.warning("Configure an AI API key in AI Config to enable model explanations.")
                                else:
                                    agent = create_agent(api_key, model)
                                    if hasattr(agent, 'explain_advanced'):
                                        with st.spinner("Generating AI explanation for advanced results…"):
                                            try:
                                                resp = agent.explain_advanced(adv)
                                                if isinstance(resp, dict):
                                                    st.json(resp)
                                                else:
                                                    st.write(str(resp))
                                            except Exception as _e:
                                                st.error(f"AI explanation failed: {_e}")
                                    else:
                                        st.info("This agent version doesn’t implement explain_advanced().")
                        except Exception:
                            pass
                # Also display any specialized analyses if present
                for key, title in [
                    ('protocol_analysis', 'Protocol Analysis'),
                    ('credential_analysis', 'Credential Analysis'),
                    ('behavioral_analysis', 'Behavioral Analysis'),
                    ('ai_analysis', 'Enhanced Analysis'),
                    ('enhanced_flag_hunt', 'Enhanced Flag Hunt')
                ]:
                    if results.get(key):
                        with st.expander(f"{title}"):
                            val = results.get(key)
                            if isinstance(val, (dict, list)):
                                st.json(val)
                            else:
                                st.write(str(val))
            else:
                st.warning("No AI data available. Ensure AI mode is enabled and an API key/model is configured on the AI Config page.")

        # Visuals Tab
        with tabs[5]:
            st.markdown("### 📈 Visualizations")
            vis = st.session_state.ctf_visualizer if 'ctf_visualizer' in st.session_state else None
            if results.get('findings') and vis:
                try:
                    st.markdown("#### Findings Distribution")
                    fig = st.session_state.ctf_visualizer.create_findings_distribution(results['findings'])
                    st.plotly_chart(fig, use_container_width=True)
                except Exception:
                    pass
                try:
                    st.markdown("#### Confidence Heatmap")
                    fig2 = st.session_state.ctf_visualizer.create_confidence_heatmap(results['findings'])
                    st.plotly_chart(fig2, use_container_width=True)
                except Exception:
                    pass
            else:
                st.info("No visualization data available yet. Run analysis to populate findings.")

            # IO Graphs
            st.markdown("---")
            st.markdown("### 📈 IO Graphs")
            io_graph_data = results.get('io_graph_data')
            if io_graph_data:
                pps_df = pd.DataFrame(io_graph_data['packets_per_second'])
                bps_df = pd.DataFrame(io_graph_data['bytes_per_second'])

                if not pps_df.empty:
                    pps_fig = px.line(pps_df, x='time', y='packets', title='Packets per Second')
                    st.plotly_chart(pps_fig, use_container_width=True)

                if not bps_df.empty:
                    bps_fig = px.line(bps_df, x='time', y='bytes', title='Bytes per Second')
                    st.plotly_chart(bps_fig, use_container_width=True)
            else:
                st.info("IO graph data not available.")

        # Timeline Tab
        with tabs[6]:
            st.markdown("### 🕒 Timeline")
            timeline = results.get('timeline') or []
            if not timeline:
                st.info("No timeline events available.")
            else:
                max_rows = st.slider("Max events to display", 50, 2000, min(500, len(timeline)), key="timeline_max")
                cols = ["datetime","type","protocol","src_ip","dst_ip","description"]
                rows = []
                for e in timeline[:max_rows]:
                    rows.append({k: e.get(k,'') for k in cols})
                try:
                    import pandas as _pd
                    st.dataframe(_pd.DataFrame(rows))
                except Exception:
                    for r in rows:
                        st.write(" - ", r.get('datetime',''), r.get('type',''), r.get('protocol',''), f"{r.get('src_ip','')} → {r.get('dst_ip','')}", r.get('description',''))
            # Correlation Graph (simple Plotly scatter for nodes and lines for edges)
            graph = results.get('correlation_graph') or {}
            nodes = graph.get('nodes') or []
            edges = graph.get('edges') or []
            if nodes and edges:
                st.markdown("#### Correlation Graph")
                try:
                    import plotly.graph_objects as go
                    # Assign simple positions in a circle
                    import math
                    n = len(nodes)
                    positions = {}
                    for i, node in enumerate(nodes):
                        angle = 2 * math.pi * i / max(n,1)
                        positions[node['id']] = (math.cos(angle), math.sin(angle))
                    edge_x = []
                    edge_y = []
                    for e in edges:
                        s = positions.get(e.get('source'))
                        t = positions.get(e.get('target'))
                        if s and t:
                            edge_x += [s[0], t[0], None]
                            edge_y += [s[1], t[1], None]
                    node_x = [positions[n['id']][0] for n in nodes if n['id'] in positions]
                    node_y = [positions[n['id']][1] for n in nodes if n['id'] in positions]
                    node_text = [f"{n.get('type','node')}: {n.get('id')}" for n in nodes if n['id'] in positions]
                    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='#888'), hoverinfo='none', mode='lines')
                    node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text', text=node_text,
                                            marker=dict(showscale=False, color='#00bcd4', size=10, line_width=2))
                    fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(showlegend=False,
                                margin=dict(l=0,r=0,b=0,t=0), xaxis=dict(visible=False), yaxis=dict(visible=False)))
                    st.plotly_chart(fig, width='stretch')
                except Exception:
                    st.info("Correlation graph available, but Plotly rendering failed.")

        # Files Tab
        with tabs[7]:
            st.markdown("### 🗂️ Extracted Files / File Carving Results")
            files_list = results.get('file_carving_results', []) or results.get('extracted_files', [])
            if not files_list:
                st.info("No carved or extracted files found.")
            else:
                # Mini Stego Lab summary and helper
                try:
                    with st.expander("🕵️ Stego Lab", expanded=False):
                        img_exts = {"png","jpg","gif","ico"}
                        img_count = sum(1 for f in files_list if str(f.get('ext') or f.get('extension','')).lower() in img_exts)
                        txt_hits = []
                        for f in files_list:
                            a = f.get('analysis') or {}
                            for s in (a.get('stego') or []):
                                content = s.get('content')
                                if content and isinstance(content, str) and content.strip():
                                    txt_hits.append((f, s))
                        st.write(f"Images: {img_count}  •  Extracted texts from stego analyzers: {len(txt_hits)}")
                        if txt_hits:
                            if st.button("➕ Promote extracted texts to Decoded Data", key="promote_stego_texts"):
                                added = 0
                                for fobj, s in txt_hits[:100]:
                                    try:
                                        content = s.get('content')
                                        if not content:
                                            continue
                                        entry = {
                                            'type': 'stego_extracted',
                                            'decoded': str(content)[:10000],
                                            'chain': ['stego'],
                                            'protocol': 'FILE',
                                            'packet_index': -1,
                                            'confidence': 0.7,
                                            'source': f"carved:{fobj.get('name') or fobj.get('filename','file')}"
                                        }
                                        st.session_state.analysis_results.setdefault('decoded_data', []).append(entry)
                                        added += 1
                                    except Exception:
                                        continue
                                st.success(f"Promoted {added} extracted text item(s) into Decoded Data.")
                except Exception:
                    pass
                # Filters
                name_filter = st.text_input("Search by name/hash", key="file_name_filter")
                min_size = st.slider("Minimum size (bytes)", 0, 1000000, 0, key="file_min_size")
                uniq = st.checkbox("Unique by hash", value=True, key="file_unique_hash")
                # Sub-tabs by category
                cat_tabs = st.tabs(["All", "Images", "Docs", "Archives", "Binaries", "Audio/Video", "Other"])
                categories = {
                    'Images': {"png","jpg","gif","ico"},
                    'Docs': {"pdf"},
                    'Archives': {"zip","gz","bz2"},
                    'Binaries': {"exe","elf"},
                    'Audio/Video': {"mp3","wav","mp4"},
                }
                def apply_filters(items, allowed_exts=None):
                    filtered = []
                    seen = set()
                    for idx, fobj in enumerate(items):
                        name = fobj.get('name') or fobj.get('filename') or f"carved_file_{idx}"
                        ext = (fobj.get('ext') or fobj.get('extension') or '').lower()
                        fhash = fobj.get('hash') or fobj.get('sha256') or fobj.get('md5_hash', '')
                        size = fobj.get('size', len(fobj.get('data', b'')) if isinstance(fobj.get('data'), (bytes, bytearray)) else 0)
                        if name_filter and name_filter.lower() not in (name.lower() + fhash.lower()):
                            continue
                        if size < min_size:
                            continue
                        if allowed_exts is not None and ext not in allowed_exts:
                            continue
                        key = fhash if uniq else (name, size)
                        if uniq and fhash and key in seen:
                            continue
                        seen.add(key)
                        # uid is a stable per-file identifier for widget keys
                        uid = fhash or f"{name}_{size}_{idx}"
                        filtered.append((idx, fobj, name, ext, fhash, size, uid))
                    return filtered
                def render_list(filtered, key_prefix:"str"="all"):
                    if not filtered:
                        st.info("No files match the current filters.")
                        return
                    for idx, fobj, name, ext, fhash, size, uid in filtered:
                        st.write(f"- {name}{('.' + ext) if ext else ''} ({size} bytes)  |  Hash: {fhash}")
                        raw = fobj.get('data')
                        data_bytes = None
                        if isinstance(raw, (bytes, bytearray)):
                            data_bytes = raw
                        elif isinstance(raw, str):
                            try:
                                import base64
                                data_bytes = base64.b64decode(raw)
                            except Exception:
                                data_bytes = None
                        if data_bytes:
                            st.download_button(
                                label=f"⬇️ Download {name}",
                                data=data_bytes,
                                file_name=f"{name}{('.' + ext) if ext else ''}",
                                mime="application/octet-stream",
                                key=f"dl_{key_prefix}_{uid}"
                            )
                        # Carved File Details (analysis & stego notes)
                        analysis = fobj.get('analysis') or {}
                        if analysis:
                            with st.expander(f"Carved File Details: {name}"):
                                meta = analysis.get('metadata') or {}
                                stego = analysis.get('stego') or []
                                if meta:
                                    st.markdown("**Metadata:**")
                                    # Highlight EXIF GPS/Author/Software if present
                                    exif = meta.get('exif') or {}
                                    if exif:
                                        highlights = {k: exif.get(k) for k in ['GPSInfo','Artist','Software','Make','Model'] if exif.get(k)}
                                        if highlights:
                                            st.markdown("**EXIF Highlights:**")
                                            st.json(highlights)
                                    st.json(meta)
                                if stego:
                                    st.markdown("**Stego Indicators:**")
                                    for s in stego:
                                        st.write(f"- {s.get('type','note')}")
                                        content = s.get('content')
                                        if content:
                                            st.code(str(content)[:1000], language='text')
                                            st.download_button(
                                                label="⬇️ Export extracted text",
                                                data=str(content).encode('utf-8', errors='ignore'),
                                                file_name=f"{name}_extracted.txt",
                                                mime="text/plain",
                                                key=f"dl_text_{key_prefix}_{uid}_{s.get('type','t')}"
                                            )
                with cat_tabs[0]:
                    render_list(apply_filters(files_list), key_prefix="all")
                with cat_tabs[1]:
                    render_list(apply_filters(files_list, categories['Images']), key_prefix="images")
                with cat_tabs[2]:
                    render_list(apply_filters(files_list, categories['Docs']), key_prefix="docs")
                with cat_tabs[3]:
                    render_list(apply_filters(files_list, categories['Archives']), key_prefix="archives")
                with cat_tabs[4]:
                    render_list(apply_filters(files_list, categories['Binaries']), key_prefix="binaries")
                with cat_tabs[5]:
                    render_list(apply_filters(files_list, categories['Audio/Video']), key_prefix="av")
                with cat_tabs[6]:
                    known = set().union(*categories.values())
                    filtered = [f for f in files_list if (f.get('ext') or f.get('extension','')).lower() not in known]
                    render_list(apply_filters(filtered), key_prefix="other")
                # Audio Spectrogram previews
                if results.get('voip_audio'):
                    has_spec = any(item.get('spectrogram_png') for item in results['voip_audio'])
                    if has_spec:
                        with st.expander("Audio Spectrograms"):
                            for i, item in enumerate(results['voip_audio']):
                                img_bytes = item.get('spectrogram_png')
                                if not img_bytes:
                                    continue
                                st.markdown(f"Session: {item.get('session_id','unknown')}  |  Sample Rate: {item.get('sample_rate','')} Hz")
                                st.image(img_bytes, caption=f"Spectrogram #{i+1}", width='stretch')
                                st.download_button(
                                    label="⬇️ Download Spectrogram",
                                    data=img_bytes,
                                    file_name=f"spectrogram_{i+1}.png",
                                    mime="image/png",
                                    key=f"dl_spec_{i}"
                                )

        # Replay Tab
        with tabs[8]:
            st.markdown("### 🔁 Replay Commands")
            cmds = results.get('replay_commands') or []
            # If empty, show hint to run analysis with AI enabled
            if not cmds:
                st.info("No replay commands available yet. Run analysis with AI enabled or with sessions reconstructed.")
            else:
                # Display commands only (no descriptions)
                for c in cmds[:20]:
                    st.code(c.get('command',''), language='bash')

        # Crypto Tab
        with tabs[9]:
            st.markdown("### 🛡️ Crypto & Decoding")
            shown = False
            
            # JWT Tokens
            jwt_tokens = results.get('jwt_tokens', [])
            if jwt_tokens:
                shown = True
                st.markdown("#### JWT Tokens")
                for j in jwt_tokens[:20]:
                    with st.expander(f"JWT (frame {j.get('packet_index',0)+1})"):
                        st.markdown("**Header:**")
                        st.json(j.get('header', {}))
                        st.markdown("**Claims:**")
                        st.json(j.get('claims', {}))
                        st.markdown(f"Source: {j.get('src_ip','')} → {j.get('dst_ip','')} | Protocol: {j.get('protocol','Unknown')}")
            
            # Decoded Data
            decoded_data = results.get('decoded_data', [])
            if decoded_data:
                shown = True
                st.markdown("#### Decoded Data")
                for d in decoded_data[:50]:
                    decoded_text = d.get('decoded', '') or d.get('result', '')
                    if decoded_text:
                        with st.expander(f"Decoded via {d.get('type','unknown')} (frame {(d.get('packet_index') or 0)+1})"):
                            st.code(decoded_text, language='text')
                            if d.get('poc'):
                                st.markdown("**PoC Steps:**")
                                for sidx, step in enumerate(d['poc'].get('extraction_steps', []), 1):
                                    st.write(f"{sidx}. {step.get('method','')}")
                                    if step.get('command'):
                                        st.code(step['command'], language='bash')
            
            # Check for base64 and other encoded content in findings
            encoded_findings = [f for f in results.get('findings', []) if 'base64' in f.get('type', '').lower() or 'encoded' in f.get('display_type', '').lower()]
            if encoded_findings and not decoded_data:
                shown = True
                st.markdown("#### Encoded Content in Findings")
                for f in encoded_findings[:10]:
                    with st.expander(f"Encoded Finding (packet {f.get('packet_index', 0)+1})"):
                        st.code(f.get('data', ''), language='text')
                        st.markdown(f"**Type:** {f.get('display_type', 'Unknown')}")
                        st.markdown(f"**Protocol:** {f.get('protocol', 'Unknown')}")
            
            # Encryption Attempts
            encryption_attempts = results.get('encryption_attempts', [])
            if encryption_attempts:
                shown = True
                st.markdown("#### Encryption/Decryption Attempts")
                for attempt in encryption_attempts:
                    with st.expander(f"Attempt: {attempt.get('method', 'Unknown')}"):
                        st.markdown(f"**Input:**")
                        st.code(attempt.get('input', ''), language="text")
                        st.markdown(f"**Output:**")
                        st.code(attempt.get('output', ''), language="text")
                        st.markdown(f"**Status:** {attempt.get('status', 'N/A')}")
                        if attempt.get('key'):
                            st.markdown(f"**Key/Password Used:** {attempt['key']}")
            
            if not shown:
                st.info("No crypto/decoding artifacts found. Try running analysis with encoded data or enable decryption options.")

        # Database Tab
        with tabs[11]:
            st.markdown("### 🗄️ Database Analysis")
            db_analysis = results.get('database_analysis')
            if db_analysis:
                for db_name, db_results in db_analysis.items():
                    if db_results.get('total_' + db_name + '_packets', 0) > 0:
                        with st.expander(f"{db_name.capitalize()} Traffic ({db_results['total_' + db_name + '_packets']} packets)"):
                            if 'command_distribution' in db_results:
                                st.write("**Command Distribution:**")
                                st.json(db_results['command_distribution'])
                            if 'detected_queries' in db_results and db_results['detected_queries']:
                                st.write("**Detected Queries:**")
                                for query in db_results['detected_queries']:
                                    st.code(query, language='sql')
                            if 'detected_commands' in db_results and db_results['detected_commands']:
                                st.write("**Detected Commands:**")
                                for cmd in db_results['detected_commands']:
                                    st.code(str(cmd))
                            if 'responses' in db_results and db_results['responses']:
                                st.write("**Responses:**")
                                for resp in db_results['responses']:
                                    st.write(resp)
            else:
                st.info("No database traffic detected.")

        # Malware Tab
        with tabs[12]:
            st.markdown("### 🦠 Malware Analysis")
            malware_analysis = results.get('malware_analysis')
            if malware_analysis:
                if malware_analysis['signatures']['detected_signatures']:
                    st.subheader("Detected Signatures")
                    for sig in malware_analysis['signatures']['detected_signatures']:
                        st.write(f"- Type: {sig['type']}, Signature: {sig['signature']}")
                        st.code(sig['packet_summary'])
                if malware_analysis['c2']['detected_c2_patterns']:
                    st.subheader("Detected C2 Patterns")
                    for pattern in malware_analysis['c2']['detected_c2_patterns']:
                        st.write(f"- Type: {pattern['type']}, Source: {pattern['source_ip']}, Destination: {pattern['destination_ip']}")
                        st.write(f"  Packet Count: {pattern['packet_count']}, Average Interval: {pattern['average_interval']:.2f}s")
            else:
                st.info("No malware indicators detected.")

        # YARA Scan Tab
        with tabs[13]:
            st.markdown("### 🛡️ YARA Scan Results")
            yara_matches = results.get('yara_matches')
            if yara_matches:
                for match in yara_matches:
                    with st.expander(f"Rule: {match['rule']}"):
                        st.write(f"**Tags:** {', '.join(match['tags'])}")
                        st.write("**Strings:**")
                        st.json(match['strings'])
            else:
                st.info("No YARA matches found.")

        # Export Tab
        with tabs[14]:
            st.markdown("### 📥 Export Results")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("📄 Export JSON", width='stretch'):
                    export_results(results, "json")
            with col2:
                if st.button("📊 Export CSV", width='stretch'):
                    export_results(results, "csv")
            with col3:
                if st.button("📋 Export HTML", width='stretch'):
                    export_results(results, "html")

        # Early return to avoid legacy layout duplication
        st.markdown('</div>', unsafe_allow_html=True)
        return
    
    else:
        st.markdown("""
        <div style="text-align: center; padding: 4rem 2rem;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">📊</div>
            <div style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;">No Results Yet</div>
            <div style="color: rgba(255, 255, 255, 0.7);">Run an analysis to see results here</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_advanced_page():
    """Render advanced features page"""
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    st.markdown("### 🚀 Advanced Features & Multi-Agent System")
    
    if not IMPORTS_OK:
        st.error("Advanced features unavailable - Import error detected")
        st.markdown('</div>', unsafe_allow_html=True)
        return
    
    # Initialize systems if not already done
    if not st.session_state.multi_agent_system:
        try:
            api_key = AgentConfig.get_api_key()
            if api_key:
                st.session_state.multi_agent_system = MultiAgentSystem(api_key)
                st.success("✅ Multi-Agent System initialized!")
            else:
                st.warning("⚠️ Configure AI API key to enable multi-agent system")
        except Exception as e:
            st.error(f"Failed to initialize multi-agent system: {e}")
    
    if not st.session_state.workflow_orchestrator:
        try:
            st.session_state.workflow_orchestrator = WorkflowOrchestrator()
            st.success("✅ Workflow Orchestrator initialized!")
        except Exception as e:
            st.error(f"Failed to initialize workflow orchestrator: {e}")
    
    # Multi-Agent System Status
    st.markdown("#### 🤖 Multi-Agent System Status")
    
    if st.session_state.multi_agent_system:
        agent_cols = st.columns(5)
        
        with agent_cols[0]:
            st.markdown("""
            <div style="text-align: center; padding: 1rem; background: rgba(0, 245, 255, 0.1); border-radius: 15px;">
                <div style="font-size: 2rem;">🎯</div>
                <div style="font-weight: 600;">Flag Hunter</div>
                <div style="font-size: 0.8rem;">Active</div>
            </div>
            """, unsafe_allow_html=True)
        
        with agent_cols[1]:
            st.markdown("""
            <div style="text-align: center; padding: 1rem; background: rgba(255, 0, 255, 0.1); border-radius: 15px;">
                <div style="font-size: 2rem;">🔍</div>
                <div style="font-weight: 600;">Forensics</div>
                <div style="font-size: 0.8rem;">Active</div>
            </div>
            """, unsafe_allow_html=True)
        
        with agent_cols[2]:
            st.markdown("""
            <div style="text-align: center; padding: 1rem; background: rgba(0, 255, 136, 0.1); border-radius: 15px;">
                <div style="font-size: 2rem;">🔐</div>
                <div style="font-weight: 600;">Crypto</div>
                <div style="font-size: 0.8rem;">Active</div>
            </div>
            """, unsafe_allow_html=True)
        
        with agent_cols[3]:
            st.markdown("""
            <div style="font-size: 2rem;">🌐</div>
            <div style="font-weight: 600;">Network</div>
            <div style="font-size: 0.8rem;">Active</div>
            """, unsafe_allow_html=True)
        
        with agent_cols[4]:
            st.markdown("""
            <div style="font-size: 2rem;">🦠</div>
            <div style="font-weight: 600;">Malware</div>
            <div style="font-size: 0.8rem;">Active</div>
            """, unsafe_allow_html=True)
    
    # AI Monitor
    st.markdown("#### 📊 AI Activity Monitor")
    
    if st.session_state.ai_monitor:
        st.session_state.ai_monitor.display_monitor(st.container())
    
    # Workflow Orchestrator
    st.markdown("#### 🔄 Workflow Orchestrator")
    
    if st.session_state.workflow_orchestrator:
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🚀 Create Network CTF Workflow", width='stretch'):
                try:
                    # Initialize required components for workflow
                    from utils.parsers import PacketParser
                    from utils.patterns import PatternMatcher
                    from analyzers.ctf.ctf_analyzer import NetworkTrafficDecoder, EncodingDecoder, CTFAnalyzer
                    
                    packet_parser = PacketParser()
                    pattern_matcher = PatternMatcher()
                    network_decoder = NetworkTrafficDecoder()
                    encoding_decoder = EncodingDecoder()
                    ctf_analyzer = CTFAnalyzer()
                    
                    # Create workflow with proper components
                    workflow = create_network_ctf_workflow(
                        st.session_state.workflow_orchestrator,
                        packet_parser,
                        pattern_matcher,
                        network_decoder,
                        encoding_decoder,
                        ctf_analyzer
                    )
                    st.success("✅ Network CTF workflow created!")
                except Exception as e:
                    st.error(f"Failed to create workflow: {e}")
        
        with col2:
            if st.button("📋 View Active Workflows", width='stretch'):
                workflows = st.session_state.workflow_orchestrator.list_workflows()
                if workflows:
                    st.write("Active workflows:", workflows)
                else:
                    st.info("No active workflows")
    
    # CTF Visualizations
    st.markdown("#### 📈 CTF Analysis Visualizations")
    
    if st.session_state.ctf_visualizer and st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        if results.get('findings'):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Findings Distribution**")
                fig = st.session_state.ctf_visualizer.create_findings_distribution(results['findings'])
                st.plotly_chart(fig, width='stretch')
            
            with col2:
                st.markdown("**Confidence Heatmap**")
                fig = st.session_state.ctf_visualizer.create_confidence_heatmap(results['findings'])
                st.plotly_chart(fig, width='stretch')
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_about_page():
    """Render about page"""
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    st.markdown("### ⚡ About FlagSniff Pro")
    
    st.markdown("""
    **FlagSniff Pro** is a next-generation PCAP analysis tool designed for security professionals, 
    red team operators, and CTF players. Built with cutting-edge AI technology and modern web interfaces.
    
    #### 🚀 Key Features
    - **AI-Powered Analysis**: Advanced machine learning for pattern recognition
    - **Real-time Processing**: Lightning-fast analysis of network captures
    - **Modern Interface**: Sleek, responsive design with dark/light themes
    - **Multiple AI Models**: Choose from 10+ state-of-the-art AI models
    - **Export Options**: JSON, CSV, and HTML report generation
    - **Multi-Agent System**: 5 specialized AI agents working together
    - **Workflow Orchestration**: Automated multi-step analysis pipelines
    - **Advanced Visualizations**: Interactive charts and network graphs
    - **Real-time AI Monitoring**: Live tracking of AI agent activities
    
    #### 🎯 Supported Analysis
    - CTF flag detection with advanced patterns
    - Credential extraction from network traffic
    - API token and authentication data discovery
    - Protocol security assessment
    - Steganography and covert channel detection
    - Multi-layer encoding analysis
    - Behavioral pattern recognition
    - Threat intelligence correlation
    
    #### 🤖 AI Models & Agents
    - **Claude 3.5 Sonnet**: Best overall performance
    - **GPT-4 Turbo**: Creative analysis and insights
    - **Gemini Pro**: Fast and efficient processing
    - **Llama 3.1**: Open-source power
    - **Flag Hunter Agent**: Specialized CTF analysis
    - **Forensics Agent**: Evidence analysis
    - **Crypto Agent**: Encryption analysis
    - **Network Security Agent**: Security assessment
    - **Malware Analysis Agent**: Threat detection
    
    #### 📊 Version Information
    - **Version**: 3.0 (Enhanced with Multi-Agent System)
    - **Author**: Waleed
    """)
    
    st.markdown('</div>', unsafe_allow_html=True)

def run_analysis(uploaded_file, search_options, custom_regex, ai_mode, ai_enabled, confidence_threshold, ctf_context=None, user_decrypt_key=None, tls_keylog_upload=None, display_filter=None, yara_rules=None):
    """Run the analysis with progress tracking"""
    if not IMPORTS_OK:
        st.error("Analysis unavailable - Import error detected")
        return
    
    # Save file temporarily (and persist path in session for Copilot re-analysis)
    try:
        # Cleanup previous saved PCAP, if any
        prev_path = st.session_state.get('last_pcap_path')
        if prev_path and os.path.exists(prev_path):
            try:
                os.unlink(prev_path)
            except Exception:
                pass
    except Exception:
        pass
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_file_path = tmp_file.name
    # Persist for re-analysis actions
    st.session_state.last_pcap_path = tmp_file_path
    # Save TLS key log temporarily if provided
    tls_keylog_path = None
    if tls_keylog_upload is not None:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tls_file:
                tls_file.write(tls_keylog_upload.getvalue())
                tls_keylog_path = tls_file.name
                st.session_state.last_tls_keylog_path = tls_keylog_path
        except Exception as e:
            st.warning(f"Could not save TLS key log file: {e}")
    
    # Progress container
    progress_container = st.empty()
    
    with progress_container.container():
        st.markdown("🔍 Analysis in Progress...")
        progress_bar = st.progress(0)
        ai_live_container = st.container()
    
    try:
        # Initialize analyzer
        analyzer = WebPcapAnalyzer()
        
        # Update progress
        progress_bar.progress(25)
        st.text("📊 Analyzing PCAP Structure...")
        
        # Perform analysis
        results = analyzer.analyze_file(tmp_file_path, search_options, custom_regex, user_decrypt_key=user_decrypt_key, tls_keylog_file=tls_keylog_path, display_filter=display_filter, yara_rules=yara_rules)
        # Track source for grounded summaries and re-analysis
        results['source_pcap'] = tmp_file_path
        
        # Update progress
        progress_bar.progress(75)
        st.text("🤖 Running AI Analysis...")
        
        # AI Analysis if enabled
        if ai_enabled and ai_mode != "📊 Standard Only":
            try:
                config = AgentConfig.load_config()
                model = config.get('model', 'LongCat-Flash-Chat')
                api_key = config.get('longcat_api_key') or config.get('openrouter_api_key')
                
                # Check if current model is rate limited
                rate_handler = st.session_state.rate_limit_handler
                if model in rate_handler.rate_limit_errors:
                    st.warning(f"⚠️ Current model '{model}' is rate limited. Switching to offline analysis mode.")
                    ai_enabled = False
                    results['ai_status'] = 'rate_limited'
                    results['ai_error'] = f"Model {model} is rate limited. Offline analysis completed successfully."
                else:
                    # Start AI monitoring
                    if st.session_state.ai_monitor:
                        st.session_state.ai_monitor.start_monitoring(ai_mode)
                        st.session_state.ai_monitor.update_phase("Initializing AI Agent", 0.1)
                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                    
                    agent = create_agent(api_key, model)
                    if agent:
                        # Backward compatible: only call if method exists (older agents may not expose it)
                        if hasattr(agent, 'set_confidence_thresholds'):
                            agent.set_confidence_thresholds(
                                min_confidence=confidence_threshold,
                                flag_threshold=max(confidence_threshold, 85),
                                credential_threshold=max(confidence_threshold, 90)
                            )
                        else:
                            # Soft-set attributes if supported; ignore if not present
                            try:
                                setattr(agent, 'min_confidence_threshold', confidence_threshold)
                                setattr(agent, 'flag_confidence_threshold', max(confidence_threshold, 85))
                                setattr(agent, 'credential_confidence_threshold', max(confidence_threshold, 90))
                            except Exception:
                                pass
                        
                        with open(tmp_file_path, 'rb') as f:
                            raw_data = f.read()
                        packet_text = raw_data.decode('utf-8', errors='ignore')[:15000]

                        # Enrich AI context with TLS key log snippet and decrypted TLS snippets
                        try:
                            tls_context_parts = []
                            if tls_keylog_upload is not None and 'name' in dir(tls_keylog_upload):
                                # We saved the file earlier; try reusing the saved path if available
                                try:
                                    if 'tls_keylog_path' in locals() and tls_keylog_path and os.path.exists(tls_keylog_path):
                                        with open(tls_keylog_path, 'r', errors='ignore') as tf:
                                            tls_text = tf.read(1000)
                                            if tls_text:
                                                tls_context_parts.append("[TLS Key Log Snippet]\n" + tls_text)
                                except Exception:
                                    pass

                            # Include a few decrypted TLS snippets from results
                            tls_snips = []
                            for d in (results.get('decoded_data') or [])[:50]:
                                if d.get('type') in ('tls_decrypted', 'tls', 'https_tls', 'dns_exfil'):
                                    res = str(d.get('result', ''))
                                    if res:
                                        tls_snips.append(res[:500])
                                if len(tls_snips) >= 5:
                                    break
                            if tls_snips:
                                tls_context_parts.append("[Decrypted TLS / DNS Exfil Snippets]\n" + "\n---\n".join(tls_snips))

                            if tls_context_parts:
                                packet_text = packet_text + "\n\n" + "\n\n".join(tls_context_parts)
                        except Exception:
                            # Non-fatal, just skip
                            pass
                        
                        # Update AI monitor
                        if st.session_state.ai_monitor:
                            st.session_state.ai_monitor.update_phase("Running AI Analysis", 0.3)
                            st.session_state.ai_monitor.log_activity("🤖 AI Agent initialized and analyzing", "info")
                            st.session_state.ai_monitor.display_monitor(ai_live_container)
                        
                        # Specialized AI Analysis based on mode
                        try:
                            if "🎯 Deep Flag Hunt" in ai_mode:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Deep Flag Hunting", 0.5)
                                    st.session_state.ai_monitor.log_activity("🎯 Deep flag hunting mode activated", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                ai_findings = agent.flag_hunter_analysis(packet_text, ctf_context)
                                results['ai_findings'] = ai_findings
                                
                            elif "🔬 Protocol Analysis" in ai_mode:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Protocol Analysis", 0.5)
                                    st.session_state.ai_monitor.log_activity("🔬 Protocol analysis in progress", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                protocol_analysis = agent.protocol_analyzer_analysis(packet_text, ctf_context)
                                results['protocol_analysis'] = protocol_analysis
                                
                            elif "🔐 Credential Hunt" in ai_mode:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Credential Hunting", 0.5)
                                    st.session_state.ai_monitor.log_activity("🔐 Credential hunting mode activated", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                credential_analysis = agent.credential_harvester_analysis(packet_text, ctf_context)
                                results['credential_analysis'] = credential_analysis
                                
                            elif "🧠 Behavioral Analysis" in ai_mode:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Behavioral Analysis", 0.5)
                                    st.session_state.ai_monitor.log_activity("🧠 Behavioral analysis in progress", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                behavioral_analysis = agent.behavioral_analysis(packet_text, "Network Traffic Analysis", ctf_context)
                                results['behavioral_analysis'] = behavioral_analysis
                                
                            else:  # Enhanced Analysis
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Enhanced Analysis", 0.5)
                                    st.session_state.ai_monitor.log_activity("🧠 Enhanced analysis mode activated", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                ai_analysis = agent.analyze_findings(results['findings'], packet_text)
                                results['ai_analysis'] = ai_analysis
                                
                                if ctf_context and (ctf_context.get('description') or ctf_context.get('hints')):
                                    enhanced_flag_hunt = agent.flag_hunter_analysis(packet_text, ctf_context)
                                    results['enhanced_flag_hunt'] = enhanced_flag_hunt
                                
                                ai_findings = agent.hunt_hidden_flags(packet_text, "Enhanced Mode")
                                results['ai_findings'] = ai_findings
                            
                            # Multi-Agent System Analysis
                            if st.session_state.multi_agent_system:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Multi-Agent Coordination", 0.7)
                                    st.session_state.ai_monitor.log_activity("🤖 Coordinating multi-agent analysis", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                try:
                                    # Run multi-agent analysis synchronously
                                    import asyncio
                                    
                                    # Create event loop for async execution
                                    try:
                                        loop = asyncio.get_event_loop()
                                    except RuntimeError:
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                    
                                    # Run the async function synchronously
                                    multi_agent_results = loop.run_until_complete(
                                        st.session_state.multi_agent_system.coordinate_analysis(packet_text, results['findings'])
                                    )
                                    results['multi_agent_analysis'] = multi_agent_results
                                    
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.log_activity("✅ Multi-agent analysis completed", "success")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                                except Exception as e:
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.log_activity(f"⚠️ Multi-agent analysis failed: {str(e)}", "warning")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                            
                            # Workflow Orchestration
                            if st.session_state.workflow_orchestrator:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.update_phase("Workflow Execution", 0.8)
                                    st.session_state.ai_monitor.log_activity("🔄 Executing analysis workflows", "info")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                                
                                try:
                                    # Initialize required components for workflow
                                    from utils.parsers import PacketParser
                                    from utils.patterns import PatternMatcher
                                    from analyzers.ctf.ctf_analyzer import NetworkTrafficDecoder, EncodingDecoder, CTFAnalyzer
                                    
                                    packet_parser = PacketParser()
                                    pattern_matcher = PatternMatcher()
                                    network_decoder = NetworkTrafficDecoder()
                                    encoding_decoder = EncodingDecoder()
                                    ctf_analyzer = CTFAnalyzer()
                                    
                                    # Execute network CTF workflow with proper components
                                    workflow = create_network_ctf_workflow(
                                        st.session_state.workflow_orchestrator,
                                        packet_parser,
                                        pattern_matcher,
                                        network_decoder,
                                        encoding_decoder,
                                        ctf_analyzer
                                    )
                                    
                                    # Execute the workflow
                                    try:
                                        st.session_state.workflow_orchestrator.start_workflow("network_ctf", results)
                                        workflow_results = st.session_state.workflow_orchestrator.execute_all_steps()
                                        results['workflow_results'] = workflow_results
                                    except Exception as workflow_error:
                                        st.warning(f"Workflow execution warning: {workflow_error}")
                                        results['workflow_results'] = {'error': str(workflow_error)}
                                    
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.log_activity("✅ Workflow execution completed", "success")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                                except Exception as e:
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.log_activity(f"⚠️ Workflow execution failed: {str(e)}", "warning")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                            
                            # Verifying agent: validate AI/decoded claims and adjust confidence
                            try:
                                if agent:
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.update_phase("Verifying AI Findings", 0.9)
                                        st.session_state.ai_monitor.log_activity("🔎 Running verifying agent", "info")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                                    ver = agent.verify_findings(results)
                                    if isinstance(ver, dict):
                                        # Merge verified ctf_analysis and add verification report
                                        if ver.get('ctf_analysis'):
                                            results['ctf_analysis'] = ver['ctf_analysis']
                                        if ver.get('verification_report'):
                                            results['verification_report'] = ver['verification_report']
                            except Exception as e:
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.log_activity(f"⚠️ Verifying agent failed: {str(e)}", "warning")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)

                            suggestions = agent.suggest_next_steps(results['findings'], f"Mode: {ai_mode}")
                            results['ai_suggestions'] = suggestions
                            
                            # Final AI monitor update
                            if st.session_state.ai_monitor:
                                st.session_state.ai_monitor.update_phase("Analysis Complete", 1.0)
                                st.session_state.ai_monitor.log_activity("🎉 AI analysis completed successfully", "success")
                                st.session_state.ai_monitor.display_monitor(ai_live_container)
                            
                        except Exception as ai_error:
                            # Handle specific AI errors
                            error_msg = str(ai_error)
                            
                            if "429" in error_msg or "rate" in error_msg.lower() or "temporarily rate-limited" in error_msg:
                                # Rate limit detected
                                fallback_model = rate_handler.handle_rate_limit(model, error_msg)
                                if fallback_model:
                                    st.warning(f"⚠️ Model '{model}' hit rate limit. Switching to '{fallback_model}'...")
                                    if st.session_state.ai_monitor:
                                        st.session_state.ai_monitor.log_activity(f"⚠️ Switching to fallback model: {fallback_model}", "warning")
                                        st.session_state.ai_monitor.display_monitor(ai_live_container)
                                    # Try with fallback model
                                    try:
                                        fallback_agent = create_agent(api_key, fallback_model)
                                        if fallback_agent:
                                            # Quick retry with fallback
                                            ai_findings = fallback_agent.hunt_hidden_flags(packet_text, "Fallback Mode")
                                            results['ai_findings'] = ai_findings
                                            results['ai_status'] = 'fallback_success'
                                            results['ai_fallback_model'] = fallback_model
                                    except Exception as fallback_error:
                                        st.warning(f"⚠️ Fallback model also failed: {str(fallback_error)}")
                                        results['ai_status'] = 'fallback_failed'
                                        results['ai_error'] = str(fallback_error)
                                else:
                                    st.warning("⚠️ All AI models are rate limited. Continuing with offline analysis.")
                                    results['ai_status'] = 'all_models_rate_limited'
                                    results['ai_error'] = "All AI models are currently rate limited"
                            else:
                                # Other AI error
                                st.error(f"❌ AI analysis error: {error_msg}")
                                results['ai_status'] = 'error'
                                results['ai_error'] = error_msg
                                
                                if st.session_state.ai_monitor:
                                    st.session_state.ai_monitor.log_activity(f"❌ AI analysis failed: {error_msg}", "error")
                                    st.session_state.ai_monitor.display_monitor(ai_live_container)
                    
            except Exception as e:
                if st.session_state.ai_monitor:
                    st.session_state.ai_monitor.log_activity(f"❌ AI analysis failed: {str(e)}", "error")
                st.error(f"AI analysis failed: {str(e)}")
                results['ai_status'] = 'failed'
                results['ai_error'] = str(e)
        
        # Complete
        progress_bar.progress(100)
        st.text("✅ Analysis Complete!")
        
        # Store results with CTF context
        if ctf_context:
            results['ctf_context'] = ctf_context
        st.session_state.analysis_results = results
        # Persist last run options for Copilot re-analysis
        st.session_state.last_search_options = search_options
        st.session_state.last_custom_regex = custom_regex
        st.session_state.last_user_decrypt_key = user_decrypt_key
        
        # Show success message
        findings_count = len(results.get('findings', []))
        ai_findings_count = len(results.get('ai_findings', []))
        
        st.success(f"🎉 Analysis complete! Found {findings_count} standard findings and {ai_findings_count} AI discoveries")
        
        # Auto-switch to results page
        st.session_state.current_page = 'results'
        st.rerun()
        
    except Exception as e:
        progress_container.empty()
        st.error(f"❌ Analysis failed: {str(e)}")
    
    finally:
        # Intentionally keep the saved PCAP and TLS key log in session for Copilot re-analysis actions
        # Cleanup will occur on next upload or when the session ends
        pass

def run_demo_analysis(ai_enabled=False, mode="standard"):
    """Run demo analysis"""
    if not IMPORTS_OK:
        st.error("Demo unavailable - Import error detected")
        return
    
    progress_container = st.empty()
    
    with progress_container.container():
        st.markdown("🎮 Running Demo Analysis...")
        progress_bar = st.progress(0)
    
    try:
        # Get demo results
        demo_results = analyze_sample_pcap()
        
        if ai_enabled:
            # Add AI demo data
            demo_results['ai_findings'] = [
                {
                    'flag_candidate': 'CTF{d3m0_fl4g_h1dd3n_1n_dns}',
                    'confidence': 92,
                    'reasoning': 'Found base64-encoded flag in DNS subdomain query',
                    'source': 'ai_hunting'
                },
                {
                    'flag_candidate': 'FLAG{t1m1ng_4tt4ck_d3t3ct3d}',
                    'confidence': 78,
                    'reasoning': 'Detected timing-based steganography in packet intervals',
                    'source': 'ai_hunting'
                }
            ]
            
            demo_results['ai_suggestions'] = [
                'Decode all base64 strings found in DNS queries',
                'Analyze packet timing patterns for steganographic messages',
                'Check HTTP headers for additional hidden flags'
            ]
        
        progress_bar.progress(100)
        st.text("✅ Demo Complete!")
        
        # Store results
        st.session_state.analysis_results = demo_results
        
        st.success("🎮 Demo analysis complete!")
        
        # Auto-switch to results
        st.session_state.current_page = 'results'
        st.rerun()
        
    except Exception as e:
        progress_container.empty()
        st.error(f"❌ Demo failed: {str(e)}")

def export_results(results, format_type):
    """Export results in specified format"""
    if not IMPORTS_OK:
        st.error("Export unavailable - Import error detected")
        return
    
    try:
        analyzer = WebPcapAnalyzer()
        analyzer.results = results
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"flagsniff_results_{timestamp}.{format_type}"
        
        exported_data = analyzer.export_results(format_type)
        
        # Set appropriate MIME type
        if format_type.lower() == 'csv':
            mime = "text/csv"
        elif format_type.lower() == 'html':
            mime = "text/html"
        else:  # json
            mime = "application/json"
        
        st.download_button(
            label=f"📥 Download {format_type.upper()}",
            data=exported_data,
            file_name=filename,
            mime=mime,
            type="primary"
        )
        
        st.success(f"✅ {format_type.upper()} export ready!")
        
    except Exception as e:
        st.error(f"❌ Export failed: {str(e)}")

def main():
    """Main application"""
    
    # Apply theme styles
    st.markdown(get_theme_styles(), unsafe_allow_html=True)
    
    # Render Copilot sidebar - moved after navigation/hero to ensure it renders
    # Render navigation
    render_navigation()
    
    # Render hero section
    render_hero()
    
    # Render Copilot sidebar (right)
    try:
        render_copilot_sidebar()
    except Exception as e:
        # Keep main UI functional even if sidebar fails
        st.sidebar.warning(f"Copilot: {str(e)[:100]}")
    
    # Render current page based on session state
    if st.session_state.current_page == 'analyzer':
        render_analyzer_page()
    elif st.session_state.current_page == 'ai_config':
        render_ai_config_page()
    elif st.session_state.current_page == 'results':
        render_results_page()
    elif st.session_state.current_page == 'advanced':
        render_advanced_page()
    elif st.session_state.current_page == 'about':
        render_about_page()
    else:
        # Fallback to analyzer if unknown page
        st.session_state.current_page = 'analyzer'
        render_analyzer_page()

if __name__ == "__main__":
    main()
