import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import tempfile
import os
from pathlib import Path
import time

# Import enhanced analyzer and AI agent
from apps.web_analyzer import WebPcapAnalyzer, analyze_sample_pcap
from ai.ai_agent import create_agent, AgentConfig

# Optional CTF visualizations import
try:
    from analyzers.ctf.ctf_visualizations import CTFVisualizer
    HAS_CTF_VIZ = True
except ImportError:
    HAS_CTF_VIZ = False
    CTFVisualizer = None

# Page config with clean branding
st.set_page_config(
    page_title="FlagSniff",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'analyzer'
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None

def get_theme_styles():
    # Return CSS based on the current theme. Use a safe default.
    theme = st.session_state.get('theme', 'light')
    if theme == 'dark':
        return """
        <style>
        /* Dark theme base */
        .stApp { background: #0f172a; color: #e6eef8; font-family: 'Inter', sans-serif; }
        .nav-container { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); }
        .glass-card { background: rgba(255,255,255,0.03); color: #e6eef8; }
        </style>
        """
    else:
        return """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        .stApp {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 50%, #bae6fd 100%);
            font-family: 'Inter', sans-serif;
        }
        /* Hide Streamlit branding */
        #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
        .nav-container { background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(20px); border-radius: 20px; padding: 1rem 2rem; margin: 1rem 0 2rem 0; text-align: center; }
        .nav-brand { font-size: 1.8rem; font-weight: 700; }
        .nav-links { display: flex; gap: 1rem; justify-content: center; }
        .nav-link { color: rgba(0,0,0,0.7); text-decoration: none; padding: 0.4rem 0.8rem; border-radius: 8px; }
        .glass-card { background: rgba(255,255,255,0.85); backdrop-filter: blur(20px); border-radius: 20px; padding: 2rem; color: #1e293b; }
        </style>
        """

def render_navigation():
    """Render a single, working navigation bar"""
    theme_icon = "🌙" if st.session_state.get('theme', 'light') == 'light' else "☀️"
    # Minimal, valid navigation HTML to avoid parser errors from malformed markup
    st.markdown("""
    <div class="nav-container">
        <div class="nav-brand">FlagSniff Pro</div>
        <div class="nav-links">
            <a class="nav-link" href="#" onclick="window.location.hash='analyzer'">Analyzer</a>
            <a class="nav-link" href="#" onclick="window.location.hash='ai_config'">AI Config</a>
            <a class="nav-link" href="#" onclick="window.location.hash='results'">Results</a>
            <a class="nav-link" href="#" onclick="window.location.hash='about'">About</a>
        </div>
        <div style="margin-top:0.4rem; font-size:0.9rem;">Configure API key to enable AI features</div>
    </div>
    """, unsafe_allow_html=True)

    # Continue with existing setup wizard logic
    # ...existing code...
def _execute_copilot_actions(actions, results, agent=None):
    """Small set of safe, local actions over current results for the sidebar."""
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
                    outs.append(f"- {f.get('display_type', f.get('type',''))} [{f.get('confidence',0)}%]")
            elif at == 'show_decoded':
                dec = results.get('decoded_data', [])[:10]
                outs.append(f"Decoded items (top {len(dec)}):")
                for d in dec:
                    chain = ' -> '.join(d.get('chain', [])) if d.get('chain') else ''
                    txt = (d.get('decoded') or d.get('result',''))
                    outs.append(f"- {chain}: {str(txt)[:100]}")
            elif at == 'show_ctf_flags':
                flags = (results.get('ctf_analysis', {}).get('flag_candidates', []) or [])[:10]
                outs.append(f"Flag candidates (top {len(flags)}):")
                for c in flags:
                    outs.append(f"- [{c.get('confidence',0)}%] {c.get('flag')}")
    except Exception as e:
        outs.append(f"Execution error: {e}")
    return outs

def render_copilot_sidebar():
    """Widget-based Copilot sidebar for reliability across Streamlit versions."""
    try:
        # Scoped visual styles
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

        # Header card
        st.sidebar.markdown("<div class=\"sb-card\"><div style=\"font-weight:700; display:flex; justify-content:space-between;\">🤝 Copilot <span id=\"wb_status\"></span></div></div>", unsafe_allow_html=True)

        # Model/status
        try:
            cfg = AgentConfig.load_config()
            model_name = (cfg.get('model') or 'offline').split('/')[-1]
            api_key_present = bool(cfg.get('openrouter_api_key'))
        except Exception:
            model_name = 'offline'
            api_key_present = False
        st.sidebar.markdown(
            f"""
            <div class="sb-card">
                <div class="sb-row" style="justify-content:space-between;">
                    <div class="sb-row"><span class="sb-chip blue">Model: <code>{model_name}</code></span></div>
                    <span class="sb-chip {'green' if api_key_present else 'amber'}">{'Online' if api_key_present else 'Offline'}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # State
        if 'copilot_history' not in st.session_state:
            st.session_state.copilot_history = []

        # Handler
        def _handle_query(q: str):
            if not q:
                return
            st.session_state.copilot_history.append({'role':'user','content':q,'ts':time.time()})
            results = st.session_state.get('analysis_results')
            if not results:
                st.session_state.copilot_history.append({'role':'assistant','content':'Please run an analysis first.','ts':time.time()})
                st.rerun()
            agent = None
            try:
                cfg_local = AgentConfig.load_config()
                api_key = cfg_local.get('openrouter_api_key')
                model = cfg_local.get('model')
                if api_key and model:
                    agent = create_agent(api_key, model)
            except Exception:
                agent = None
            # Simple plan
            if agent:
                plan = agent.plan_actions(q, results)
                answer = plan.get('answer') or ''
                actions = plan.get('actions') or []
            else:
                answer = "I'll run local searches over your results."
                actions = []
                ql = q.lower()
                if 'flag' in ql:
                    actions.append({'type':'show_ctf_flags','params':{}})
                if 'decoded' in ql or 'decode' in ql:
                    actions.append({'type':'show_decoded','params':{}})
                if 'findings' in ql:
                    actions.append({'type':'list_findings','params':{'limit':10}})
            outs = _execute_copilot_actions(actions, results, agent)
            ai_text = None
            if agent:
                try:
                    resp = agent.answer_query(q, results)
                    ai_text = (resp or {}).get('text')
                except Exception:
                    ai_text = None
            text_out = (ai_text or answer or '').strip()
            if outs:
                text_out = (text_out + "\n\n" + "\n".join(outs[:6])).strip()
            st.session_state.copilot_history.append({'role':'assistant','content':text_out,'ts':time.time()})
            st.rerun()

        # Quick metrics
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
        tcols = st.sidebar.columns([1,1])
        if tcols[0].button("➕ New Chat", key="wb_copilot_new"):
            st.session_state.copilot_history = []
            st.rerun()
        if tcols[1].button("🧹 Clear", key="wb_copilot_clear"):
            st.session_state.copilot_history = []
            st.rerun()

        # History or welcome
        holder = st.sidebar.container()
        if st.session_state.copilot_history:
            for m in st.session_state.copilot_history[-20:]:
                prefix = "🧑‍💻" if m.get('role') == 'user' else "🤖"
                ts = m.get('ts')
                meta = ''
                if ts:
                    try:
                        meta = datetime.fromtimestamp(float(ts)).strftime('%H:%M')
                    except Exception:
                        meta = ''
                safe_text = str(m.get('content','')).replace('<','&lt;').replace('>','&gt;')
                cls = 'user' if m.get('role') == 'user' else 'assistant'
                holder.markdown(
                    f"""
                    <div class="sb-msg {cls}">
                        <div><strong>{prefix} {meta}</strong></div>
                        <div style=\"margin-top:6px;\">{safe_text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            holder.info("Hello! I'm your PCAP Copilot. Ask about findings, decoded data, or streams.")
            sugg = ["Summarize the analysis","List flag candidates","Verify flags"]
            res = st.session_state.get('analysis_results') or {}
            streams = (res.get('reconstructed_streams') or {})
            if streams:
                first_id = list(streams.keys())[0]
                sugg.append(f"Explain stream {first_id}")
            sc = holder.columns(min(3, max(1, len(sugg))))
            for i, s in enumerate(sugg):
                if sc[i % len(sc)].button(s, key=f"wb_sugg_{i}"):
                    _handle_query(s)

        # Input
        st.sidebar.markdown('<div class="sb-section-title">Ask about this PCAP…</div>', unsafe_allow_html=True)
        q = st.sidebar.text_input("Ask about this PCAP…", key="wb_copilot_input", placeholder="e.g., list probable flags, explain stream")
        send_cols = st.sidebar.columns([3,1])
        if send_cols[1].button("Send", key="wb_copilot_send"):
            _handle_query(st.session_state.get('wb_copilot_input',''))
    except Exception as e:
        st.sidebar.error(f"Copilot error: {e}")
def render_hero():
    """Render the hero section"""
    hero_html = """
    <div class="hero-section fade-in">
        <div class="hero-title">Next-Gen PCAP Analysis</div>
        <div class="hero-subtitle">
            Powered by Advanced AI • Built for Security Professionals • Optimized for CTF
        </div>
    </div>
    """
    st.markdown(hero_html, unsafe_allow_html=True)

def render_analyzer_page():
    """Render the main analyzer page"""
    st.markdown('<div class="fade-in">', unsafe_allow_html=True)
    
    # Feature cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🚩</div>
            <div class="feature-title">Flag Hunter</div>
            <div class="feature-desc">Advanced pattern recognition for CTF flags</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🔐</div>
            <div class="feature-title">Credential Extractor</div>
            <div class="feature-desc">Detect passwords, tokens, and API keys</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🤖</div>
            <div class="feature-title">AI Analysis</div>
            <div class="feature-desc">Machine learning powered insights</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">⚡</div>
            <div class="feature-title">Real-time</div>
            <div class="feature-desc">Lightning fast processing</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Main analyzer interface
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    # File upload
    st.markdown("### 📁 Upload PCAP File")
    uploaded_file = st.file_uploader(
        "Choose your PCAP file",
        type=['pcap', 'pcapng'],
        help="Upload .pcap or .pcapng files for analysis"
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
        
        with col2:
            st.markdown("**🤖 AI Configuration**")
            
            # Check AI status
            current_api_key = AgentConfig.get_api_key()
            ai_enabled = current_api_key is not None
            
            if ai_enabled:
                current_config = AgentConfig.load_config()
                current_model = current_config.get('model', 'neversleep/llama-3-lumimaid-8b')
                
                st.markdown(f"""
                <div class="ai-status">
                    <div class="status-online">🟢 AI Agent Online</div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem;">
                        Model: <code>{current_model.split('/')[-1]}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
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
                st.markdown("""
                <div class="ai-status">
                    <div class="status-offline">🔴 AI Agent Offline</div>
                    <div style="margin-top: 0.5rem; font-size: 0.9rem;">
                        Configure API key to enable AI features
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                
                ai_mode = "📊 Standard Only"
                confidence_threshold = 70
        
        # Custom regex
        st.markdown("### 🎯 Custom Pattern")
        custom_regex = st.text_input(
            "Custom Regex Pattern",
            placeholder="flag\\{.*?\\}",
            help="Enter your custom regex pattern for specialized searches"
        )
        
        # CTF Challenge Context Section
        st.markdown("### 🏆 CTF Challenge Context")
        st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(255, 215, 0, 0.1) 0%, rgba(255, 140, 0, 0.1) 100%); 
                    padding: 1.5rem; border-radius: 15px; margin: 1rem 0; border: 1px solid rgba(255, 215, 0, 0.3);">
            <h5 style="margin: 0; color: #FFD700;">🧠 Challenge Intelligence</h5>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">
                Provide challenge description or hints to help XBOW understand the context and generate better POCs
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            challenge_description = st.text_area(
                "Challenge Description",
                placeholder="e.g., 'Find the hidden flag in network traffic. The admin mentioned something about DNS...",
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
        
        # Challenge category for better context
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
            help="Select the challenge category to help XBOW focus its analysis"
        )
        
        # Analysis button
        st.markdown("--- ")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🚀 START ANALYSIS", key="analyze_btn", width='stretch'):
                # Prepare CTF context
                ctf_context = {
                    'description': challenge_description,
                    'hints': challenge_hints,
                    'category': challenge_category
                }
                
                run_analysis(uploaded_file, {
                    'flags': search_flags,
                    'credentials': search_creds,
                    'tokens': search_tokens,
                    'emails': search_emails,
                    'hashes': search_hashes
                }, custom_regex, ai_mode, ai_enabled, confidence_threshold, ctf_context)
    
    else:
        # Upload area
        st.markdown("""
        <div class="upload-area">
            <div style="font-size: 3rem; margin-bottom: 1rem;">📁</div>
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 0.5rem;">
                Drop your PCAP file here
            </div>
            <div style="color: rgba(255, 255, 255, 0.7);">
                Supports .pcap and .pcapng formats
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Demo buttons
        st.markdown("### 🎮 Try Demo")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🧪 Demo Standard", width='stretch'):
                run_demo_analysis(False)
        
        with col2:
            if st.button("🤖 Demo AI", width='stretch', disabled=not AgentConfig.get_api_key()):
                run_demo_analysis(True)
        
        with col3:
            if st.button("🔍 Demo Deep Hunt", width='stretch', disabled=not AgentConfig.get_api_key()):
                run_demo_analysis(True, "deep_hunt")
    
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

def render_ai_config_page():
    """Render the AI configuration page"""
    st.markdown('<div class="glass-card fade-in">', unsafe_allow_html=True)
    
    st.markdown("### 🤖 AI Agent Configuration")
    
    # Free models highlight
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(0, 255, 136, 0.1) 0%, rgba(0, 245, 255, 0.1) 100%); 
                padding: 1rem; border-radius: 10px; margin: 1rem 0; border: 1px solid rgba(0, 255, 136, 0.3);">
        <h4 style="margin: 0; color: #00ff88;">🆓 FREE AI Models Available!</h4>
        <p style="margin: 0.5rem 0 0 0;">
            Start with free models like Venice Uncensored, GPT-OSS-20B, or Qwen3 - no API costs required!
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Current status
    current_config = AgentConfig.load_config()
    current_api_key = AgentConfig.get_api_key()
    current_model = current_config.get('model', 'neversleep/llama-3-lumimaid-8b')
    
    if current_api_key:
        st.markdown(f"""
        <div class="ai-status">
            <div class="status-online">🟢 AI Agent Configured</div>
            <div style="margin-top: 1rem;">
                <strong>Current Model:</strong> <code>{current_model}</code><br>
                <strong>Setup Date:</strong> {current_config.get('setup_date', 'Unknown')}<br>
                <strong>Status:</strong> Ready for analysis
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Model change section (only show if API key exists)
        st.markdown("### 🔄 Change AI Model")
        
        model_options = {
            # FREE MODELS
            "neversleep/llama-3-lumimaid-8b": "🆓 Venice: Uncensored - FREE uncensored model",
            "openai/gpt-oss-20b": "🆓 OpenAI: GPT-OSS-20B - FREE OpenAI model",
            "qwen/qwen-2.5-72b-instruct": "🆓 Qwen: Qwen3 235B A22B - FREE advanced reasoning",
            "cognitivecomputations/dolphin-mistral-24b-venice-edition:free": "🆓 Dolphin Mistral Venice - FREE enhanced model",
            "openai/gpt-3.5-turbo": "💰 GPT-3.5 Turbo - Affordable and reliable",
            
            # PREMIUM MODELS
            "anthropic/claude-3.5-sonnet": "🧠 Claude 3.5 Sonnet (Recommended)",
            "anthropic/claude-3-haiku": "⚡ Claude 3 Haiku (Fast)",
            "openai/gpt-4-turbo": "🚀 GPT-4 Turbo (Creative)",
            "openai/gpt-4o-mini": "💡 GPT-4o Mini (Efficient)",
            "google/gemini-pro-1.5": "🔍 Gemini Pro 1.5 (Analytical)",
            "google/gemini-flash-1.5": "⚡ Gemini Flash 1.5 (Ultra Fast)",
            "meta-llama/llama-3.1-70b-instruct": "🦙 Llama 3.1 70B (Powerful)",
            "meta-llama/llama-3.1-8b-instruct": "🦙 Llama 3.1 8B (Budget)",
            "mistralai/mistral-7b-instruct": "🌟 Mistral 7B (European)",
            "anthropic/claude-3-opus": "👑 Claude 3 Opus (Premium)"
        }
        
        # Find current model index
        current_index = 0
        if current_model in model_options:
            current_index = list(model_options.keys()).index(current_model)
        
        selected_model = st.selectbox(
            "Select AI Model",
            list(model_options.keys()),
            format_func=lambda x: model_options[x],
            index=current_index,
            key="model_selector"
        )
        
        # Model info
        model_info = {
            # FREE MODELS
            "neversleep/llama-3-lumimaid-8b": {"cost": "FREE", "speed": "Fast", "strength": "Uncensored responses"},
            "openai/gpt-oss-20b": {"cost": "FREE", "speed": "Medium", "strength": "OpenAI architecture"},
            "qwen/qwen-2.5-72b-instruct": {"cost": "FREE", "speed": "Medium", "strength": "Advanced reasoning"},
            "cognitivecomputations/dolphin-mistral-24b-venice-edition:free": {"cost": "FREE", "speed": "Fast", "strength": "Enhanced reasoning"},
            "openai/gpt-3.5-turbo": {"cost": "Low", "speed": "Fast", "strength": "Reliable and affordable"},
            
            # PREMIUM MODELS
            "anthropic/claude-3.5-sonnet": {"cost": "Medium", "speed": "Fast", "strength": "Best overall"},
            "anthropic/claude-3-haiku": {"cost": "Low", "speed": "Very Fast", "strength": "Quick insights"},
            "openai/gpt-4-turbo": {"cost": "High", "speed": "Medium", "strength": "Creative analysis"},
            "openai/gpt-4o-mini": {"cost": "Very Low", "speed": "Fast", "strength": "Cost-effective"},
            "google/gemini-pro-1.5": {"cost": "Low", "speed": "Fast", "strength": "Protocol analysis"},
            "google/gemini-flash-1.5": {"cost": "Very Low", "speed": "Very Fast", "strength": "Quick analysis"},
            "meta-llama/llama-3.1-70b-instruct": {"cost": "Low", "speed": "Medium", "strength": "Open source"},
            "meta-llama/llama-3.1-8b-instruct": {"cost": "Very Low", "speed": "Fast", "strength": "Budget option"},
            "mistralai/mistral-7b-instruct": {"cost": "Very Low", "speed": "Fast", "strength": "European model"},
            "anthropic/claude-3-opus": {"cost": "Very High", "speed": "Slow", "strength": "Most capable"}
        }
        
        if selected_model in model_info:
            info = model_info[selected_model]
            st.markdown(f"""
            <div style="background: rgba(0, 245, 255, 0.1); padding: 1rem; border-radius: 10px; margin: 1rem 0;">
                <div style="font-size: 0.9rem;">
                    💰 <strong>Cost:</strong> {info['cost']}<br>
                    ⚡ <strong>Speed:</strong> {info['speed']}<br>
                    🎯 <strong>Best for:</strong> {info['strength']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Change model button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🔄 CHANGE MODEL", width='stretch', disabled=selected_model == current_model):
                # Update only the model in the existing config
                current_config['model'] = selected_model
                current_config['setup_date'] = datetime.now().isoformat()
                AgentConfig.save_config(current_config)
                st.success(f"✅ Model changed to: {model_options[selected_model]}")
                st.balloons()
                time.sleep(1)
                st.rerun()
        
        if selected_model == current_model:
            st.info("💡 This model is already selected")
        
    else:
        st.markdown("""
        <div class="ai-status">
            <div class="status-offline">🔴 AI Agent Not Configured</div>
            <div style="margin-top: 1rem;">
                Configure your OpenRouter API key to enable AI features
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Initial setup form
        st.markdown("### ⚙️ Initial Setup")
        
        api_key_input = st.text_input(
            "OpenRouter API Key",
            type="password",
            value="",
            help="Get your API key from https://openrouter.ai/",
            placeholder="sk-or-v1-..."
        )
        
        if api_key_input:
            if st.button("🧪 Test API Key"):
                with st.spinner("Testing API connection..."):
                    try:
                        test_agent = create_agent(api_key_input, "neversleep/llama-3-lumimaid-8b")
                        if test_agent:
                            st.success("✅ API key is valid!")
                        else:
                            st.error("❌ API key test failed")
                    except Exception as e:
                        st.error(f"❌ Test failed: {str(e)}")
            
            if st.button("💾 SAVE API KEY", width='stretch'):
                config = {
                    'openrouter_api_key': api_key_input,
                    'model': 'neversleep/llama-3-lumimaid-8b',  # Default to Venice
                    'setup_date': datetime.now().isoformat(),
                    'version': '2.0'
                }
                AgentConfig.save_config(config)
                st.success("✅ Configuration saved successfully!")
                st.balloons()
                time.sleep(1)
                st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_setup_ai_page():
    """Render the comprehensive AI setup page"""
    st.markdown('<div class="glass-card fade-in">', unsafe_allow_html=True)
    
    st.markdown("### ⚙️ AI Agent Setup Wizard")
    
    # Welcome section
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(0, 245, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%); 
                padding: 2rem; border-radius: 15px; margin: 1rem 0; border: 1px solid rgba(0, 245, 255, 0.3);">
        <h3 style="margin: 0; color: #00f5ff;">🚀 Welcome to AI Setup!</h3>
        <p style="margin: 0.5rem 0 0 0;">
            Configure your AI agent for advanced PCAP analysis. Choose from FREE models or premium options.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Current status check
    current_config = AgentConfig.load_config()
    current_api_key = AgentConfig.get_api_key()
    
    if current_api_key:
        st.success("✅ AI Agent is already configured!")
        current_model = current_config.get('model', 'Unknown')
        st.info(f"Current model: **{current_model}**")
        
        if st.button("🔄 Reconfigure AI Agent", type="secondary"):
            # Clear current config for reconfiguration
            st.session_state.setup_step = 1
    else:
        st.warning("🤖 AI Agent not configured yet")
    
    # Setup wizard steps
    if 'setup_step' not in st.session_state:
        st.session_state.setup_step = 1
    
    # Step 1: Introduction and API Key Info
    if st.session_state.setup_step == 1:
        st.markdown("## 📋 Step 1: Get Your API Key")
        
        # OpenRouter information
        st.markdown("""
        <div style="background: rgba(255, 255, 255, 0.05); padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
            <h4>🔑 OpenRouter API Key</h4>
            <p><strong>OpenRouter</strong> provides access to multiple AI models through a single API.</p>
            
            <h5>🆓 FREE Models Available:</h5>
            <ul>
                <li><strong>Venice: Uncensored</strong> - Uncensored responses</li>
                <li><strong>OpenAI: GPT-OSS-20B</strong> - OpenAI architecture</li>
                <li><strong>Qwen: Qwen3 235B A22B</strong> - Advanced reasoning</li>
                <li><strong>Dolphin Mistral Venice</strong> - Enhanced reasoning</li>
            </ul>
            
            <h5>💰 Premium Models:</h5>
            <ul>
                <li><strong>Claude 3.5 Sonnet</strong> - Best overall performance</li>
                <li><strong>GPT-4 Turbo</strong> - Creative analysis</li>
                <li><strong>Gemini Pro</strong> - Fast and efficient</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Instructions
        st.markdown("### 📝 How to get your API key:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            1. **Visit** [OpenRouter.ai](https://openrouter.ai/)
            2. **Sign up** for a free account
            3. **Go to** the Keys section
            4. **Create** a new API key
            5. **Copy** the key (starts with `sk-or-v1-`)
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            💡 **Tips:**
            - Free models require no credits
            - Premium models need account credits
            - $5-10 is enough for extensive testing
            - You can start with free models
            """, unsafe_allow_html=True)
        
        # Continue button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("✅ I have my API key, continue", type="primary", width='stretch'):
                st.session_state.setup_step = 2
                st.rerun()
    
    # Step 2: API Key Input and Testing
    elif st.session_state.setup_step == 2:
        st.markdown("## 🔑 Step 2: Enter Your API Key")
        
        api_key_input = st.text_input(
            "OpenRouter API Key",
            type="password",
            placeholder="sk-or-v1-...",
            help="Paste your OpenRouter API key here"
        )
        
        if api_key_input:
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🧪 Test API Key", type="secondary", width='stretch'):
                    with st.spinner("Testing API connection..."):
                        try:
                            # Test with a simple model
                            test_agent = create_agent(api_key_input, "neversleep/llama-3-lumimaid-8b")
                            if test_agent:
                                st.success("✅ API key is valid!")
                                st.session_state.api_key_valid = True
                                st.session_state.temp_api_key = api_key_input
                            else:
                                st.error("❌ API key test failed")
                                st.session_state.api_key_valid = False
                        except Exception as e:
                            st.error(f"❌ Test failed: {str(e)}")
                            st.session_state.api_key_valid = False
            
            with col2:
                if st.session_state.get('api_key_valid', False):
                    if st.button("➡️ Continue to Model Selection", type="primary", width='stretch'):
                        st.session_state.setup_step = 3
                        st.rerun()
        
        # Back button
        if st.button("⬅️ Back to Step 1"):
            st.session_state.setup_step = 1
            st.rerun()
    
    # Step 3: Model Selection
    elif st.session_state.setup_step == 3:
        st.markdown("## 🤖 Step 3: Choose Your AI Model")
        
        # Model categories
        st.markdown("### 🆓 FREE Models (Recommended to start)")
        
        free_models = {
            "neversleep/llama-3-lumimaid-8b": {
                "name": "Venice: Uncensored",
                "description": "Uncensored AI responses for unrestricted analysis",
                "speed": "Fast",
                "cost": "FREE"
            },
            "openai/gpt-oss-20b": {
                "name": "OpenAI: GPT-OSS-20B", 
                "description": "OpenAI architecture with 20B parameters",
                "speed": "Medium",
                "cost": "FREE"
            },
            "qwen/qwen-2.5-72b-instruct": {
                "name": "Qwen: Qwen3 235B A22B",
                "description": "Advanced reasoning and instruction following",
                "speed": "Medium", 
                "cost": "FREE"
            },
            "cognitivecomputations/dolphin-mistral-24b-venice-edition:free": {
                "name": "Dolphin Mistral Venice",
                "description": "Enhanced reasoning with Mistral architecture",
                "speed": "Fast", 
                "cost": "FREE"
            }
        }
        
        # Free model selection
        selected_free_model = None
        for model_id, info in free_models.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"""
                <div style="background: rgba(0, 255, 136, 0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                    <h5 style="margin: 0; color: #00ff88;">🆓 {info['name']}</h5>
                    <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">{info['description']}</p>
                    <small>Speed: {info['speed']} | Cost: {info['cost']}</small>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                if st.button(f"Select", key=f"select_{model_id}", width='stretch'):
                    selected_free_model = model_id
                    st.session_state.selected_model = model_id
                    st.session_state.selected_model_name = info['name']
        
        st.markdown("### 💰 Premium Models (Require Credits)")
        
        premium_models = {
            "openai/gpt-3.5-turbo": {
                "name": "GPT-3.5 Turbo",
                "description": "Reliable and affordable",
                "speed": "Fast",
                "cost": "Low"
            },
            "anthropic/claude-3.5-sonnet": {
                "name": "Claude 3.5 Sonnet", 
                "description": "Best overall performance",
                "speed": "Fast",
                "cost": "Medium"
            },
            "openai/gpt-4-turbo": {
                "name": "GPT-4 Turbo",
                "description": "Most advanced analysis",
                "speed": "Medium",
                "cost": "High"
            }
        }
        
        # Premium model selection
        for model_id, info in premium_models.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"""
                <div style="background: rgba(255, 165, 0, 0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                    <h5 style="margin: 0; color: #ffa500;">💰 {info['name']}</h5>
                    <p style="margin: 0.5rem 0 0 0; font-size: 0.9rem;">{info['description']}</p>
                    <small>Speed: {info['speed']} | Cost: {info['cost']}</small>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                if st.button(f"Select", key=f"select_{model_id}", width='stretch'):
                    st.session_state.selected_model = model_id
                    st.session_state.selected_model_name = info['name']
        
        # Show selection and continue
        if 'selected_model' in st.session_state:
            st.success(f"✅ Selected: **{st.session_state.selected_model_name}**")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("⬅️ Back to API Key"):
                    st.session_state.setup_step = 2
                    st.rerun()
            with col2:
                if st.button("➡️ Complete Setup", type="primary", width='stretch'):
                    st.session_state.setup_step = 4
                    st.rerun()
    
    # Step 4: Final Configuration and Save
    elif st.session_state.setup_step == 4:
        st.markdown("## ✅ Step 4: Complete Setup")
        
        # Summary
        st.markdown("### 📋 Configuration Summary")
        
        api_key = st.session_state.get('temp_api_key', '')
        model = st.session_state.get('selected_model', '')
        model_name = st.session_state.get('selected_model_name', '')
        
        st.markdown(f"""
        <div style="background: rgba(0, 245, 255, 0.1); padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
            <h4>🎯 Your AI Configuration:</h4>
            <p><strong>API Key:</strong> {api_key[:20]}...{api_key[-10:] if len(api_key) > 30 else api_key}</p>
            <p><strong>Selected Model:</strong> {model_name}</p>
            <p><strong>Model ID:</strong> <code>{model}</code></p>
        </div>
        """, unsafe_allow_html=True)
        
        # Save configuration
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            if st.button("💾 Save Configuration", type="primary", width='stretch'):
                try:
                    config = {
                        'openrouter_api_key': api_key,
                        'model': model,
                        'setup_date': datetime.now().isoformat(),
                        'version': '2.0',
                        'setup_method': 'web_wizard'
                    }
                    AgentConfig.save_config(config)
                    
                    st.success("🎉 Configuration saved successfully!")
                    st.balloons()
                    
                    # Reset setup wizard
                    for key in ['setup_step', 'api_key_valid', 'temp_api_key', 'selected_model', 'selected_model_name']:
                        if key in st.session_state:
                            del st.session_state[key]
                    
                    time.sleep(2)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Failed to save configuration: {str(e)}")
        
        # Back button
        if st.button("⬅️ Back to Model Selection"):
            st.session_state.setup_step = 3
            st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_results_page():
    """Render the enhanced results page with CTF analysis"""
    st.markdown('<div class="glass-card fade-in">', unsafe_allow_html=True)
    
    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        visualizer = CTFVisualizer() if HAS_CTF_VIZ else None
        
        st.markdown("### 📊 Analysis Results")
        
        # Enhanced summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
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
        
        with col5:
            suspicious_count = len(results.get('suspicious_packets', []))
            st.metric("Suspicious Packets", suspicious_count)
        
        # CTF Challenge Context Display (if provided)
        if results.get('ctf_context'):
            ctf_ctx = results['ctf_context']
            if ctf_ctx.get('description') or ctf_ctx.get('hints'):
                st.markdown("--- ")
                st.markdown("### 🏆 CTF Challenge Context")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if ctf_ctx.get('description'):
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, rgba(255, 215, 0, 0.1) 0%, rgba(255, 140, 0, 0.1) 100%); 
                                    padding: 1rem; border-radius: 10px; margin: 0.5rem 0; border-left: 4px solid #FFD700;">
                            <h5 style="margin: 0; color: #FFD700;">📝 Challenge Description</h5>
                            <p style="margin: 0.5rem 0 0 0;">{ctf_ctx['description']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                
                with col2:
                    if ctf_ctx.get('hints'):
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, rgba(0, 245, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%); 
                                    padding: 1rem; border-radius: 10px; margin: 0.5rem 0; border-left: 4px solid #00f5ff;">
                            <h5 style="margin: 0; color: #00f5ff;">💡 Hints & Clues</h5>
                            <p style="margin: 0.5rem 0 0 0;">{ctf_ctx['hints']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                
                if ctf_ctx.get('category'):
                    st.markdown(f"""
                    <div style="text-align: center; margin: 1rem 0;">
                        <span style="background: rgba(255, 255, 255, 0.1); padding: 0.5rem 1rem; border-radius: 20px; font-weight: 600;">
                            📂 Category: {ctf_ctx['category']}
                        </span>
                    </div>
                    """, unsafe_allow_html=True)

        # Optional: Compact Tracking Pixels panel
        try:
            tp = results.get('tracking_pixels') or []
            if tp:
                st.markdown("---")
                st.markdown("### 🧿 Tracking Pixels (compact)")
                # Map packet_index -> time using timeline if available
                idx_to_time = {}
                try:
                    for ev in (results.get('timeline') or []):
                        if isinstance(ev, dict) and ev.get('type') == 'packet' and 'packet_index' in ev:
                            idx_to_time[ev['packet_index']] = ev.get('time')
                except Exception:
                    pass
                rows = []
                for e in tp[:1000]:
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
                        # Content-Length and Content-Type (per-response if available)
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
                    for r in rows[:50]:
                        st.write(f"[{r.get('time','')}] {r.get('host','')} {r.get('path','')} | {r.get('hints','')} | {r.get('token_decoded','')} | CL={r.get('CL','')} | CT={r.get('CT','')}")
        except Exception:
            pass
        
        # CTF Analysis Tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔍 Findings", "📊 Visualizations", "🕵️ Suspicious", "💡 Hints", "📈 Advanced"])
        
        with tab1:
            render_findings_tab(results)
        
        with tab2:
            render_visualizations_tab(results, visualizer)
        
        with tab3:
            render_suspicious_tab(results)
        
        with tab4:
            render_hints_tab(results)
        
        with tab5:
            render_advanced_tab(results)
        
        # Findings display
        if results.get('findings'):
            st.markdown("### 🔍 Detected Findings")
            
            for i, finding in enumerate(results['findings'][:10]):  # Show top 10
                confidence = finding.get('confidence', 50)
                if confidence >= 80:
                    card_class = "finding-high"
                elif confidence >= 60:
                    card_class = "finding-medium"
                else:
                    card_class = "finding-low"
                
                st.markdown(f"""
                <div class="result-card {card_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <div style="font-weight: 600; font-size: 1.1rem;">
                            {finding.get('icon', '🔍')} {finding.get('display_type', 'Finding')}
                        </div>
                        <div style="background: rgba(0, 245, 255, 0.2); padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem;">
                            {confidence}% confidence
                        </div>
                    </div>
                    <div style="font-family: monospace; background: rgba(0, 0, 0, 0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                        {finding.get('data', 'No data')[:100]}{'...' if len(finding.get('data', '')) > 100 else ''}
                    </div>
                    <div style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.7);">
                        <strong>Protocol:</strong> {finding.get('protocol', 'Unknown')} | 
                        <strong>Source:</strong> {finding.get('src_ip', 'N/A')} → {finding.get('dst_ip', 'N/A')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        # Enhanced AI findings with POCs
        if results.get('ai_findings'):
            st.markdown("### 🤖 AI Discoveries with POCs")
            
            for i, finding in enumerate(results['ai_findings'][:5]):  # Show top 5 AI findings
                confidence = finding.get('confidence', 50)
                
                with st.expander(f"🚩 AI Discovery #{i+1} - {confidence}% Confidence", expanded=True):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown("**🎯 Finding:**")
                        st.code(finding.get('flag_candidate', finding.get('data', 'No data')), language="text")
                        
                        if finding.get('reasoning'):
                            st.markdown("**🧠 AI Reasoning:**")
                            st.markdown(finding['reasoning'])
                    
                    with col2:
                        st.markdown("**📊 Details:**")
                        st.markdown(f"<strong>Confidence:</strong> {confidence}%")
                        if finding.get('location'):
                            st.markdown(f"<strong>Location:</strong> {finding['location']}")
                        if finding.get('encoding'):
                            st.markdown(f"<strong>Encoding:</strong> {finding['encoding']}")
                    
                    # POC Section
                    if finding.get('poc'):
                        st.markdown("--- ")
                        st.markdown("### 🔧 Proof of Concept")
                        st.markdown(finding['poc'])
                    
                    if finding.get('exploitation_steps'):
                        st.markdown("**📋 Exploitation Steps:**")
                        if isinstance(finding['exploitation_steps'], list):
                            for step in finding['exploitation_steps']:
                                st.markdown(f"• {step}")
                        else:
                            st.markdown(finding['exploitation_steps'])
                    
                    if finding.get('tools_needed'):
                        st.markdown("**🛠️ Tools Needed:**")
                        if isinstance(finding['tools_needed'], list):
                            st.markdown(", ".join(finding['tools_needed']))
                        else:
                            st.markdown(finding['tools_needed'])
        
        # Specialized AI Analysis Results with POCs
        if results.get('protocol_analysis'):
            st.markdown("### 🔬 Protocol Analysis with POCs")
            protocol_data = results['protocol_analysis']
            
            with st.expander("🔍 Protocol Security Analysis", expanded=True):
                if isinstance(protocol_data, dict) and 'protocol_analysis' in protocol_data:
                    st.markdown(protocol_data['protocol_analysis'])
                else:
                    st.json(protocol_data)
        
        if results.get('credential_analysis'):
            st.markdown("### 🔐 Credential Analysis with POCs")
            cred_data = results['credential_analysis']
            
            with st.expander("🔑 Credential Harvesting Results", expanded=True):
                if isinstance(cred_data, dict) and 'credential_analysis' in cred_data:
                    st.markdown(cred_data['credential_analysis'])
                else:
                    st.json(cred_data)
        
        if results.get('behavioral_analysis'):
            st.markdown("### 🧠 Behavioral Analysis with POCs")
            behavior_data = results['behavioral_analysis']
            
            with st.expander("🎭 Behavioral Anomaly Analysis", expanded=True):
                if isinstance(behavior_data, dict) and 'behavioral_analysis' in behavior_data:
                    st.markdown(behavior_data['behavioral_analysis'])
                else:
                    st.json(behavior_data)
        
        if results.get('enhanced_flag_hunt'):
            st.markdown("### 🎯 Enhanced Context-Aware Flag Hunt")
            enhanced_data = results['enhanced_flag_hunt']
            
            with st.expander("🚩 Context-Enhanced Flag Discovery", expanded=True):
                if isinstance(enhanced_data, dict) and 'flag_hunter_analysis' in enhanced_data:
                    st.markdown(enhanced_data['flag_hunter_analysis'])
                else:
                    st.json(enhanced_data)
        
        # Export options
        st.markdown("### 📥 Export Results")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📄 Export JSON", width='stretch'):
                export_results(results, "json")
        
        with col2:
            if st.button("📊 Export CSV", width='stretch'):
                export_results(results, "csv")
        
        with col3:
            if st.button("📋 Export HTML", width='stretch'):
                export_results(results, "html")
                
        with col4:
            if st.button("📑 Export PDF", width='stretch'):
                export_results(results, "pdf")
    
    else:
        st.markdown("""
        <div style="text-align: center; padding: 4rem 2rem;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">📊</div>
            <div style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;">No Results Yet</div>
            <div style="color: rgba(255, 255, 255, 0.7);">
                Run an analysis to see results here
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_findings_tab(results):
    """Render the findings tab with standard and CTF findings"""
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔍 Standard Findings")
        findings = results.get('findings', [])
        
        if findings:
            for i, finding in enumerate(findings[:10]):  # Show top 10
                confidence = finding.get('confidence', 50)
                
                st.markdown(f"""
                <div class="result-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <div style="font-weight: 600; font-size: 1.1rem;">
                            {finding.get('icon', '🔍')} {finding.get('display_type', 'Finding')}
                        </div>
                        <div style="background: rgba(0, 245, 255, 0.2); padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem;">
                            {confidence}% confidence
                        </div>
                    </div>
                    <div style="font-family: monospace; background: rgba(0, 0, 0, 0.1); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                        {finding.get('data', 'No data')[:100]}{'...' if len(finding.get('data', '')) > 100 else ''}
                    </div>
                    <div style="font-size: 0.9rem; color: rgba(255, 255, 255, 0.7);">
                        <strong>Protocol:</strong> {finding.get('protocol', 'Unknown')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No standard findings detected")
    
    with col2:
        st.markdown("#### 🎯 CTF Findings")
        ctf_findings = results.get('ctf_findings', [])
        
        if ctf_findings:
            for finding in ctf_findings[:10]:  # Show top 10
                confidence = finding.get('confidence', 50)
                
                # Determine finding category for styling
                finding_type = finding.get('type', '').lower()
                if 'flag' in finding_type or 'credential' in finding_type:
                    icon = '🚩'
                    color = 'rgba(0, 255, 136, 0.2)'
                elif 'stego' in finding_type or 'timing' in finding_type:
                    icon = '🕵️'
                    color = 'rgba(255, 165, 0, 0.2)'
                elif 'dns' in finding_type or 'http' in finding_type:
                    icon = '🌐'
                    color = 'rgba(0, 245, 255, 0.2)'
                else:
                    icon = '🔍'
                    color = 'rgba(255, 0, 255, 0.2)'
                
                st.markdown(f"""
                <div style="background: {color}; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; border: 1px solid rgba(255, 255, 255, 0.1);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <div style="font-weight: 600; font-size: 1.1rem;">
                            {icon} {finding.get('type', 'CTF Finding').replace('_', ' ').title()}
                        </div>
                        <div style="background: rgba(0, 255, 136, 0.3); padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem;">
                            {confidence}% confidence
                        </div>
                    </div>
                    <div style="font-family: monospace; background: rgba(0, 0, 0, 0.2); padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                        {finding.get('data', finding.get('decoded', 'No data'))[:150]}{'...' if len(str(finding.get('data', ''))) > 150 else ''}
                    </div>
                    <div style="font-size: 0.9rem; margin-top: 0.5rem;">
                        <strong>Method:</strong> {finding.get('method', finding.get('reason', 'Unknown'))}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No CTF-specific findings detected")

def render_visualizations_tab(results, visualizer):
    """Render the visualizations tab"""
    st.markdown("#### 📊 Analysis Visualizations")
    
    if not visualizer:
        st.warning("⚠️ Advanced visualizations require additional packages")
        st.info("Install with: `pip install networkx matplotlib`")
        return
    
    # Get all findings for visualization
    all_findings = results.get('findings', []) + results.get('ctf_findings', [])
    
    if all_findings:
        col1, col2 = st.columns(2)
        
        with col1:
            # Findings distribution
            fig1 = visualizer.create_findings_distribution(all_findings)
            st.plotly_chart(fig1, width='stretch')
        
        with col2:
            # Protocol analysis
            fig2 = visualizer.create_protocol_analysis_chart(all_findings)
            st.plotly_chart(fig2, width='stretch')
        
        # Suspicious packets chart
        suspicious_packets = results.get('suspicious_packets', [])
        if suspicious_packets:
            st.markdown("#### 🕵️ Suspicious Packets")
            fig3 = visualizer.create_suspicious_packets_chart(suspicious_packets)
            st.plotly_chart(fig3, width='stretch')
    
    else:
        st.info("No data available for visualization")

def render_suspicious_tab(results):
    """Render the suspicious packets tab"""
    st.markdown("#### 🕵️ Suspicious Packets Analysis")
    
    suspicious_packets = results.get('suspicious_packets', [])
    
    if suspicious_packets:
        for i, packet in enumerate(suspicious_packets[:10]):  # Show top 10
            score = packet.get('suspicion_score', 0)
            reasons = packet.get('reasons', [])
            
            # Color based on suspicion score
            if score >= 80:
                color = 'rgba(255, 68, 68, 0.2)'
                icon = '🚨'
            elif score >= 60:
                color = 'rgba(255, 170, 0, 0.2)'
                icon = '⚠️'
            else:
                color = 'rgba(255, 255, 0, 0.2)'
                icon = '⚡'
            
            st.markdown(f"""
            <div style="background: {color}; padding: 1.5rem; border-radius: 12px; margin: 1rem 0; border: 1px solid rgba(255, 255, 255, 0.1);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <div style="font-weight: 600; font-size: 1.1rem;">
                        {icon} Packet #{packet.get('packet_index', i)}
                    </div>
                    <div style="background: rgba(255, 68, 68, 0.3); padding: 0.3rem 0.8rem; border-radius: 15px; font-size: 0.8rem;">
                        Suspicion: {score}%
                    </div>
                </div>
                <div style="margin-bottom: 1rem;">
                    <strong>Reasons:</strong>
                    <ul style="margin: 0.5rem 0;">
                        {''.join([f'<li>{reason}</li>' for reason in reasons])}
                    </ul>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    else:
        st.info("No suspicious packets detected")

def render_hints_tab(results):
    """Render the hints and recommendations tab"""
    st.markdown("#### 💡 CTF Analysis Hints")
    
    hints = results.get('hints', [])
    
    if hints:
        st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(0, 245, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%); 
                    padding: 2rem; border-radius: 15px; margin: 1rem 0; border: 1px solid rgba(0, 245, 255, 0.3);">
            <h4 style="margin: 0; color: #00f5ff;">🧠 AI-Generated Hints</h4>
            <p style="margin: 0.5rem 0 0 0;">
                Based on your analysis results, here are some suggestions for further investigation:
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        for i, hint in enumerate(hints, 1):
            st.markdown(f"""
            <div style="background: rgba(255, 255, 255, 0.05); padding: 1.5rem; border-radius: 12px; margin: 1rem 0; border-left: 4px solid #00f5ff;">
                <div style="font-weight: 600; margin-bottom: 0.5rem;">
                    💡 Hint #{i}
                </div>
                <div>
                    {hint}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    else:
        st.info("No specific hints available for this analysis")

def render_advanced_tab(results):
    """Render the advanced analysis tab"""
    st.markdown("#### 📈 Advanced Analysis")
    
    # Statistics overview
    stats = results.get('statistics', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("##### 📊 Analysis Statistics")
        if stats:
            st.json(stats)
        else:
            st.info("No statistics available")
    
    with col2:
        st.markdown("##### ⚙️ Analysis Configuration")
        config_info = {
            "Analysis Time": results.get('analysis_time', {}).get('duration', 'Unknown'),
            "Total Findings": len(results.get('findings', [])),
            "CTF Findings": len(results.get('ctf_findings', [])),
            "Suspicious Packets": len(results.get('suspicious_packets', []))
        }
        st.json(config_info)

def render_about_page():
    """Render the about page"""
    st.markdown('<div class="glass-card fade-in">', unsafe_allow_html=True)
    
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
    
    #### 🎯 Supported Analysis
    - CTF flag detection with advanced patterns
    - Credential extraction from network traffic
    - API token and authentication data discovery
    - Protocol security assessment
    - Steganography and covert channel detection
    
    #### 🤖 AI Models
    - **Claude 3.5 Sonnet**: Best overall performance
    - **GPT-4 Turbo**: Creative analysis and insights
    - **Gemini Pro**: Fast and efficient processing
    - **Llama 3.1**: Open-source power
    - And many more...
    
    #### 📊 Version Information
    - **Version**: 0.1
    - **Author**: Waleed
    """)
    
    st.markdown('</div>', unsafe_allow_html=True)

def run_analysis(uploaded_file, search_options, custom_regex, ai_mode, ai_enabled, confidence_threshold, ctf_context=None):
    """Run the analysis with progress tracking"""
    
    # Save file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_file_path = tmp_file.name
    
    # Progress container
    progress_container = st.empty()
    
    with progress_container.container():
        st.markdown("""
        <div class="progress-container">
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">
                🔍 Analysis in Progress
            </div>
            <div class="progress-bar" style="width: 0%"></div>
        </div>
        """, unsafe_allow_html=True)
    
    try:
        # Initialize analyzer
        analyzer = WebPcapAnalyzer()
        
        # Update progress
        progress_container.markdown("""
        <div class="progress-container">
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">
                📊 Analyzing PCAP Structure...
            </div>
            <div class="progress-bar" style="width: 25%"></div>
        </div>
        """, unsafe_allow_html=True)
        
        # Perform analysis
        results = analyzer.analyze_file(tmp_file_path, search_options, custom_regex)
        
        # Update progress
        progress_container.markdown("""
        <div class="progress-container">
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">
                🤖 Running AI Analysis...
            </div>
            <div class="progress-bar" style="width: 75%"></div>
        </div>
        """, unsafe_allow_html=True)
        
        # AI Analysis if enabled
        if ai_enabled and ai_mode != "📊 Standard Only":
            try:
                # Load configuration to get the correct model
                config = AgentConfig.load_config()
                model = config.get('model', 'neversleep/llama-3-lumimaid-8b')
                api_key = config.get('openrouter_api_key')
                
                agent = create_agent(api_key, model)
                if agent:
                    # Configure confidence thresholds based on user setting
                    # Backward compatibility for older agent builds
                    if hasattr(agent, 'set_confidence_thresholds'):
                        agent.set_confidence_thresholds(
                            min_confidence=confidence_threshold,
                            flag_threshold=max(confidence_threshold, 85),
                            credential_threshold=max(confidence_threshold, 90)
                        )
                    else:
                        try:
                            setattr(agent, 'min_confidence_threshold', confidence_threshold)
                            setattr(agent, 'flag_confidence_threshold', max(confidence_threshold, 85))
                            setattr(agent, 'credential_confidence_threshold', max(confidence_threshold, 90))
                        except Exception:
                            pass
                    
                    # Enable ensemble mode for enhanced analysis
                    if "Enhanced Analysis" in ai_mode:
                        agent.enable_ensemble_mode(True)
                    
                    # Get packet data
                    with open(tmp_file_path, 'rb') as f:
                        raw_data = f.read()
                    packet_text = raw_data.decode('utf-8', errors='ignore')[:15000]
                    
                    # Specialized AI Analysis based on mode with CTF context
                    if "Deep Flag Hunt" in ai_mode:
                        ai_findings = agent.flag_hunter_analysis(packet_text, ctf_context)
                        results['ai_findings'] = ai_findings
                    elif "Protocol Analysis" in ai_mode:
                        protocol_analysis = agent.protocol_analyzer_analysis(packet_text, ctf_context)
                        results['protocol_analysis'] = protocol_analysis
                    elif "Credential Hunt" in ai_mode:
                        credential_analysis = agent.credential_harvester_analysis(packet_text, ctf_context)
                        results['credential_analysis'] = credential_analysis
                    elif "Behavioral Analysis" in ai_mode:
                        behavioral_analysis = agent.behavioral_analysis(packet_text, "Network Traffic Analysis", ctf_context)
                        results['behavioral_analysis'] = behavioral_analysis
                    else:  # Enhanced Analysis (Ensemble Mode)
                        ai_analysis = agent.analyze_findings(results['findings'], packet_text)
                        results['ai_analysis'] = ai_analysis
                        
                        # Also run context-aware flag hunting for enhanced mode
                        if ctf_context and (ctf_context.get('description') or ctf_context.get('hints')):
                            enhanced_flag_hunt = agent.flag_hunter_analysis(packet_text, ctf_context)
                            results['enhanced_flag_hunt'] = enhanced_flag_hunt
                        ai_findings = agent.hunt_hidden_flags(packet_text, "Enhanced Mode")
                        results['ai_findings'] = ai_findings
                    
                    # Get suggestions
                    suggestions = agent.suggest_next_steps(results['findings'], f"Mode: {ai_mode}")
                    results['ai_suggestions'] = suggestions
                    
            except Exception as e:
                st.error(f"AI analysis failed: {str(e)}")
        
        # Complete
        progress_container.markdown("""
        <div class="progress-container">
            <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">
                ✅ Analysis Complete!
            </div>
            <div class="progress-bar" style="width: 100%"></div>
        </div>
        """, unsafe_allow_html=True)
        
        # Store results with CTF context
        if ctf_context:
            results['ctf_context'] = ctf_context
        
        # Save results to session state
        st.session_state.analysis_results = results
        
        # Automatically switch to results page
        st.session_state.current_page = 'results'
        
        # Clean up temporary file
        os.remove(tmp_file_path)
        
        # Rerun to show results
        st.rerun()
        
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        # Clean up temporary file in case of error
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)

def run_demo_analysis(ai_enabled=False, mode="enhanced"):
    """Run a demo analysis with sample data"""
    try:
        # Use a sample PCAP for the demo
        results = analyze_sample_pcap()
        
        # Simulate AI analysis if requested
        if ai_enabled:
            results['ai_findings'] = [
                {
                    'flag_candidate': 'flag{d3m0_4i_fl4g}',
                    'reasoning': 'AI model detected a common flag format with leetspeak encoding.',
                    'confidence': 95,
                    'location': 'Packet 15, TCP Stream 2',
                    'encoding': 'plaintext',
                    'poc': 'A proof of concept can be generated here...' 
                }
            ]
            results['ai_suggestions'] = [
                'Investigate TCP stream 2 for more context.',
                'Look for other encoded data in the same stream.'
            ]
        
        st.session_state.analysis_results = results
        st.session_state.current_page = 'results'
        st.rerun()
        
    except Exception as e:
        st.error(f"Demo analysis failed: {str(e)}")

def export_results(results, format_type):
    """Export analysis results to a file"""
    try:
        analyzer = WebPcapAnalyzer()
        analyzer.results = results  # Load results into analyzer
        
        # Generate file content
        if format_type == 'json':
            file_content = analyzer.export_results('json')
            file_extension = 'json'
            mime_type = 'application/json'
        elif format_type == 'csv':
            file_content = analyzer.export_results('csv')
            file_extension = 'csv'
            mime_type = 'text/csv'
        elif format_type == 'html':
            file_content = analyzer.export_results('html')
            file_extension = 'html'
            mime_type = 'text/html'
        elif format_type == 'pdf':
            file_content = analyzer.export_results('pdf')
            file_extension = 'pdf'
            mime_type = 'application/pdf'
        else:
            st.error(f"Unsupported format: {format_type}")
            return
        
        # Create a download button
        st.download_button(
            label=f"Download {format_type.upper()}",
            data=file_content,
            file_name=f"flagsniff_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}",
            mime=mime_type
        )
        
    except Exception as e:
        st.error(f"Export failed: {str(e)}")


# Main application logic
def main():
    """Main Streamlit application entry point"""
    st.markdown(get_theme_styles(), unsafe_allow_html=True)
    
    render_navigation()
    # Render Copilot sidebar (right) safely
    try:
        render_copilot_sidebar()
    except Exception as e:
        st.sidebar.warning(f"Copilot: {str(e)[:100]}")
    
    if st.session_state.current_page == 'analyzer':
        render_hero()
        render_analyzer_page()
    elif st.session_state.current_page == 'ai_config':
        render_ai_config_page()
    elif st.session_state.current_page == 'results':
        render_results_page()
    elif st.session_state.current_page == 'about':
        render_about_page()
    elif st.session_state.current_page == 'setup_ai':
        render_setup_ai_page()
    
if __name__ == "__main__":
    main()