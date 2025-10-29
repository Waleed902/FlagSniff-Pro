#!/usr/bin/env python3
"""
FlagSniff Pro Web UI Launcher
Next-generation PCAP analysis with AI-powered insights
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def print_banner():
    """Print the FlagSniff Pro banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                    🔍 FlagSniff v2.0                                         ║
    ║              Next-Gen PCAP Analysis Platform                                  ║
    ║                                                                               ║
    ║  🚀 Modern UI    🤖 AI-Powered    ⚡ Lightning Fast                         ║
    ║  🎯 CTF Ready    🔍 Deep Analysis  🌙 Dark/Light Theme                      ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_requirements():
    """Check if required packages are installed"""
    print("🔍 Checking system requirements...")

    required_packages = [
        ('streamlit', 'Streamlit web framework'),
        ('pandas', 'Data analysis library'),
        ('plotly', 'Interactive visualizations'),
        ('scapy', 'Packet manipulation library'),
        ('rich', 'Terminal formatting'),
        ('requests', 'HTTP library for AI API calls')
    ]

    missing_packages = []

    for package, description in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package:<12} - {description}")
        except ImportError:
            print(f"  ⚠️  {package:<12} - {description} (MISSING)")
            missing_packages.append(package)

    if missing_packages:
        print(f"\n⚠️ Missing {len(missing_packages)} required packages")
        print("💡 Install with: pip install -r requirements_web.txt")
        return False

    print("✅ All requirements satisfied!")
    return True

def check_ai_config():
    """Check AI configuration status"""
    print("\n🤖 Checking AI configuration...")

    try:
        from ai.ai_agent import AgentConfig

        api_key = AgentConfig.get_api_key()
        if api_key:
            config = AgentConfig.load_config()
            model = config.get('model', 'Unknown')
            print(f"  ✅ AI Agent configured with {model.split('/')[-1]}")
            return True
        else:
            print("  ⚠️  AI Agent not configured (optional)")
            print("     💡 Run 'python config/setup_ai.py' to enable AI features")
            return False
    except Exception as e:
        print(f"  ⚠️  Could not check AI config: {e}")
        return False

def get_system_info():
    """Get system information"""
    print("\n📊 System Information:")
    print(f"  🐍 Python: {sys.version.split()[0]}")
    print(f"  💻 Platform: {sys.platform}")
    print(f"  📂 Working Directory: {os.getcwd()}")

def main():
    """Launch the FlagSniff Pro web interface"""

    print_banner()

    # Check if we're in the right directory
    if not os.path.exists("apps/app_new.py"):
        print("⚠️ app_new.py not found!")
        print("💡 Please run this script from the FlagSniff directory")
        sys.exit(1)

    # System checks
    get_system_info()

    if not check_requirements():
        sys.exit(1)

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='FlagSniff Web Interface')
    parser.add_argument('--port', type=int, default=8501, help='Port to run the web interface on')
    args = parser.parse_args()
    port = args.port

    ai_configured = check_ai_config()

    # Launch information
    print("\n🚀 Starting FlagSniff Web Interface...")
    print("=" * 60)
    print("📱 Web interface will open in your default browser")
    print(f"🔗 Manual access: http://localhost:{port}")
    print("🌙 Features: Dark/Light theme, AI analysis, Real-time processing")

    if ai_configured:
        print("🤖 AI Agent: ENABLED - Advanced analysis available")
    else:
        print("🤖 AI Agent: DISABLED - Standard analysis only")

    print("\n⚠️  Press Ctrl+C to stop the server")
    print("=" * 60)

    # Add a small delay for better UX
    print("⏳ Initializing...")
    time.sleep(2)

    try:
        # Launch Streamlit with optimized settings
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "apps/app_new.py",
            "--server.port", str(port),
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false",
            "--theme.base", "dark",
            "--theme.primaryColor", "#00f5ff",
            "--theme.backgroundColor", "#0c0c0c",
            "--theme.secondaryBackgroundColor", "#1a1a2e",
            "--theme.textColor", "#ffffff"
        ])
    except KeyboardInterrupt:
        print("\n👋 FlagSniff stopped gracefully")
        print("🎯 Thanks for using FlagSniff!")
    except Exception as e:
        print(f"\n⚠️ Error starting web interface: {e}")
        print("💡 Try running: streamlit run apps/app_new.py")
        sys.exit(1)

if __name__ == "__main__":
    main()