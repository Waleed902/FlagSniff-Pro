#!/usr/bin/env python3
"""
FlagSniff AI Setup - Configure LongCat API and AI Agent
"""

import json
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table

console = Console()

def print_setup_banner():
    """Print setup banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                   🤖 FlagSniff AI Setup                       ║
    ║              Configure XBOW Agent for Flag Hunting            ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")

def get_longcat_info():
    """Display LongCat API information"""
    
    info_panel = Panel(
        """🔑 [bold]LongCat API Key Setup[/bold]

🚀 [bold green]AVAILABLE MODELS:[/bold green]
• LongCat-Flash-Chat: Fast & optimized (Default) ⭐
• GPT-4o: Latest OpenAI flagship model
• GPT-4 Turbo: Advanced reasoning
• GPT-3.5 Turbo: Fast and efficient

💎 [bold]PREMIUM FEATURES:[/bold]
• High-speed API responses
• Multiple model access
• Enhanced context windows
• CTF-optimized performance

📝 [bold]How to get an API key:[/bold]
1. Visit: https://longcat.chat/platform/
2. Sign up for an account
3. Go to API Keys section
4. Create a new API key
5. Add credits to your account

💰 [bold]Pricing:[/bold]
• GPT-4o: Premium tier
• GPT-4 Turbo: Premium tier
• GPT-3.5 Turbo: Standard tier
• Competitive rates for CTF/Security analysis

🎯 [bold]For CTF/Red Team use:[/bold]
LongCat provides fast, reliable access to top AI models
        """,
        title="LongCat API Information",
        border_style="blue"
    )
    
    console.print(info_panel)

def test_api_key(api_key, model):
    """Test API key with a simple request"""
    
    try:
        from ai.ai_agent import FlagSniffAgent
        
        console.print("🧪 [yellow]Testing API key...[/yellow]")
        
        # Use LongCat endpoint
        agent = FlagSniffAgent(api_key, model, base_url="https://api.longcat.chat/openai/v1/chat/completions")
        
        # Simple test request
        test_prompt = "Respond with 'API key working' if you can see this message."
        response = agent._call_openrouter(test_prompt)
        
        if response and "working" in response.lower():
            console.print("✅ [green]API key is working![/green]")
            return True
        else:
            console.print("⚠️  [yellow]API key might be working but response unclear[/yellow]")
            console.print(f"Response: {response}")
            return True
            
    except Exception as e:
        console.print(f"❌ [red]API key test failed: {e}[/red]")
        return False

def save_config(api_key, model):
    """Save configuration to file"""
    
    config = {
        "longcat_api_key": api_key,
        "model": model,
        "setup_date": str(Path(__file__).stat().st_mtime),
        "version": "2.0",
        "api_endpoint": "https://api.longcat.chat/openai/v1/chat/completions",
        "provider": "longcat"
    }
    
    try:
        with open('.flagsniff_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        console.print("💾 [green]Configuration saved to .flagsniff_config.json[/green]")
        return True
        
    except Exception as e:
        console.print(f"❌ [red]Failed to save config: {e}[/red]")
        return False

def load_existing_config():
    """Load existing configuration"""
    
    try:
        with open('.flagsniff_config.json', 'r') as f:
            return json.load(f)
    except:
        return {}

def show_model_options():
    """Display available AI models"""
    
    models_table = Table(title="🤖 Available AI Models", show_header=True, header_style="bold magenta")
    models_table.add_column("Model", style="cyan")
    models_table.add_column("Best For", style="green")
    models_table.add_column("Cost", style="yellow")
    models_table.add_column("Speed", style="blue")
    
    # FREE MODELS
    models_table.add_row(
        "🆓 qwen/qwen3-235b-a22b:free",
        "🆓 openai/gpt-oss-20b:free",
        "🆓 cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        "🆓 qwen/qwen2.5-vl-32b-instruct:free",
        "FREE uncensored responses",
        "FREE",
        "Fast"
    )
    models_table.add_row(
        "🆓 openai/gpt-oss-20b",
        "FREE OpenAI architecture",
        "FREE",
        "Medium"
    )
    models_table.add_row(
        "🆓 qwen/qwen3-235b-a22b:freet",
        "FREE advanced reasoning",
        "FREE",
        "Medium"
    )
    models_table.add_row(
        "🆓 cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        "FREE enhanced reasoning",
        "FREE",
        "Fast"
    )
    
    # PREMIUM MODELS
    models_table.add_row(
        "anthropic/claude-3.5-sonnet",
        "Advanced analysis, CTF insights",
        "Medium",
        "Fast"
    )
    models_table.add_row(
        "openai/gpt-4-turbo",
        "Creative flag hunting",
        "High",
        "Medium"
    )
    models_table.add_row(
        "google/gemini-pro-1.5",
        "Protocol analysis",
        "Low",
        "Fast"
    )
    models_table.add_row(
        "qwen/qwen3-235b-a22b:free",
        "Cost-effective analysis",
        "Very Low",
        "Fast"
    )
    
    console.print(models_table)

def main():
    """Main setup function"""
    
    print_setup_banner()
    
    # Check if already configured
    existing_config = load_existing_config()
    
    if existing_config.get('longcat_api_key'):
        console.print("🔍 [yellow]Existing configuration found[/yellow]")
        
        if not Confirm.ask("Do you want to reconfigure?"):
            console.print("👋 [blue]Setup cancelled[/blue]")
            return
    
    # Show LongCat information
    get_longcat_info()
    
    if not Confirm.ask("\nDo you have a LongCat API key?"):
        console.print("\n📝 [blue]Please get an API key from https://longcat.chat/platform/ and run this setup again[/blue]")
        return
    
    # Get API key
    api_key = Prompt.ask("\n🔑 Enter your LongCat API key", password=True)
    
    if not api_key or len(api_key) < 10:
        console.print("❌ [red]Invalid API key format[/red]")
        return
    
    # Show model options
    console.print("\n")
    show_model_options()
    
    # Get model choice
    model_choices = [
        "LongCat-Flash-Chat",
        "gpt-4o",
        "gpt-4-turbo",
        "gpt-3.5-turbo"
    ]
    
    console.print("\n🤖 [bold]Model Selection:[/bold]")
    console.print("🚀 [bold green]LONGCAT AVAILABLE MODELS:[/bold green]")
    for i, model in enumerate(model_choices, 1):
        console.print(f"  {i}. {model}")
    
    while True:
        try:
            choice = int(Prompt.ask(f"\nSelect model (1-{len(model_choices)})", default="1"))
            if 1 <= choice <= len(model_choices):
                selected_model = model_choices[choice - 1]
                break
            else:
                console.print(f"❌ Please enter a number between 1-{len(model_choices)}")
        except ValueError:
            console.print("❌ Please enter a valid number")
    
    console.print(f"\n✅ Selected model: [green]{selected_model}[/green]")
    
    # Test API key
    if Confirm.ask("\nTest API key now?", default=True):
        if not test_api_key(api_key, selected_model):
            if not Confirm.ask("API test failed. Continue anyway?"):
                console.print("👋 [blue]Setup cancelled[/blue]")
                return
    
    # Save configuration
    if save_config(api_key, selected_model):
        console.print("\n🎉 [bold green]Setup complete![/bold green]")
        
        console.print("\n📋 [bold]Next steps:[/bold]")
        console.print("1. Run: [cyan]python flagsniff_ai.py -f your_file.pcap --ai enhanced[/cyan]")
        console.print("2. Or use the web UI: [cyan]python run_web.py[/cyan]")
        console.print("3. Try deep flag hunting: [cyan]python flagsniff_ai.py -f file.pcap --ai deep_hunt[/cyan]")
        
        # Show usage examples
        examples_panel = Panel(
            """🎯 [bold]Usage Examples:[/bold]

[cyan]# Standard analysis with AI enhancement[/cyan]
python flagsniff_ai.py -f capture.pcap --find all --ai enhanced

[cyan]# Deep flag hunting mode[/cyan]
python flagsniff_ai.py -f capture.pcap --ai deep_hunt --confidence 80

[cyan]# Protocol security analysis[/cyan]
python flagsniff_ai.py -f capture.pcap --ai protocol

[cyan]# Web interface with AI[/cyan]
python run_web.py

[cyan]# Export AI analysis results[/cyan]
python flagsniff_ai.py -f capture.pcap --ai enhanced --export results.json
            """,
            title="Ready to Hunt Flags! 🚩",
            border_style="green"
        )
        
        console.print(examples_panel)
    
    else:
        console.print("❌ [red]Setup failed[/red]")

if __name__ == "__main__":
    main()