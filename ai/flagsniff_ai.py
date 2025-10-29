#!/usr/bin/env python3
"""
FlagSniff AI - Enhanced CLI with XBOW Agent
Advanced PCAP analysis with AI-powered flag hunting
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
import json

# Import existing modules
from apps.web_analyzer import WebPcapAnalyzer
from ai.ai_agent import create_agent, AgentConfig
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

console = Console()

def print_banner():
    """Print FlagSniff AI banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🎯 FlagSniff AI v2.0                       ║
    ║              Advanced PCAP Analysis with XBOW Agent           ║
    ║                                                               ║
    ║  🤖 AI-Powered Flag Hunting  🔍 Deep Pattern Analysis        ║
    ║  🧠 Intelligent Insights     🎯 CTF Optimization             ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")

def setup_ai_agent(api_key=None, model=None):
    """Setup and configure AI agent"""
    
    if not api_key:
        api_key = AgentConfig.get_api_key()
    
    if not api_key:
        console.print("⚠️  [yellow]AI Agent not configured[/yellow]")
        console.print("💡 Set OPENROUTER_API_KEY environment variable or use --api-key")
        return None
    
    try:
        agent = create_agent(api_key, model or "qwen/qwen3-235b-a22b:free")
        console.print("🤖 [green]XBOW Agent: ONLINE[/green]")
        return agent
    except Exception as e:
        console.print(f"❌ [red]Failed to initialize AI agent: {e}[/red]")
        return None

def analyze_with_ai(analyzer, agent, file_path, search_options, custom_regex=None, ai_mode="standard"):
    """Perform analysis with AI enhancement"""
    
    console.print(f"\n🔍 [bold]Analyzing: {file_path}[/bold]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Standard analysis
        task1 = progress.add_task("📊 Running standard analysis...", total=None)
        
        def progress_callback(message):
            progress.update(task1, description=f"📊 {message}")
        
        try:
            results = analyzer.analyze_file(file_path, search_options, custom_regex, progress_callback)
            progress.remove_task(task1)
            
            # AI Analysis
            if agent and ai_mode != "standard":
                task2 = progress.add_task("🤖 XBOW Agent analyzing...", total=None)
                
                try:
                    # Get raw packet data
                    with open(file_path, 'rb') as f:
                        raw_data = f.read()
                    packet_text = raw_data.decode('utf-8', errors='ignore')[:10000]
                    
                    if ai_mode == "deep_hunt":
                        progress.update(task2, description="🔍 AI hunting hidden flags...")
                        ai_findings = agent.hunt_hidden_flags(packet_text, "CLI Deep Hunt")
                        results['ai_findings'] = ai_findings
                    
                    elif ai_mode == "protocol":
                        progress.update(task2, description="🔬 AI analyzing protocols...")
                        protocol_analysis = agent.analyze_protocols(packet_text)
                        results['protocol_analysis'] = protocol_analysis
                    
                    else:  # enhanced
                        progress.update(task2, description="🧠 AI enhancing analysis...")
                        ai_analysis = agent.analyze_findings(results['findings'], packet_text)
                        results['ai_analysis'] = ai_analysis
                        
                        # Also hunt for hidden flags
                        ai_findings = agent.hunt_hidden_flags(packet_text)
                        results['ai_findings'] = ai_findings
                    
                    # Get suggestions
                    progress.update(task2, description="💡 Generating recommendations...")
                    suggestions = agent.suggest_next_steps(results['findings'], f"CLI mode: {ai_mode}")
                    results['ai_suggestions'] = suggestions
                    
                    progress.remove_task(task2)
                    
                except Exception as e:
                    progress.remove_task(task2)
                    console.print(f"⚠️  [yellow]AI analysis failed: {e}[/yellow]")
            
            return results
            
        except Exception as e:
            progress.remove_task(task1)
            console.print(f"❌ [red]Analysis failed: {e}[/red]")
            return None

def display_results(results, show_ai=True, confidence_threshold=70):
    """Display analysis results in CLI"""
    
    if not results:
        return
    
    # Summary statistics
    stats_table = Table(title="📊 Analysis Summary", show_header=True, header_style="bold magenta")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")
    
    stats_table.add_row("Total Packets", f"{results['total_packets']:,}")
    stats_table.add_row("Analyzed Packets", f"{results['analyzed_packets']:,}")
    stats_table.add_row("Total Findings", str(len(results.get('findings', []))))
    
    # Count by type
    findings = results.get('findings', [])
    type_counts = {}
    for finding in findings:
        ftype = finding.get('display_type', finding.get('type', 'Unknown'))
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
    
    for ftype, count in type_counts.items():
        stats_table.add_row(f"{ftype}s Found", str(count))
    
    console.print(stats_table)
    
    # AI Findings
    if show_ai and 'ai_findings' in results:
        ai_findings = results['ai_findings']
        high_conf_findings = [f for f in ai_findings if f.get('confidence', 0) >= confidence_threshold]
        
        if high_conf_findings:
            console.print(f"\n🤖 [bold]XBOW Agent Discoveries[/bold] (Confidence ≥ {confidence_threshold}%)")
            
            ai_table = Table(show_header=True, header_style="bold blue")
            ai_table.add_column("Flag Candidate", style="green")
            ai_table.add_column("Confidence", style="yellow")
            ai_table.add_column("Reasoning", style="white")
            
            for finding in high_conf_findings:
                confidence = finding.get('confidence', 0)
                conf_color = "green" if confidence >= 90 else "yellow" if confidence >= 80 else "red"
                
                ai_table.add_row(
                    finding.get('flag_candidate', 'Unknown'),
                    f"[{conf_color}]{confidence}%[/{conf_color}]",
                    finding.get('reasoning', 'No reasoning provided')[:60] + "..."
                )
            
            console.print(ai_table)
    
    # Standard Findings
    if findings:
        console.print(f"\n🔍 [bold]Standard Findings[/bold]")
        
        findings_table = Table(show_header=True, header_style="bold cyan")
        findings_table.add_column("Type", style="magenta")
        findings_table.add_column("Protocol", style="blue")
        findings_table.add_column("Content", style="green")
        findings_table.add_column("Source → Dest", style="yellow")
        
        for finding in findings[:20]:  # Show top 20
            content = finding.get('data', finding.get('content', 'No content'))
            if len(content) > 50:
                content = content[:47] + "..."
            
            src_ip = finding.get('src_ip', finding.get('src', 'N/A'))
            dst_ip = finding.get('dst_ip', finding.get('dst', 'N/A'))
            
            findings_table.add_row(
                finding.get('display_type', finding.get('type', 'Unknown')),
                finding.get('protocol', 'Unknown'),
                content,
                f"{src_ip} → {dst_ip}"
            )
        
        console.print(findings_table)
        
        if len(findings) > 20:
            console.print(f"... and {len(findings) - 20} more findings")
    
    # AI Suggestions
    if show_ai and 'ai_suggestions' in results:
        suggestions = results['ai_suggestions']
        if suggestions:
            console.print(f"\n💡 [bold]AI Recommendations[/bold]")
            
            for i, suggestion in enumerate(suggestions[:8], 1):
                console.print(f"  {i}. {suggestion}")
    
    # Protocol Analysis
    if show_ai and 'protocol_analysis' in results:
        protocol_analysis = results['protocol_analysis']
        if isinstance(protocol_analysis, dict) and 'analysis' in protocol_analysis:
            console.print(f"\n🔬 [bold]Protocol Security Analysis[/bold]")
            console.print(Panel(protocol_analysis['analysis'], title="AI Protocol Analysis"))

def export_results(results, format_type, output_file):
    """Export results to file"""
    
    try:
        analyzer = WebPcapAnalyzer()
        analyzer.results = results
        
        exported_data = analyzer.export_results(format_type)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(exported_data)
        
        console.print(f"✅ [green]Results exported to: {output_file}[/green]")
        
    except Exception as e:
        console.print(f"❌ [red]Export failed: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(
        description="🎯 FlagSniff AI - Advanced PCAP Analysis with XBOW Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard analysis
  python flagsniff_ai.py -f capture.pcap --find all
  
  # AI-enhanced analysis
  python flagsniff_ai.py -f capture.pcap --find all --ai enhanced
  
  # Deep flag hunting with AI
  python flagsniff_ai.py -f capture.pcap --ai deep_hunt --confidence 80
  
  # Protocol analysis with AI
  python flagsniff_ai.py -f capture.pcap --ai protocol
  
  # Export results
  python flagsniff_ai.py -f capture.pcap --find all --ai enhanced --export results.json
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='Path to PCAP file')
    parser.add_argument('--find', choices=['flags', 'credentials', 'tokens', 'emails', 'hashes', 'all'], 
                       default='all', help='What to search for')
    parser.add_argument('--regex', help='Custom regex pattern')
    parser.add_argument('--ai', choices=['standard', 'enhanced', 'deep_hunt', 'protocol'], 
                       default='standard', help='AI analysis mode')
    parser.add_argument('--api-key', help='OpenRouter API key')
    parser.add_argument('--model', default='qwen/qwen3-235b-a22b:free', help='AI model to use')
    parser.add_argument('--confidence', type=int, default=70, help='AI confidence threshold (0-100)')
    parser.add_argument('--export', help='Export results to file (JSON/CSV/HTML)')
    parser.add_argument('--no-ai-display', action='store_true', help='Hide AI results in output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check file exists
    if not os.path.exists(args.file):
        console.print(f"❌ [red]File not found: {args.file}[/red]")
        sys.exit(1)
    
    # Setup AI agent
    agent = None
    if args.ai != 'standard':
        agent = setup_ai_agent(args.api_key, args.model)
        if not agent:
            console.print("⚠️  [yellow]Continuing with standard analysis only[/yellow]")
            args.ai = 'standard'
    
    # Setup search options
    search_options = {}
    if args.find == 'all':
        search_options = {
            'flags': True,
            'credentials': True,
            'tokens': True,
            'emails': True,
            'hashes': True
        }
    else:
        search_options[args.find] = True
    
    # Initialize analyzer
    analyzer = WebPcapAnalyzer()
    
    # Perform analysis
    results = analyze_with_ai(analyzer, agent, args.file, search_options, args.regex, args.ai)
    
    if results:
        # Display results
        display_results(results, not args.no_ai_display, args.confidence)
        
        # Export if requested
        if args.export:
            format_type = 'json'
            if args.export.endswith('.csv'):
                format_type = 'csv'
            elif args.export.endswith('.html'):
                format_type = 'html'
            
            export_results(results, format_type, args.export)
        
        console.print(f"\n🎯 [bold green]Analysis complete![/bold green]")
        
        # Show summary
        total_findings = len(results.get('findings', []))
        ai_findings = len(results.get('ai_findings', []))
        high_conf_ai = len([f for f in results.get('ai_findings', []) if f.get('confidence', 0) >= args.confidence])
        
        console.print(f"📊 Found {total_findings} standard findings")
        if ai_findings:
            console.print(f"🤖 AI discovered {ai_findings} additional candidates ({high_conf_ai} high confidence)")
    
    else:
        console.print("❌ [red]Analysis failed[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()