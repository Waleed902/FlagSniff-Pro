# 🔍 FlagSniff Pro v2.0

> Next-generation PCAP analysis platform with AI-powered insights

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.50+-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

FlagSniff is a comprehensive network traffic analysis tool designed for CTF competitions, penetration testing, and security research. It combines powerful packet analysis with AI-driven insights to help you find flags, detect vulnerabilities, and understand network behavior.

## ✨ Key Features

### 🎯 Core Capabilities
- **Deep Packet Inspection** - Analyze PCAP/PCAPNG files with Scapy
- **Protocol Decoders** - HTTP, DNS, TCP, TLS, WebSocket, gRPC, MQTT, Modbus
- **ICMP Tunneling Detection** - Identify covert channels and data exfiltration
- **TLS Stream Reconstruction** - Extract metadata from encrypted traffic (SNI, cipher suites)
- **File Carving** - Extract files from network traffic (FTP, HTTP, SMB)
- **VoIP Analysis** - RTP/SIP audio extraction and call reconstruction
- **TLS Fingerprinting** - JA3/JA3S fingerprints for client/server identification

### 🤖 AI-Powered Analysis
- **Multi-Agent System** - Coordinated AI agents for comprehensive analysis
- **Automated CTF Solver** - Intelligent challenge classification and solving
- **Consensus Engine** - Multiple AI models working together
- **Natural Language Interface** - Ask questions about your traffic

### ⚡ Offensive Capabilities
- **Packet Crafting** - Build custom packets from templates
- **Replay & Modification** - Replay captured traffic with changes
- **Protocol Fuzzing** - Automated fuzzing with crash detection
- **Exploit Templates** - SQL injection, XSS, buffer overflow patterns

### 🎨 Modern UI
- **Streamlit Interface** - Beautiful, responsive web UI
- **Dark/Light Themes** - Comfortable viewing in any environment
- **Interactive Visualizations** - Protocol distribution, timeline analysis
- **Real-time Processing** - Instant feedback as you analyze

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/flagsniff.git
cd flagsniff

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements_web.txt

# (Optional) Configure AI features
python config/setup_ai.py
```

### Running FlagSniff

```bash
# Launch web interface
python run_web.py

# Or directly with Streamlit
streamlit run apps/app_new.py

# Custom port
python run_web.py --port 8080
```

Then open your browser to `http://localhost:8501`

### Basic Usage

1. **Upload PCAP** - Drag and drop or browse for your capture file
2. **View Overview** - See protocol distribution and key statistics
3. **Analyze** - Use built-in analyzers or ask AI questions
4. **Extract** - Pull out files, credentials, or hidden data
5. **Export** - Save findings as JSON or generate reports

## 📁 Project Structure

```
FlagSniff-main/
├── 📱 apps/           # Application entry points
├── 🤖 ai/             # AI agents and orchestration  
├── 🔍 analyzers/      # Protocol analyzers
├── ⚙️  config/        # Configuration
├── ⚡ features/       # Analysis modules
├── 📚 docs/           # Documentation
└── 🚀 run_web.py      # Main launcher
```

See [docs/DIRECTORY_STRUCTURE.md](docs/DIRECTORY_STRUCTURE.md) for detailed structure.

## 🎯 Use Cases

### CTF Competitions
- Automatic flag detection and extraction
- Challenge type classification
- Encoding chain analysis
- Steganography detection

### Penetration Testing
- Credential harvesting
- Protocol anomaly detection
- TLS/SSL security analysis
- Session hijacking opportunities

### Security Research
- Protocol reverse engineering
- Malware C2 analysis
- Encrypted traffic fingerprinting
- ICS/SCADA protocol analysis

### Network Forensics
- Incident investigation
- Data exfiltration detection
- Timeline reconstruction
- Communication pattern analysis

## 🔧 Advanced Features

### Protocol Decoders

```python
from analyzers.protocols.advanced import WebSocketDecoder, MQTTDecoder

# Decode WebSocket traffic
ws = WebSocketDecoder()
analysis = ws.analyze_websocket_traffic(packets)

# Decode MQTT messages
mqtt = MQTTDecoder()
analysis = mqtt.analyze_mqtt_traffic(packets)
```

### Packet Crafting & Replay

```python
from analyzers.replay import PacketCrafter, PacketReplayer

# Craft custom packet
crafter = PacketCrafter()
pkt = crafter.craft_packet('http_get', dst='192.168.1.1', path='/admin')

# Replay with modifications
replayer = PacketReplayer()
replayer.replay_packets([pkt], modifications={0: {'IP.ttl': 64}})
```

### TLS Fingerprinting

```python
from analyzers.protocols.tls import TLSAnalyzer

# Generate JA3/JA3S fingerprints
analyzer = TLSAnalyzer()
analysis = analyzer.analyze_tls_packets(packets)
print(analysis['ja3_fingerprints'])
```

### CTF Auto-Solver

```python
from analyzers.ctf import CTFAutoSolver

# Automatically solve challenge
solver = CTFAutoSolver()
solution = solver.solve_challenge(packets, metadata={'category': 'network'})
print(f"Flags found: {solution.flags_found}")
```

## 🤖 AI Configuration

FlagSniff supports multiple AI providers through OpenRouter:

```bash
# Run configuration wizard
python config/setup_ai.py

# Supported models:
# - GPT-4 / GPT-4 Turbo
# - Claude 3 (Opus, Sonnet, Haiku)
# - DeepSeek R1
# - Google Gemini
# - And more...
```

## 📊 Supported Formats

### Input Files
- PCAP (Packet Capture)
- PCAPNG (Next Generation)
- CAP (Wireshark)

### Protocols
- **Application**: HTTP, HTTPS, FTP, DNS, SMTP, POP3, IMAP
- **Transport**: TCP, UDP, SCTP
- **Network**: IP, ICMP, ARP
- **Modern**: WebSocket, gRPC, MQTT, Modbus
- **VoIP**: SIP, RTP, RTCP

## 🛡️ Security Features

- **Credential Detection** - Find passwords in cleartext protocols
- **Weak Cipher Detection** - Identify deprecated TLS ciphers
- **DNS Exfiltration** - Detect data tunneling over DNS
- **Suspicious Patterns** - Port scans, bruteforce attempts
- **Certificate Validation** - Check TLS certificate chains

## 🎨 Screenshots

*(Add screenshots of your UI here)*

## 📖 Documentation

- [Directory Structure](docs/DIRECTORY_STRUCTURE.md) - Project organization
- [Feature Implementation](docs/FEATURE_IMPLEMENTATION_SUMMARY.md) - New features
- [API Reference](docs/API.md) - *(Coming soon)*
- [Contributing Guide](docs/CONTRIBUTING.md) - *(Coming soon)*

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Streamlit** - Beautiful web framework
- **OpenRouter** - Multi-model AI API
- **TShark** - Network protocol analyzer
- The CTF and infosec community

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/flagsniff/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/flagsniff/discussions)

---

**Made with ❤️ for the security community**

*Last updated: October 28, 2025*
