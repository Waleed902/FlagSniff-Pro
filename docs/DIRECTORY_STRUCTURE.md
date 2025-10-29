# FlagSniff Directory Structure

This document explains the reorganized directory structure for better maintainability and clarity.

## 📁 Root Directory Structure

```
FlagSniff-main/
├── 📱 apps/                    # Application entry points
├── 🤖 ai/                      # AI agents and orchestration
├── 🔍 analyzers/               # Protocol and traffic analyzers
├── ⚙️  config/                 # Configuration and setup
├── 🎯 core/                    # Core functionality
├── 🚨 detectors/               # Detection modules
├── 📚 docs/                    # Documentation
├── ⚡ features/                # Analysis features and modules
├── 🔌 integrations/            # External integrations
├── 📜 scripts/                 # Utility scripts
├── 🧪 tests/                   # Test suites
├── 📦 test_data/               # Sample PCAP files
├── 🎨 ui/                      # UI components
├── 🛠️  utils/                  # Utility functions
├── 🚀 run_web.py               # Main launcher
└── 📋 requirements_web.txt     # Dependencies
```

## 📱 apps/ - Application Layer

Main application entry points and interfaces:

- **app_new.py** - Streamlit web application (primary UI)
- **flagsniff.py** - Command-line interface
- **web_analyzer.py** - Core PCAP analyzer engine
- **web_interface.py** - Web UI components and helpers
- **tshark_ai.py** - TShark integration with AI capabilities

### Usage
```bash
# Run web interface
python run_web.py

# Or directly
streamlit run apps/app_new.py
```

## 🤖 ai/ - AI & Agent Systems

AI-powered analysis and multi-agent orchestration:

- **ai_agent.py** - Core AI agent implementation
- **ai_consensus_system.py** - Multi-agent consensus mechanism
- **ai_monitor.py** - AI performance monitoring
- **flagsniff_ai.py** - AI integration layer
- **multi_agent_system.py** - Multi-agent coordination
- **workflow_orchestrator.py** - Automated workflow management
- **conversational_analysis.py** - Natural language analysis interface

### Key Features
- OpenRouter API integration
- Multiple AI models (GPT-4, Claude, DeepSeek)
- Consensus-based decision making
- Automated CTF challenge solving
- Conversational analysis interface

## 🔍 analyzers/ - Protocol & Traffic Analysis

Modular analysis components organized by category:

### analyzers/protocols/
- **dns/** - DNS query/response analysis
- **http/** - HTTP traffic analysis
- **tcp/** - TCP stream analysis
- **tls/** - TLS/SSL analysis with JA3/JA3S fingerprinting
- **advanced/** - WebSocket, gRPC, MQTT, Modbus decoders

### analyzers/forensics/
- **file_carving.py** - Extract files from traffic
- **sessions.py** - TCP/UDP session reconstruction
- **voip.py** - VoIP/RTP audio extraction
- **suspicious.py** - Anomaly detection

### analyzers/crypto/
- Cryptographic analysis modules
- Cipher identification
- Key recovery attempts

### analyzers/stego/
- Steganography detection
- LSB analysis
- Hidden data extraction

### analyzers/replay/
- **packet_crafter.py** - Packet crafting and modification
- **fuzzer.py** - Protocol fuzzing engine

### analyzers/ctf/
- **auto_solver.py** - Automated CTF challenge solver
- CTF-specific analysis tools
- Flag extraction and validation

## ⚡ features/ - Analysis Features

High-level analysis modules and feature implementations:

- **advanced_features.py** - Advanced analysis capabilities
- **binary_analysis.py** - Binary protocol analysis
- **cryptanalysis_suite.py** - Cryptographic analysis suite
- **crypto_analysis_suite.py** - Alternative crypto tools
- **enhanced_analyzer.py** - Enhanced traffic analysis
- **memory_forensics.py** - Memory dump analysis
- **packet_sequence_tracker.py** - Sequence analysis
- **protocol_analysis.py** - Protocol identification
- **security_analysis.py** - Security vulnerability detection
- **steganography_suite.py** - Steganography analysis suite
- **tactical_analysis_modes.py** - Specialized analysis modes
- **core_patterns.py** - Pattern matching engine

## ⚙️ config/ - Configuration

Setup and configuration files:

- **setup_ai.py** - AI agent configuration wizard
- **.flagsniff_config.json** - Application settings

### First-Time Setup
```bash
# Configure AI features
python config/setup_ai.py
```

## 🎯 core/ - Core Functionality

Core framework components (existing):
- Base classes
- Core utilities
- Fundamental algorithms

## 🚨 detectors/ - Detection Modules

Specialized detection components (existing):
- Anomaly detection
- Threat detection
- Pattern recognition

## 🔌 integrations/ - External Integrations

Third-party tool integrations (existing):
- TShark/PyShark
- External APIs
- Database connectors

## 🎨 ui/ - UI Components

User interface components (existing):
- Streamlit widgets
- Theme configuration
- Visualization helpers

## 🛠️ utils/ - Utilities

Shared utility functions (existing):
- **parsers.py** - Data parsing utilities
- **patterns.py** - Pattern definitions
- Helper functions

## 📚 docs/ - Documentation

Project documentation:

- **FEATURE_IMPLEMENTATION_SUMMARY.md** - New features documentation
- **DIRECTORY_STRUCTURE.md** - This file
- API documentation (future)

## 🧪 tests/ - Test Suites

Unit and integration tests:
- Module tests
- Integration tests
- Test fixtures

## 📦 test_data/ - Sample Data

Sample PCAP files for testing:
- Protocol examples
- CTF challenges
- Attack scenarios

## 🚀 Quick Start

### Running the Application

```bash
# From project root
python run_web.py

# Or with custom port
python run_web.py --port 8080
```

### Importing Modules

```python
# Import from reorganized structure
from apps.web_analyzer import PcapAnalyzer
from ai.ai_agent import AgentConfig
from analyzers.protocols.tls import TLSAnalyzer
from analyzers.replay import PacketCrafter
from features.enhanced_analyzer import EnhancedAnalyzer

# Backward compatibility maintained through __init__.py
from ai import multi_agent_system
from features import advanced_features
```

## 📝 Migration Notes

### Backward Compatibility

All moved modules maintain backward compatibility through package `__init__.py` files:

```python
# Old import (still works)
import ai_agent

# New import (preferred)
from ai import ai_agent
```

### Path Updates Required

If you have custom scripts importing these modules, update paths:

**Before:**
```python
from web_analyzer import PcapAnalyzer
from ai_agent import AgentConfig
import ctf_analyzer
```

**After:**
```python
from apps.web_analyzer import PcapAnalyzer
from ai.ai_agent import AgentConfig
from analyzers.ctf import ctf_analyzer
```

## 🔄 Benefits of New Structure

1. **Clear Organization**: Files grouped by purpose
2. **Easier Navigation**: Find components quickly
3. **Better Scalability**: Easy to add new features
4. **Cleaner Root**: Only essential files at top level
5. **Logical Grouping**: Related files together
6. **Professional Structure**: Industry-standard layout

## 🎯 Future Enhancements

- Add API documentation
- Create architecture diagrams
- Add contribution guidelines
- Implement CI/CD pipeline
- Add performance benchmarks

---

**Last Updated**: October 28, 2025  
**Version**: 2.0
