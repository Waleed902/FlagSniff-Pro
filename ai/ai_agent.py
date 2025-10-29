"""
AI Agent for FlagSniff - Intelligent PCAP Analysis
Uses OpenRouter API for advanced pattern recognition and flag hunting
"""

import requests
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import base64
import hashlib
import socket
from urllib.parse import urlparse

class FlagSniffAgent:
    """Intelligent AI agent for automated flag hunting and analysis"""
    
    def __init__(self, api_key: str, model: str = "LongCat-Flash-Chat", base_url: str = None):
        self.api_key = api_key
        self.model = model or "LongCat-Flash-Chat"
        self.base_url = base_url or "https://api.longcat.chat/openai/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://flagsniff.local",
            "X-Title": "FlagSniff AI Agent"
        }
        
        # Ensemble analysis configuration
        self.use_ensemble = False
        self.ensemble_models = [
            "LongCat-Flash-Chat",
            "gpt-4o",
            "gpt-4-turbo",
            "gpt-3.5-turbo"
        ]
        
        # Multi-agent specialist modes for CTF analysis
        self.specialist_modes = {
            "🔍 Steganography Hunter": {
                "description": "Specialized in detecting hidden data in images, audio, and files",
                "focus": ["steganography", "hidden_data", "image_analysis", "audio_patterns"],
                "confidence_boost": 15
            },
            "🔗 Encoding Chain Decoder": {
                "description": "Multi-layer encoding analysis (Base64→Hex→ROT13, etc.)",
                "focus": ["base64", "hex", "rot13", "url_encoding", "multi_layer"],
                "confidence_boost": 20
            },
            "🕷️ Web Exploit Scanner": {
                "description": "SQL injection, XSS, and web vulnerability detection",
                "focus": ["sql_injection", "xss", "web_vulnerabilities", "http_analysis"],
                "confidence_boost": 18
            },
            "🔐 Crypto Analyzer": {
                "description": "Hash cracking, cipher identification, and cryptographic analysis",
                "focus": ["hashes", "ciphers", "cryptography", "encryption"],
                "confidence_boost": 22
            },
            "🌐 Protocol Anomaly Detector": {
                "description": "Unusual protocol behavior and covert channels",
                "focus": ["protocol_anomalies", "covert_channels", "timing_analysis"],
                "confidence_boost": 16
            },
            "📡 Network Forensics Expert": {
                "description": "Traffic correlation and attack reconstruction",
                "focus": ["attack_correlation", "forensics", "timeline_analysis"],
                "confidence_boost": 19
            },
            "🎭 Social Engineering Detector": {
                "description": "Phishing attempts and social engineering indicators",
                "focus": ["phishing", "social_engineering", "deception"],
                "confidence_boost": 14
            }
        }
        
        # False positive prevention settings - VERY CONSERVATIVE
        self.min_confidence_threshold = 85  # Minimum confidence for any finding
        self.flag_confidence_threshold = 95  # Very high threshold for flag findings
        self.credential_confidence_threshold = 95  # Very high threshold for credentials
        self.enable_strict_filtering = True
        
        # Agent personality and expertise - Optimized for API compatibility
        self.system_prompt = """You are XBOW, an elite AI agent specialized in cybersecurity and CTF competitions.

CORE CAPABILITIES:
- Pattern recognition for flags, credentials, and sensitive data
- Network traffic analysis and protocol understanding
- Cryptographic analysis and encoding detection
- CTF challenge solving with high accuracy

FLAG HUNTING:
- Recognize CTF flag formats: flag{}, CTF{}, HTB{}, etc.
- Identify encoded data (base64, hex, rot13)
- Detect hidden messages and steganography

ANALYSIS REQUIREMENTS:
- Only report high confidence findings (80%+)
- Provide detailed reasoning for each finding
- Reject potential false positives
- Focus on quality over quantity
- Validate findings against multiple criteria

DNS EXFIL RECONSTRUCTION SPECIALIST:
- Recognize chunked subdomains carrying encoded data (base64/base32/hex)
- Reconstruct data across sequential DNS queries from same src->dst and base domain
- Normalize URL-safe base64, fix padding, then decode; try hex and base32 if base64 fails
- If partial/ambiguous ordering, propose 2-3 plausible reconstructions and verification steps
- Provide concrete Wireshark/tshark filters to isolate suspicious DNS queries

When you suspect DNS exfiltration, include: (a) reconstruction steps, (b) decoding chain, (c) verification PoC.

Respond with structured JSON containing your analysis, confidence scores, and detailed reasoning."""
    
    def generate_progressive_hints(self, findings: List[Dict], progress_percentage: float, challenge_context: str = "") -> List[Dict]:
        """
        Generate progressive hints based on analysis progress and current findings
        
        Args:
            findings: Current findings from analysis
            progress_percentage: Analysis completion percentage (0-100)
            challenge_context: CTF challenge context/category
            
        Returns:
            List of progressive hints with difficulty levels
        """
        hints = []
        
        # Analyze current findings to determine progress
        finding_types = set(f.get('display_type', '').lower() for f in findings)
        has_flags = any('flag' in ft for ft in finding_types)
        has_encoded = any('encoded' in ft or 'base64' in ft for ft in finding_types)
        has_web = any('http' in ft or 'web' in ft for ft in finding_types)
        has_crypto = any('hash' in ft or 'crypto' in ft for ft in finding_types)
        
        # Progressive hint levels based on progress
        if progress_percentage < 25:
            # Initial exploration hints
            hints.extend([
                {
                    'level': 'beginner',
                    'hint': '🔍 Start by examining HTTP headers for unusual patterns or hidden data',
                    'confidence': 95,
                    'category': 'initial_recon',
                    'reasoning': 'HTTP headers often contain encoded flags or clues in CTF challenges'
                },
                {
                    'level': 'beginner', 
                    'hint': '📝 Look for suspicious strings in packet payloads - they might be encoded',
                    'confidence': 90,
                    'category': 'pattern_recognition',
                    'reasoning': 'Encoded data is frequently hidden in plain sight within packet data'
                }
            ])
            
        elif progress_percentage < 50:
            # Intermediate analysis hints
            if has_encoded:
                hints.append({
                    'level': 'intermediate',
                    'hint': '🧩 Try decoding Base64 strings - they might contain multi-layer encoding',
                    'confidence': 88,
                    'category': 'decoding',
                    'reasoning': 'Multiple encoding layers are common in intermediate CTF challenges'
                })
            
            if has_web:
                hints.append({
                    'level': 'intermediate',
                    'hint': '🌐 Analyze HTTP POST data and cookies for hidden parameters or flags',
                    'confidence': 85,
                    'category': 'web_analysis',
                    'reasoning': 'Web challenges often hide flags in form data or session cookies'
                })
                
        elif progress_percentage < 75:
            # Advanced analysis hints
            hints.extend([
                {
                    'level': 'advanced',
                    'hint': '🔗 Check for multi-layer encoding chains (Base64→Hex→ROT13→etc.)',
                    'confidence': 82,
                    'category': 'advanced_decoding',
                    'reasoning': 'Advanced challenges often use complex encoding chains'
                },
                {
                    'level': 'advanced',
                    'hint': '📁 Look for file fragments that might need reconstruction across packets',
                    'confidence': 80,
                    'category': 'file_reconstruction',
                    'reasoning': 'Files split across packets require careful reassembly'
                }
            ])
            
        else:
            # Expert-level hints
            hints.extend([
                {
                    'level': 'expert',
                    'hint': '🎯 Focus on reconstructing files from packet fragments and timing analysis',
                    'confidence': 78,
                    'category': 'expert_analysis',
                    'reasoning': 'Expert challenges often require deep protocol analysis'
                },
                {
                    'level': 'expert',
                    'hint': '🕰️ Analyze packet timing patterns for covert channels or hidden data',
                    'confidence': 75,
                    'category': 'covert_channels',
                    'reasoning': 'Timing-based covert channels are advanced steganography techniques'
                }
            ])
        
        # Context-specific hints
        if 'crypto' in challenge_context.lower():
            hints.append({
                'level': 'contextual',
                'hint': '🔐 This appears to be a crypto challenge - focus on hash identification and cipher analysis',
                'confidence': 92,
                'category': 'crypto_context',
                'reasoning': 'Crypto challenges require specialized cryptographic analysis'
            })
        elif 'web' in challenge_context.lower():
            hints.append({
                'level': 'contextual',
                'hint': '🌐 Web challenge detected - examine HTTP methods, headers, and form data carefully',
                'confidence': 90,
                'category': 'web_context',
                'reasoning': 'Web challenges focus on HTTP protocol vulnerabilities and data hiding'
            })
        elif 'forensics' in challenge_context.lower():
            hints.append({
                'level': 'contextual',
                'hint': '🔍 Forensics challenge - focus on evidence reconstruction and timeline analysis',
                'confidence': 88,
                'category': 'forensics_context',
                'reasoning': 'Forensics challenges require detailed evidence analysis and correlation'
            })
            
        return hints

    def analyze_findings(self, findings: List[Dict], packet_data: str = "") -> Dict[str, Any]:
        """
        Analyze findings using AI to provide intelligent insights
        
        Args:
            findings: List of raw findings from pattern matching
            packet_data: Raw packet data for context
            
        Returns:
            Enhanced analysis with AI insights
        """
        
        if not findings and not packet_data:
            return self._generate_fallback_analysis([], "No data to analyze")
        
        # Pre-analysis dependency validation
        if not self.api_key:
            return self._generate_fallback_analysis(findings, "API key not configured")
        
        # Use ensemble analysis if enabled
        if self.use_ensemble and len(self.ensemble_models) > 1:
            try:
                return self._ensemble_analysis(findings, packet_data)
            except Exception as e:
                return self._generate_fallback_analysis(findings, f"Ensemble analysis failed: {str(e)}")
        
        # Prepare analysis prompt
        try:
            analysis_prompt = self._create_analysis_prompt(findings, packet_data)
        except Exception as e:
            return self._generate_fallback_analysis(findings, f"Analysis prompt creation failed: {str(e)}")
        
        try:
            # Phase-by-phase analysis tracking
            response = self._call_openrouter(analysis_prompt, self.model)
            
            if response:
                # Parse AI response and enhance findings
                enhanced_analysis = self._parse_ai_response(response, findings)
                
                # Apply STRICT confidence filtering to prevent false positives
                if 'ai_analysis' in enhanced_analysis and isinstance(enhanced_analysis['ai_analysis'], dict):
                    if 'enhanced_findings' in enhanced_analysis['ai_analysis']:
                        original_findings = enhanced_analysis['ai_analysis']['enhanced_findings']
                        if isinstance(original_findings, list):
                            print(f"DEBUG: Starting with {len(original_findings)} AI findings")
                            for i, f in enumerate(original_findings):
                                print(f"  Finding {i}: {f.get('finding', f.get('data', ''))[:50]} (conf: {f.get('confidence', 0)})")
                            
                            # First pass: confidence filtering
                            confidence_filtered = self._filter_low_confidence_findings(original_findings)
                            print(f"DEBUG: After confidence filter: {len(confidence_filtered)} findings")
                            
                            # Second pass: quality validation
                            quality_filtered = []
                            for f in confidence_filtered:
                                is_valid = self._validate_finding_quality(f)
                                if is_valid:
                                    quality_filtered.append(f)
                                else:
                                    print(f"DEBUG: Rejected by quality filter: {f.get('finding', f.get('data', ''))[:50]}")
                            print(f"DEBUG: After quality filter: {len(quality_filtered)} findings")
                            
                            # Third pass: strict false positive removal
                            final_findings = []
                            for f in quality_filtered:
                                clean_findings = self._remove_false_positives([f])
                                if clean_findings:
                                    final_findings.extend(clean_findings)
                                else:
                                    print(f"DEBUG: Rejected by false positive filter: {f.get('finding', f.get('data', ''))[:50]}")
                            
                            print(f"DEBUG: Final count: {len(final_findings)} findings")
                            
                            enhanced_analysis['ai_analysis']['enhanced_findings'] = final_findings
                            enhanced_analysis['filtering_stats'] = {
                                'original_count': len(original_findings),
                                'confidence_filtered': len(confidence_filtered),
                                'quality_filtered': len(quality_filtered),
                                'final_count': len(final_findings),
                                'total_removed': len(original_findings) - len(final_findings)
                            }
                
                return enhanced_analysis
            else:
                return self._generate_fallback_analysis(findings, "AI service temporarily unavailable")
                
        except requests.exceptions.Timeout:
            return self._generate_fallback_analysis(findings, "AI service timeout - using local analysis")
        except requests.exceptions.ConnectionError:
            return self._generate_fallback_analysis(findings, "Network connectivity issue - using offline analysis")
        except requests.exceptions.RequestException as e:
            return self._generate_fallback_analysis(findings, f"API request failed: {str(e)[:50]}...")
        except Exception as e:
            return self._generate_fallback_analysis(findings, f"Analysis error: {str(e)[:50]}...")
    
    def hunt_hidden_flags(self, packet_data: str, context: str = "") -> List[Dict]:
        """
        Use AI to hunt for hidden flags that regex might miss
        
        Args:
            packet_data: Raw packet data to analyze
            context: Additional context about the capture
            
        Returns:
            List of potential hidden flags with confidence scores
        """
        
        hunt_prompt = f"""HIDDEN FLAG HUNTING MISSION

Analyze this network traffic data for hidden flags that traditional regex patterns might miss:

PACKET DATA:
```
{packet_data[:5000]}
```

CONTEXT: {context}

HUNTING OBJECTIVES:
1. Look for flags hidden in:
   - Encoded data (base64, hex, URL encoding, etc.)
   - DNS queries and responses
   - HTTP headers and unusual fields
   - Binary data patterns
   - Timing patterns or packet sequences
   - File metadata or magic bytes
   - Custom encoding schemes

2. Check for multi-stage flags:
   - Flags split across multiple packets
   - Flags requiring decoding chains
   - Flags hidden in protocol fields

3. Analyze suspicious patterns:
   - Unusual data lengths
   - Repeated patterns or sequences
   - Out-of-place characters or strings
   - Suspicious domains or URLs

4. Consider CTF techniques:
   - Steganography indicators
   - Cipher patterns
   - Hash lookups needed
   - Social engineering clues

RESPONSE FORMAT:
For each potential flag found, provide:
- flag_candidate: The potential flag string
- confidence: Confidence level (0-100%)
- location: Where it was found
- encoding: How it was hidden/encoded
- reasoning: Why you think this is a flag
- next_steps: Suggested actions to verify

Be thorough but focus on high-confidence findings. Think like an elite CTF player!
"""
        
        try:
            # Pre-analysis dependency validation
            if not self.api_key:
                return self._generate_fallback_flag_hunting(packet_data, "API key not configured")
            
            # Phase-by-phase analysis tracking
            response = self._call_openrouter(hunt_prompt)
            if response:
                return self._parse_flag_hunting_response(response)
            else:
                return self._generate_fallback_flag_hunting(packet_data, "AI service temporarily unavailable")
                
        except requests.exceptions.Timeout:
            return self._generate_fallback_flag_hunting(packet_data, "AI service timeout")
        except requests.exceptions.ConnectionError:
            return self._generate_fallback_flag_hunting(packet_data, "Network connectivity issue")
        except requests.exceptions.RequestException as e:
            return self._generate_fallback_flag_hunting(packet_data, f"API request failed: {str(e)[:50]}...")
        except Exception as e:
            return self._generate_fallback_flag_hunting(packet_data, f"Flag hunting error: {str(e)[:50]}...")
    
    def analyze_protocols(self, packet_data: str) -> Dict[str, Any]:
        """
        Analyze network protocols for security issues and hidden data
        
        Args:
            packet_data: Raw packet data
            
        Returns:
            Protocol analysis with security insights
        """
        
        protocol_prompt = f"""PROTOCOL SECURITY ANALYSIS

Analyze this network traffic for protocol-level security issues and hidden information:

TRAFFIC DATA:
```
{packet_data[:3000]}
```

ANALYSIS OBJECTIVES:

1. PROTOCOL IDENTIFICATION:
   - Identify all protocols present
   - Detect unusual or custom protocols
   - Find protocol violations or anomalies

2. SECURITY ASSESSMENT:
   - Unencrypted sensitive data
   - Weak authentication mechanisms
   - Protocol downgrade attacks
   - Man-in-the-middle indicators

3. HIDDEN DATA DETECTION:
   - Covert channels in protocol fields
   - Data exfiltration techniques
   - Tunneling protocols
   - Steganographic communication

4. ATTACK INDICATORS:
   - Reconnaissance activities
   - Exploitation attempts
   - Lateral movement patterns
   - Command and control communication

Provide structured analysis with confidence levels and actionable insights.
"""
        
        try:
            # Pre-analysis dependency validation
            if not self.api_key:
                return self._generate_fallback_protocol_analysis(packet_data, "API key not configured")
            
            # Phase-by-phase analysis tracking
            response = self._call_openrouter(protocol_prompt)
            if response:
                return {"analysis": response, "timestamp": datetime.now().isoformat()}
            else:
                return self._generate_fallback_protocol_analysis(packet_data, "AI service temporarily unavailable")
                
        except requests.exceptions.Timeout:
            return self._generate_fallback_protocol_analysis(packet_data, "AI service timeout")
        except requests.exceptions.ConnectionError:
            return self._generate_fallback_protocol_analysis(packet_data, "Network connectivity issue")
        except requests.exceptions.RequestException as e:
            return self._generate_fallback_protocol_analysis(packet_data, f"API request failed: {str(e)[:50]}...")
        except Exception as e:
            return self._generate_fallback_protocol_analysis(packet_data, f"Protocol analysis error: {str(e)[:50]}...")
    
    def suggest_next_steps(self, findings: List[Dict], analysis_context: str = "") -> List[str]:
        """
        Get AI suggestions for next analysis steps
        
        Args:
            findings: Current findings
            analysis_context: Context about the analysis
            
        Returns:
            List of suggested next steps
        """
        
        suggestions_prompt = f"""NEXT STEPS RECOMMENDATION

Based on these findings, suggest the next analysis steps:

CURRENT FINDINGS:
{json.dumps(findings, indent=2)}

CONTEXT: {analysis_context}

PROVIDE RECOMMENDATIONS FOR:

1. IMMEDIATE ACTIONS:
   - High-priority items to investigate
   - Quick wins for flag hunting
   - Critical security issues to address

2. DEEP ANALYSIS:
   - Areas requiring manual investigation
   - Tools to use for further analysis
   - Specific techniques to apply

3. EXPLOITATION OPPORTUNITIES:
   - Potential attack vectors
   - Privilege escalation paths
   - Lateral movement possibilities

4. ADDITIONAL DATA NEEDED:
   - Missing information for complete analysis
   - Additional packet captures needed
   - External resources to consult

Format as a prioritized list with clear action items.
"""
        
        try:
            # Pre-analysis dependency validation
            if not self.api_key:
                return self._generate_fallback_suggestions(findings, "API key not configured")
            
            # Phase-by-phase analysis tracking
            response = self._call_openrouter(suggestions_prompt)
            
            if response:
                # Parse response into actionable steps
                steps = self._parse_suggestions(response)
                if steps and len(steps) > 0:
                    return steps
                else:
                    return self._generate_fallback_suggestions(findings, "AI response parsing failed")
            else:
                return self._generate_fallback_suggestions(findings, "AI service temporarily unavailable")
                
        except requests.exceptions.Timeout:
            return self._generate_fallback_suggestions(findings, "AI service timeout - using local analysis")
        except requests.exceptions.ConnectionError:
            return self._generate_fallback_suggestions(findings, "Network connectivity issue - using offline analysis")
        except requests.exceptions.RequestException as e:
            return self._generate_fallback_suggestions(findings, f"API request failed: {str(e)[:50]}...")
        except Exception as e:
            return self._generate_fallback_suggestions(findings, f"Analysis error: {str(e)[:50]}...")
    
    def _create_analysis_prompt(self, findings: List[Dict], packet_data: str) -> str:
        """Create comprehensive analysis prompt for AI"""
        
        findings_summary = []
        for finding in findings[:10]:  # Limit to prevent token overflow
            findings_summary.append({
                "type": finding.get("display_type", finding.get("type", "Unknown")),
                "data": finding.get("data", finding.get("content", ""))[:200],
                "protocol": finding.get("protocol", "Unknown"),
                "context": finding.get("context", "")[:100]
            })
        
        prompt = f"""ADVANCED PCAP ANALYSIS REQUEST

Analyze these network security findings with your expert knowledge:

FINDINGS DETECTED:
{json.dumps(findings_summary, indent=2)}

SAMPLE PACKET DATA:
```
{packet_data[:2000] if packet_data else "No raw packet data provided"}
```

ANALYSIS REQUIREMENTS:

1. VALIDATE FINDINGS:
   - Assess confidence level (0-100%) for each finding
   - Identify potential false positives
   - Explain reasoning behind confidence scores

2. ENHANCE ANALYSIS:
   - Decode any encoded data found
   - Identify additional patterns or connections
   - Suggest what these findings might indicate

3. SECURITY ASSESSMENT:
   - Evaluate security implications
   - Identify attack vectors or vulnerabilities
   - Assess data sensitivity and risk level

4. CTF PERSPECTIVE:
   - If this appears to be CTF traffic, provide CTF-specific insights
   - Suggest flag hunting strategies
   - Identify potential challenge themes or techniques

5. DNS EXFIL RECONSTRUCTION (if suspected):
    - Identify chunked subdomains likely carrying encoded data
    - Group queries by src→dst and base domain; propose reconstruction order
    - Normalize URL-safe base64 and fix padding; if fails, try hex and base32
    - Provide Wireshark/tshark filters and manual verification steps

6. ACTIONABLE INSIGHTS:
   - Recommend immediate actions
   - Suggest additional analysis techniques
   - Provide exploitation guidance if applicable

RESPONSE FORMAT:
Provide structured JSON response with:
- enhanced_findings: Array of findings with confidence scores and explanations
- security_assessment: Overall security analysis
- recommendations: Prioritized list of next steps
- ctf_insights: CTF-specific observations (if applicable)
"""
        
        return prompt
    
    def _call_openrouter(self, prompt: str, model: str = None) -> Optional[str]:
        """Make API call to LongCat/OpenRouter compatible endpoint"""
        
        use_model = (model or self.model or "LongCat-Flash-Chat")
        if not isinstance(use_model, str):
            try:
                use_model = str(use_model) or "LongCat-Flash-Chat"
            except Exception:
                use_model = "LongCat-Flash-Chat"
        
        # Limit max_tokens based on model - be conservative for compatibility
        if 'LongCat' in use_model or 'longcat' in use_model.lower():
            max_tokens = 2048  # Conservative for LongCat
        elif 'gpt-4' in use_model.lower():
            max_tokens = 4096
        elif 'gpt-3.5' in use_model.lower():
            max_tokens = 2048
        else:
            max_tokens = 2048  # Default conservative value
        
        payload = {
            "model": use_model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": max_tokens
        }
        
        try:
            # Short-circuit if endpoint cannot be resolved
            try:
                parsed = urlparse(self.base_url)
                host = parsed.hostname
                if not host:
                    print("❌ Invalid AI API endpoint")
                    return None
                socket.gethostbyname(host)
            except Exception as dns_err:
                print(f"🌐 AI request skipped: endpoint resolution failed ({dns_err})")
                return None

            response = requests.post(
                self.base_url,
                headers=self.headers,
                json=payload,
                timeout=90
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                except Exception as je:
                    print(f"API Error: Invalid JSON response - {je}")
                    return None
                if isinstance(result, dict) and "choices" in result and isinstance(result.get("choices"), list) and len(result["choices"]) > 0:
                    msg = result["choices"][0]
                    try:
                        return msg["message"]["content"]
                    except Exception:
                        # Some providers use a different schema
                        return str(msg)
                else:
                    print(f"API Error: Unexpected response format - {result}")
                    return None
            elif response.status_code == 400:
                try:
                    error_detail = response.json()
                    error_msg = error_detail.get('error', {}).get('message', str(error_detail))
                except:
                    error_msg = response.text
                print(f"API Error 400 (Bad Request): {error_msg}")
                print(f"Model used: {use_model}")
                print(f"Endpoint: {self.base_url}")
                print(f"Max tokens: {max_tokens}")
                return None
            elif response.status_code == 401:
                print(f"API Error 401: Invalid API key")
                return None
            elif response.status_code == 429:
                print(f"API Error 429: Rate limit exceeded")
                return None
            else:
                print(f"API Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"API call timeout after 90 seconds")
            return None
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            return None
        except Exception as e:
            print(f"API call failed: {e}")
            return None
    
    def explain_stream(self, stream_summary: Dict[str, Any], payload_preview: str = "", ctf_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Provide a concise, structured explanation for a single stream.

        Returns a dict with 'stream_explanation' containing the model output text.
        """
        try:
            ctx_parts = []
            if ctf_context:
                if ctf_context.get('description'):
                    ctx_parts.append(f"Challenge: {ctf_context['description']}")
                if ctf_context.get('hints'):
                    ctx_parts.append(f"Hints: {ctf_context['hints']}")
                if ctf_context.get('category'):
                    ctx_parts.append(f"Category: {ctf_context['category']}")

            ssrc = stream_summary.get('src_ip', '')
            sdst = stream_summary.get('dst_ip', '')
            proto = stream_summary.get('protocol', 'TCP')
            http_counts = stream_summary.get('http_counts') or {}

            prompt = f"""EXPLAIN THIS STREAM (CTF/context-aware)

Stream:
- Protocol: {proto}
- Source -> Dest: {ssrc} -> {sdst}
- Packets: {stream_summary.get('packet_count','unknown')}
- HTTP: requests={http_counts.get('requests',0)}, responses={http_counts.get('responses',0)}

Payload preview (truncated):
```
{(payload_preview or '')[:3000]}
```

{('\nContext:\n' + '\n'.join(ctx_parts)) if ctx_parts else ''}

Respond with a short JSON containing:
{{
  "explanation": "1-3 sentence summary of what this stream likely is",
  "potential_indicators": ["list", "of", "suspicious", "clues"],
  "flag_likelihood": 0-100,
  "suggested_next_steps": ["2-4 concrete, safe steps, e.g., filters/decoding"],
  "wireshark_filters": ["practical filters"],
  "decoding_hints": ["e.g., base64->gzip"],
  "confidence": 0-100
}}
Keep it concise and actionable.
"""

            response = self._call_openrouter(prompt)
            return {"stream_explanation": response, "agent": "StreamExplainer"}
        except Exception as e:
            return {"error": f"Explain stream failed: {str(e)}"}

    def verify_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Offline verifying agent: validates AI/decoded claims to adjust confidence.

        Strategy:
        - For CTF flag candidates, validate structure and corroborate with decoded_data and findings.
        - Boost confidence when corroborated; lower when failing strict pattern validation.
        - Return a verification report and updated ctf_analysis (copy) without mutating input.
        """
        try:
            import re
            updated = {}
            ctf = dict(results.get('ctf_analysis') or {})
            flags = list(ctf.get('flag_candidates') or [])
            decoded = list(results.get('decoded_data') or [])
            findings = list(results.get('findings') or [])

            # Build searchable corpora
            decoded_texts = []
            for d in decoded:
                t = (d.get('decoded') or d.get('result') or '')
                if t:
                    decoded_texts.append(t)
            finding_texts = [str(f.get('data','')) for f in findings if f.get('data')]

            ver_report = {
                'verified_count': 0,
                'adjusted': 0,
                'items': []
            }

            strict_flag = re.compile(r"(?i)(flag|ctf|htb|ductf|picoctf)\{[^}]+\}")

            new_flags = []
            for cand in flags:
                flag = cand.get('flag') or ''
                conf = int(cand.get('confidence', 70))
                chain = cand.get('decoding_chain') or []
                checks = []
                evidence = {}

                # Check 1: strict structure
                if strict_flag.search(flag or ''):
                    checks.append('pattern_ok')
                    conf += 5
                else:
                    # Penalize if it doesn't even look like a flag
                    conf = max(0, conf - 15)
                    checks.append('pattern_fail')

                # Check 2: corroborated in decoded_data
                in_decoded = any(flag and (flag in t) for t in decoded_texts)
                if in_decoded:
                    checks.append('corroborated_decoded')
                    conf += 10
                    evidence['decoded_match'] = True

                # Check 3: appears across multiple places (findings)
                occurrences = sum(1 for t in finding_texts if flag and flag in t)
                if occurrences >= 2:
                    checks.append('multi_occurrence')
                    conf += 7
                    evidence['occurrences'] = occurrences

                # Check 4: chain strength
                if chain:
                    bump = min(3, len(chain)) * 2
                    conf += bump
                    checks.append('chain_bonus')

                conf = min(99, max(0, conf))

                new_cand = dict(cand)
                new_cand['confidence'] = conf
                new_cand['verification'] = {
                    'checks': checks,
                    'evidence': evidence,
                    'verified': ('pattern_ok' in checks) and (conf >= 80)
                }
                if new_cand['verification']['verified']:
                    ver_report['verified_count'] += 1
                if conf != cand.get('confidence'):
                    ver_report['adjusted'] += 1
                ver_report['items'].append({
                    'flag': flag,
                    'confidence_before': cand.get('confidence'),
                    'confidence_after': conf,
                    'checks': checks
                })
                new_flags.append(new_cand)

            if flags:
                ctf['flag_candidates'] = new_flags
                updated['ctf_analysis'] = ctf
            updated['verification_report'] = ver_report
            return updated
        except Exception as e:
            return {'verification_error': str(e)}

    def plan_actions(self, query: str, results_ctx: Dict[str, Any], allow_ai: bool = True) -> Dict[str, Any]:
        """Plan whitelisted actions for the Copilot based on a user query and current results.

        Returns a dict {"answer": str, "actions": [ {"type": str, "params": {...}} ]}
    Allowed actions: list_findings, show_decoded, show_ctf_flags, explain_stream, extract_stream_by_id,
             search_text, decode_text, list_sessions, search_decoded, show_jwts, verify_flags,
             reanalyze_full, tshark_summary, auto_decode_hunt
        The planner is AI-assisted when available; otherwise falls back to simple keyword rules.
        """
        allowed = {
            'list_findings', 'show_decoded', 'show_ctf_flags', 'explain_stream',
            'extract_stream_by_id', 'search_text', 'decode_text',
            'list_sessions', 'search_decoded', 'show_jwts', 'verify_flags',
            'reanalyze_full', 'tshark_summary', 'auto_decode_hunt'
        }
        base_answer = "I'll help using only the uploaded PCAP results."
        actions: List[Dict[str, Any]] = []

        # Offline rules fallback
        lower = (query or '').lower()
        # Simple NLP-ish intent hints (synonyms/keywords)
        synonyms = {
            'show_jwts': ['jwt', 'jwts', 'json web token', 'bearer token', 'id token', 'access token'],
            'list_sessions': ['sessions', 'flows', 'conversations', 'connections'],
            'show_ctf_flags': ['flags', 'flag candidates', 'ctf flag', 'capture the flag'],
            'show_decoded': ['decoded', 'decoding results', 'decode output'],
            'search_text': ['search', 'find', 'grep'],
            'search_decoded': ['search decoded', 'find decoded', 'grep decoded'],
            'verify_flags': ['verify flags', 'verify flag', 'validate flag', 'validate flags', 'confirm flag', 'check flag'],
            'reanalyze_full': ['re-analyze', 'reanalyze', 're analyze', 'rerun analysis', 're run analysis', 'refresh analysis', 'run again'],
            'tshark_summary': ['tshark', 'pre-analysis', 'http summary', 'dns summary', 'run tshark'],
            'auto_decode_hunt': ['decode hunt', 'try more decoders', 're-run decoders', 'auto decode', 'bruteforce decode']
        }
        def match_any(words: list) -> bool:
            return any(w in lower for w in words)
        if 'flag' in lower or match_any(synonyms['show_ctf_flags']):
            actions.append({'type': 'show_ctf_flags', 'params': {}})
        if ('verify' in lower and 'flag' in lower) or match_any(synonyms['verify_flags']):
            actions.append({'type': 'verify_flags', 'params': {}})
        if 'decoded' in lower or 'decode' in lower or match_any(synonyms['show_decoded']):
            actions.append({'type': 'show_decoded', 'params': {}})
        if 'findings' in lower or 'summary' in lower:
            actions.append({'type': 'list_findings', 'params': {'limit': 10}})
        if 'session' in lower or match_any(synonyms['list_sessions']):
            actions.append({'type': 'list_sessions', 'params': {'limit': 10}})
        if 'jwt' in lower or 'token' in lower or match_any(synonyms['show_jwts']):
            actions.append({'type': 'show_jwts', 'params': {}})
        if 'search ' in lower or match_any(synonyms['search_text']):
            term = lower.split('search ', 1)[-1][:64]
            if term:
                actions.append({'type': 'search_text', 'params': {'q': term}})
        # decoded-specific search
        import re as _re
        m_dec = _re.search(r'(?:search\s+decoded|decoded\s+search|in\s+decoded)\s+(.+)', lower)
        if m_dec:
            term = m_dec.group(1).strip()[:64]
            if term:
                actions.append({'type': 'search_decoded', 'params': {'q': term}})
        if 'stream ' in lower and any(x in lower for x in ['explain', 'analyze']):
            # try to parse an id
            import re
            m = re.search(r'stream\s+(\S+)', lower)
            if m:
                actions.append({'type': 'explain_stream', 'params': {'stream_id': m.group(1)}})

        # Re-analysis intents (safe, offline)
        if any(w in lower for w in synonyms['reanalyze_full']):
            actions.append({'type': 'reanalyze_full', 'params': {}})
        if any(w in lower for w in synonyms['tshark_summary']):
            actions.append({'type': 'tshark_summary', 'params': {}})
        if any(w in lower for w in synonyms['auto_decode_hunt']):
            actions.append({'type': 'auto_decode_hunt', 'params': {}})

        # If AI available, ask to refine into a structured plan (kept conservative)
        if allow_ai and self.api_key:
            try:
                snapshot = {
                    'findings_count': len(results_ctx.get('findings', [])),
                    'decoded_count': len(results_ctx.get('decoded_data', [])),
                    'streams_count': len((results_ctx.get('reconstructed_streams') or {}).keys()),
                    'sessions_count': len((results_ctx.get('sessions') or {}).keys()),
                    'jwt_count': len(results_ctx.get('jwt_tokens', [])),
                    'ctf_flags': [c.get('flag') for c in (results_ctx.get('ctf_analysis', {}).get('flag_candidates', []) or [])][:5]
                }
                plan_prompt = f"""You are a Copilot limited to the given PCAP results. Propose a JSON plan of whitelisted actions only.
User query: {query}
Context: {json.dumps(snapshot)[:1200]}
Whitelisted actions: list_findings, show_decoded, show_ctf_flags, explain_stream, extract_stream_by_id, search_text, decode_text, list_sessions, search_decoded, show_jwts, verify_flags, reanalyze_full, tshark_summary, auto_decode_hunt
Respond as compact JSON: {{"answer": "short helpful reply", "actions": [{{"type":"...","params":{{...}}}}]}}
Do not invent data; only plan actions over provided results.
"""
                ai = self._call_openrouter(plan_prompt)
                parsed = None
                if ai:
                    for cand in self._extract_json_candidates(ai):
                        parsed = self._attempt_json_load(cand)
                        if isinstance(parsed, dict):
                            break
                if isinstance(parsed, dict):
                    answer = parsed.get('answer') or base_answer
                    ai_actions = parsed.get('actions') or []
                    # filter to allowed
                    filtered = [a for a in ai_actions if isinstance(a, dict) and a.get('type') in allowed]
                    if filtered:
                        actions = filtered
                        base_answer = answer
            except Exception:
                pass

        return {"answer": base_answer, "actions": actions}

    def answer_query(self, query: str, results_ctx: Dict[str, Any], allow_ai: bool = True) -> Dict[str, Any]:
        """Produce a concise answer strictly from results_ctx, with optional AI help."""
        # Build a tiny, bounded context excerpt
        try:
            findings = results_ctx.get('findings', [])[:10]
            decoded = results_ctx.get('decoded_data', [])[:10]
            flags = (results_ctx.get('ctf_analysis', {}).get('flag_candidates', []) or [])[:5]
            ctx_blob = {
                'findings_preview': [
                    {'type': f.get('display_type', f.get('type','')), 'conf': f.get('confidence',0), 'sample': str(f.get('data',''))[:120]}
                    for f in findings
                ],
                'decoded_preview': [
                    {'chain': d.get('chain', []), 'sample': (d.get('decoded') or d.get('result',''))[:120]}
                    for d in decoded
                ],
                'flags_preview': [
                    {'flag': c.get('flag'), 'conf': c.get('confidence',0)} for c in flags
                ]
            }

            if allow_ai and self.api_key:
                prompt = (
                    "You are a Copilot limited to answering from provided results only.\n"+
                    "User question: " + (query or '') + "\n" +
                    "RESULTS CONTEXT (summaries only):\n" + json.dumps(ctx_blob)[:2500] + "\n" +
                    "Answer concisely. If something isn't in the results, say you cannot verify it from this PCAP."
                )
                ai = self._call_openrouter(prompt)
                if ai:
                    return {"text": ai}
        except Exception:
            pass

        # Fallback minimal rule-based answer
        found_flags = [c.get('flag') for c in flags] if 'flags' in locals() else []
        if found_flags:
            return {"text": f"Found {len(found_flags)} flag candidate(s). Top: {found_flags[0]}"}
        if findings:
            return {"text": f"There are {len(results_ctx.get('findings', []))} findings. You can ask to list or search them."}
        return {"text": "I can search findings, decoded data, and streams from the uploaded PCAP. Ask me what to do."}

    # --- Local decoding/crypto helpers to let AI "go through" enc/dec without cloud ---
    def offline_decode_text(self, text: str) -> Dict[str, Any]:
        """Run local decoders/crypto analyzers on a text snippet and return best candidates.
        Uses EncodingDecoder and CryptanalysisEngine without external services.
        """
        try:
            from analyzers.ctf.ctf_analyzer import EncodingDecoder
            from features.cryptanalysis_suite import ModernCryptoAnalyzer
        except Exception:
            return {"error": "Decoders unavailable"}

        results: Dict[str, Any] = {"input": text[:120], "candidates": []}
        dec = EncodingDecoder()
        # Single-step decodes
        dec_all = dec.decode_all(text)
        for k, v in (dec_all or {}).items():
            if v and v != text:
                results["candidates"].append({"chain": [k], "decoded": v, "score": 0.6})

        # Chain decodes
        chains = dec.decode_chain(text)
        for c in chains:
            results["candidates"].append({"chain": c.get('chain', []), "decoded": c.get('decoded', ''), "score": 0.75})

        # Try repeating-key XOR if underlying looks like bytes via base64/hex
        try:
            import re as _re, base64 as _b64, binascii as _ba
            m_b64 = _re.fullmatch(r'[A-Za-z0-9+/=\-_]{24,}', text.strip())
            m_hex = _re.fullmatch(r'[0-9a-fA-F]{32,}', text.strip())
            data_bytes = None
            if m_b64:
                try:
                    data_bytes = _b64.b64decode(text.strip().replace('-', '+').replace('_','/'))
                except Exception:
                    data_bytes = None
            if (data_bytes is None) and m_hex and len(text.strip()) % 2 == 0:
                try:
                    data_bytes = _ba.unhexlify(text.strip())
                except Exception:
                    data_bytes = None
            if data_bytes:
                mca = ModernCryptoAnalyzer()
                rks = mca.repeating_xor_break(data_bytes)
                for cand in (rks or [])[:3]:
                    try:
                        dec_txt = (cand.get('decrypted') or b'').decode('utf-8', errors='ignore')
                    except Exception:
                        dec_txt = ''
                    results["candidates"].append({
                        "chain": ["repeating_xor"],
                        "decoded": dec_txt,
                        "key_hex": cand.get('key_hex'),
                        "score": float(cand.get('confidence', 0))/100.0
                    })
        except Exception:
            pass

        # Rank best
        results["candidates"] = [c for c in results["candidates"] if (c.get('decoded') or '').strip()]
        results["candidates"] = sorted(results["candidates"], key=lambda x: x.get('score', 0), reverse=True)[:5]
        return results

    def auto_decode_hunt(self, results_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan results for suspicious strings and attempt local decodes/crypto.
        Returns a list of decoded_data-like dicts to merge into results.
        """
        out: List[Dict[str, Any]] = []
        try:
            # Collect candidates from findings and decoded_data originals
            cands: List[Tuple[str, Optional[int], str]] = []  # (text, packet_index, source)
            for f in (results_ctx.get('findings') or [])[:200]:
                t = str(f.get('data') or '')
                if t and len(t) >= 12:
                    cands.append((t[:5000], f.get('packet_index'), f.get('type', 'finding')))
            for d in (results_ctx.get('decoded_data') or [])[:200]:
                t = str(d.get('original') or d.get('result') or d.get('decoded') or '')
                if t and len(t) >= 12:
                    cands.append((t[:5000], d.get('packet_index'), d.get('type', 'decoded')))

            seen = set()
            import re as _re
            for text, pkt_idx, src in cands[:50]:
                # pick substrings that look encoded
                parts = _re.findall(r'[A-Za-z0-9+/=\-_]{24,}', text) + _re.findall(r'\b[0-9a-fA-F]{32,}\b', text)
                for p in parts[:5]:
                    if p in seen:
                        continue
                    seen.add(p)
                    res = self.offline_decode_text(p)
                    for cand in res.get('candidates', [])[:3]:
                        out.append({
                            'type': 'ai_decode',
                            'original': p,
                            'decoded': cand.get('decoded', ''),
                            'chain': cand.get('chain', []),
                            'protocol': 'Unknown',
                            'packet_index': pkt_idx if isinstance(pkt_idx, int) else -1,
                            'confidence': cand.get('score', 0.6),
                            'source': f'AI decode from {src}'
                        })
        except Exception:
            return []
        return out

    def _extract_json_candidates(self, text: str) -> List[str]:
        """Extract likely JSON snippets from a free-form LLM response.

        Strategies:
        - Prefer fenced blocks ```json ... ```
        - Accept fenced generic blocks containing braces
        - Scan balanced {...} and [...] blocks while respecting quoted strings
        """
        candidates: List[str] = []
        if not text:
            return candidates

        # 1) ```json ... ``` fenced blocks
        fence_json = re.findall(r"```json\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
        candidates.extend([s.strip() for s in fence_json if s.strip()])

        # 2) Generic fenced blocks containing JSON-looking content
        fence_generic = re.findall(r"```\s*([\s\S]*?)```", text, re.DOTALL)
        for block in fence_generic:
            b = block.strip()
            if '{' in b or '[' in b:
                candidates.append(b)

        # 3) Balanced brace/Bracket scanning
        def scan_balanced(src: str, open_ch: str, close_ch: str) -> List[str]:
            out = []
            n = len(src)
            i = 0
            while i < n:
                if src[i] == open_ch:
                    depth = 0
                    j = i
                    in_str = False
                    esc = False
                    while j < n:
                        ch = src[j]
                        if in_str:
                            if esc:
                                esc = False
                            elif ch == '\\':
                                esc = True
                            elif ch == '"':
                                in_str = False
                        else:
                            if ch == '"':
                                in_str = True
                            elif ch == open_ch:
                                depth += 1
                            elif ch == close_ch:
                                depth -= 1
                                if depth == 0:
                                    segment = src[i:j+1]
                                    # Avoid extremely large segments
                                    if len(segment) <= 200000:
                                        out.append(segment)
                                    i = j
                                    break
                        j += 1
                i += 1
            return out

        candidates.extend(scan_balanced(text, '{', '}'))
        candidates.extend(scan_balanced(text, '[', ']'))

        # De-duplicate while preserving order
        seen = set()
        uniq = []
        for c in candidates:
            key = c.strip()
            if key not in seen:
                seen.add(key)
                uniq.append(key)
        return uniq[:10]

    def _attempt_json_load(self, s: str) -> Optional[Any]:
        """Try to parse JSON with a couple of gentle repairs for common LLM artifacts."""
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            pass
        # Remove trailing commas before } or ]
        try:
            fixed = re.sub(r",\s*([}\]])", r"\1", s)
            return json.loads(fixed)
        except Exception:
            pass
        # Replace Python literals with JSON
        try:
            fixed2 = s.replace("None", "null").replace("True", "true").replace("False", "false")
            return json.loads(fixed2)
        except Exception:
            return None

    def _parse_ai_response(self, response: str, original_findings: List[Dict]) -> Dict[str, Any]:
        """Parse AI response and structure the analysis"""
        
        # Try robust JSON extraction first
        try:
            candidates = self._extract_json_candidates(response)
            parsed: Optional[Any] = None
            for cand in candidates:
                parsed = self._attempt_json_load(cand)
                if parsed is not None:
                    break

            if parsed is not None:
                # If it's an array, wrap for consistency
                if isinstance(parsed, list):
                    parsed = {"items": parsed}

                # Fix common formatting issues
                if 'ctf_insights' in parsed and isinstance(parsed['ctf_insights'], dict):
                    ctf_insights = parsed['ctf_insights']
                    
                    # Fix challenge_themes if it's improperly formatted
                    if 'challenge_themes' in ctf_insights:
                        themes = ctf_insights['challenge_themes']
                        
                        # If themes is a string that looks like a list, try to parse it
                        if isinstance(themes, str) and themes.strip().startswith('['):
                            try:
                                ctf_insights['challenge_themes'] = json.loads(themes)
                            except:
                                # If JSON parsing fails, split by common delimiters
                                ctf_insights['challenge_themes'] = [t.strip() for t in themes.replace('[', '').replace(']', '').replace('"', '').split(',') if t.strip()]
                        
                        # If themes is a very long string with individual characters, fix it
                        elif isinstance(themes, str) and len(themes) > 100 and ',' in themes:
                            # Split by comma and clean up
                            theme_list = [t.strip() for t in themes.split(',') if t.strip() and len(t.strip()) > 1]
                            if theme_list:
                                ctf_insights['challenge_themes'] = theme_list
                            else:
                                # Fallback: treat as single theme
                                ctf_insights['challenge_themes'] = [themes[:50] + '...' if len(themes) > 50 else themes]
                        
                        # Ensure it's always a list
                        elif isinstance(themes, str):
                            ctf_insights['challenge_themes'] = [themes]
                
                return {
                    "ai_analysis": parsed,
                    "raw_response": response,
                    "original_findings": original_findings,
                    "analysis_timestamp": datetime.now().isoformat()
                }
        except Exception:
            # Silently fall back to text analysis if JSON parsing fails
            pass
        
        # Fallback to text analysis
        return {
            "ai_analysis": {"text_analysis": response},
            "raw_response": response,
            "original_findings": original_findings,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def _parse_flag_hunting_response(self, response: str) -> List[Dict]:
        """Parse flag hunting response into structured findings with POCs"""
        
        flags = []
        
        # Try to parse JSON response first
        try:
            # Look for JSON in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_data = json.loads(json_match.group())
                if 'flag_candidates' in json_data:
                    for candidate in json_data['flag_candidates']:
                        if self._validate_flag_candidate(candidate.get('flag', '')):
                            flags.append(candidate)
                    return flags
        except:
            pass
        
        # Parse structured text response
        lines = response.split('\n')
        current_flag = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Parse different fields
            if 'flag:' in line.lower() or 'flag_candidate:' in line.lower():
                if current_flag and current_flag.get('flag_candidate'):
                    if self._validate_flag_candidate(current_flag['flag_candidate']):
                        flags.append(current_flag)
                current_flag = {"flag_candidate": line.split(':', 1)[1].strip()}
            elif 'confidence:' in line.lower():
                try:
                    conf = re.search(r'(\d+)', line)
                    if conf:
                        current_flag["confidence"] = int(conf.group(1))
                except:
                    current_flag["confidence"] = 50
            elif 'reasoning:' in line.lower():
                current_flag["reasoning"] = line.split(':', 1)[1].strip()
            elif 'poc:' in line.lower():
                current_flag["poc"] = line.split(':', 1)[1].strip()
            elif 'exploitation_steps:' in line.lower():
                current_flag["exploitation_steps"] = line.split(':', 1)[1].strip()
            elif 'tools_needed:' in line.lower():
                current_flag["tools_needed"] = line.split(':', 1)[1].strip()
            elif 'location:' in line.lower():
                current_flag["location"] = line.split(':', 1)[1].strip()
            elif 'encoding:' in line.lower():
                current_flag["encoding"] = line.split(':', 1)[1].strip()
        
        # Add the last flag if valid
        if current_flag and current_flag.get('flag_candidate'):
            if self._validate_flag_candidate(current_flag['flag_candidate']):
                flags.append(current_flag)
        
        # If no structured response, look for direct flag patterns (but validate strictly)
        if not flags:
            flag_patterns = [
                r'flag\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}',
                r'CTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}',
                r'HTB\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}',
                r'DUCTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}',
                r'PICOCTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}'
            ]
            
            for pattern in flag_patterns:
                matches = re.finditer(pattern, response, re.IGNORECASE)
                for match in matches:
                    flag_candidate = match.group()
                    if self._validate_flag_candidate(flag_candidate):
                        flags.append({
                            "flag_candidate": flag_candidate,
                            "confidence": 90,
                            "source": "pattern_match",
                            "reasoning": "Direct flag pattern match with validation",
                            "poc": f"Flag found using pattern matching. Verify by searching for: {flag_candidate}",
                            "location": "Network traffic analysis",
                            "encoding": "plaintext"
                        })
        
        return flags
    
    def _validate_flag_candidate(self, flag_candidate: str) -> bool:
        """Validate if a flag candidate is likely to be real"""
        
        if not flag_candidate or len(flag_candidate) < 10:
            return False
        
        # Check for valid flag format
        valid_patterns = [
            r'^flag\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}$',
            r'^[A-Z]{2,8}\{[A-Za-z0-9_\-!@#$%^&*()+=]{8,}\}$'
        ]
        
        if not any(re.match(pattern, flag_candidate) for pattern in valid_patterns):
            return False
        
        # Reject obvious false positives
        false_positives = [
            'windows', 'microsoft', 'build', 'version', 'system', 'program',
            'copyright', 'corp', 'ltd', 'inc', 'temp', 'user', 'admin',
            'guest', 'test', 'default', 'sample', 'example'
        ]
        
        flag_content = flag_candidate.lower()
        if any(fp in flag_content for fp in false_positives):
            return False
        
        # Must have reasonable entropy (not just repeated characters)
        content = flag_candidate.split('{')[1].split('}')[0]
        if len(set(content.lower())) < 4:  # At least 4 different characters
            return False
        
        return True
    
    def _remove_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Remove obvious false positives with strict rules"""
        
        clean_findings = []
        
        for finding in findings:
            data = str(finding.get('data', finding.get('flag_candidate', ''))).strip()
            
            # Strict false positive patterns
            false_positive_indicators = [
                r'windows.*build',
                r'microsoft.*corp',
                r'64-bit.*windows',
                r'program.*files',
                r'system32',
                r'copyright.*\d{4}',
                r'version.*\d+\.\d+',
                r'temp.*folder',
                r'user.*profile',
                r'all.*rights.*reserved',
                r'\\windows\\',
                r'c:\\',
                r'\.exe',
                r'\.dll',
                r'registry',
                r'software\\',
                r'currentversion'
            ]
            
            # Check if this looks like a false positive
            is_false_positive = False
            for pattern in false_positive_indicators:
                if re.search(pattern, data.lower()):
                    is_false_positive = True
                    print(f"Removed false positive: {data[:50]}... (matched: {pattern})")
                    break
            
            # Additional checks for flags
            if not is_false_positive and ('flag' in str(finding.get('type', '')).lower() or finding.get('flag_candidate')):
                flag_data = finding.get('flag_candidate', data)
                
                # Must be a proper flag format - UPDATED to be more inclusive
                valid_flag_formats = [
                    r'^[A-Za-z0-9_]+\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Generic format
                    r'^[A-Za-z]{2,10}[0-9]{2,4}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Event format like TJDGW2023{...}
                    r'^flag\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$'  # Basic flag format
                ]
                
                if not any(re.match(pattern, flag_data) for pattern in valid_flag_formats):
                    is_false_positive = True
                    print(f"Removed invalid flag format: {flag_data}")
                
                # Check content entropy
                if '{' in flag_data and '}' in flag_data:
                    content = flag_data.split('{')[1].split('}')[0]
                    if len(set(content.lower())) < 4:  # Low entropy
                        is_false_positive = True
                        print(f"Removed low entropy flag: {flag_data}")
            
            if not is_false_positive:
                clean_findings.append(finding)
        
        return clean_findings
    
    def _generate_fallback_analysis(self, findings: List[Dict], reason: str) -> Dict[str, Any]:
        """
        Generate intelligent fallback analysis when AI services are unavailable.
        
        Args:
            findings: Current findings to analyze
            reason: Reason why AI analysis failed
            
        Returns:
            Fallback analysis with enhanced insights
        """
        
        # Count findings by type
        finding_types = {}
        for finding in findings:
            finding_type = finding.get('display_type', finding.get('type', 'unknown'))
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
        
        # Generate confidence scores based on pattern analysis
        enhanced_findings = []
        for finding in findings:
            enhanced = dict(finding)
            
            # Assign confidence based on finding type and content
            data = finding.get('data', '').lower()
            finding_type = finding.get('display_type', finding.get('type', 'unknown'))
            
            if finding_type == 'FLAG':
                if 'flag{' in data or 'ctf{' in data:
                    confidence = 95
                    risk_level = 'high'
                elif any(prefix in data for prefix in ['htb{', 'picoctf{', 'ductf{']):
                    confidence = 90
                    risk_level = 'high'
                else:
                    confidence = 75
                    risk_level = 'medium'
            elif finding_type == 'CREDENTIAL':
                if 'password' in data or 'passwd' in data:
                    confidence = 88
                    risk_level = 'high'
                else:
                    confidence = 82
                    risk_level = 'medium'
            elif finding_type == 'TOKEN':
                if len(data) > 20 and any(c.isdigit() for c in data) and any(c.isalpha() for c in data):
                    confidence = 85
                    risk_level = 'medium'
                else:
                    confidence = 78
                    risk_level = 'low'
            else:
                confidence = 70
                risk_level = 'low'
            
            enhanced['ai_analysis'] = {
                'confidence': confidence,
                'explanation': f'Offline analysis based on {finding_type.lower()} pattern recognition',
                'suggestions': [f'Manual verification recommended for {finding_type.lower()}'],
                'related_findings': [],
                'risk_level': risk_level
            }
            enhanced_findings.append(enhanced)
        
        # Generate security assessment
        security_assessment = {
            'total_findings': len(findings),
            'high_risk_count': sum(1 for f in enhanced_findings if f['ai_analysis']['risk_level'] == 'high'),
            'analysis_mode': 'offline_fallback',
            'confidence_range': 'medium',
            'recommendations': [
                'Review high-confidence findings first',
                'Verify credentials and tokens manually',
                'Check for additional encoding in suspicious data'
            ]
        }
        
        # Generate recommendations based on findings
        recommendations = []
        if finding_types.get('FLAG', 0) > 0:
            recommendations.append('🏆 Verify flag format and submission requirements')
        if finding_types.get('CREDENTIAL', 0) > 0:
            recommendations.append('🔐 Test discovered credentials on target systems')
        if finding_types.get('TOKEN', 0) > 0:
            recommendations.append('🎫 Analyze token structure for additional information')
        if not recommendations:
            recommendations.append('🔍 Continue analysis with additional search patterns')
        
        return {
            'ai_analysis': {
                'enhanced_findings': enhanced_findings,
                'security_assessment': security_assessment,
                'recommendations': recommendations,
                'analysis_metadata': {
                    'mode': 'fallback',
                    'reason': reason,
                    'timestamp': datetime.now().isoformat(),
                    'fallback_version': 'v1.0'
                }
            },
            'status': 'fallback_analysis_complete',
            'offline_mode': True
        }

    def _generate_fallback_flag_hunting(self, packet_data: str, reason: str) -> List[Dict]:
        """
        Generate intelligent fallback flag hunting when AI services are unavailable.
        
        Args:
            packet_data: Packet data to analyze
            reason: Reason why AI flag hunting failed
            
        Returns:
            List of potential flag findings based on pattern matching
        """
        
        fallback_flags = []
        
        # Basic regex patterns for flag detection
        import re
        
        # Common flag patterns
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'DUCTF\{[^}]+\}',
            r'PICOCTF\{[^}]+\}',
            r'\w+\{[a-zA-Z0-9_-]{8,}\}'
        ]
        
        text_data = packet_data[:5000] if packet_data else ""  # Limit analysis
        
        for i, pattern in enumerate(flag_patterns):
            matches = re.findall(pattern, text_data, re.IGNORECASE)
            for match in matches:
                # Higher confidence for known formats, but ensure reasonable scores
                if i < 3:  # Very specific patterns (flag{, CTF{, HTB{)
                    confidence = 92
                elif i < 5:  # Common CTF patterns
                    confidence = 88
                else:  # General patterns
                    confidence = 80
                    
                fallback_flags.append({
                    'flag_candidate': match,
                    'confidence': confidence,
                    'location': 'packet_data',
                    'encoding': 'plaintext',
                    'reasoning': f'Matches {pattern} pattern in offline analysis',
                    'next_steps': ['Verify flag format', 'Check submission requirements'],
                    'source': 'fallback_analysis',
                    'reason': reason
                })
        
        # Look for base64 encoded potential flags
        import base64
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text_data)
        for b64_str in base64_patterns[:5]:  # Limit to first 5 matches
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                # Check if decoded text contains flag patterns
                for pattern in flag_patterns[:3]:  # Check common patterns only
                    if re.search(pattern, decoded, re.IGNORECASE):
                        fallback_flags.append({
                            'flag_candidate': decoded,
                            'confidence': 85,  # Higher confidence for base64 decoded flags
                            'location': 'base64_encoded_data',
                            'encoding': 'base64',
                            'reasoning': 'Base64 decoded data contains flag pattern',
                            'next_steps': ['Verify decoded flag', 'Check for additional encoding'],
                            'source': 'fallback_analysis',
                            'reason': reason
                        })
            except Exception:
                continue
        
        return fallback_flags

    def _generate_fallback_protocol_analysis(self, packet_data: str, reason: str) -> Dict[str, Any]:
        """
        Generate intelligent fallback protocol analysis when AI services are unavailable.
        
        Args:
            packet_data: Packet data to analyze
            reason: Reason why AI protocol analysis failed
            
        Returns:
            Basic protocol analysis based on pattern recognition
        """
        
        # Basic protocol detection
        protocols_detected = []
        security_issues = []
        
        text_data = packet_data[:3000] if packet_data else ""
        
        # Basic protocol indicators
        if 'HTTP/' in text_data:
            protocols_detected.append('HTTP')
            if 'Authorization:' in text_data:
                security_issues.append('HTTP authentication detected - check for credentials')
        
        if 'DNS' in text_data or any(domain in text_data for domain in ['.com', '.org', '.net']):
            protocols_detected.append('DNS')
            security_issues.append('DNS queries detected - check for data exfiltration')
        
        if 'TCP' in text_data:
            protocols_detected.append('TCP')
        
        if 'UDP' in text_data:
            protocols_detected.append('UDP')
        
        # Look for potential credentials
        import re
        if re.search(r'password|passwd|pwd', text_data, re.IGNORECASE):
            security_issues.append('Potential password references found')
        
        if re.search(r'token|auth|session', text_data, re.IGNORECASE):
            security_issues.append('Potential authentication tokens detected')
        
        analysis_text = f"""
**OFFLINE PROTOCOL ANALYSIS**

Protocols Detected: {', '.join(protocols_detected) if protocols_detected else 'Unknown'}

Security Observations:
{chr(10).join(f'- {issue}' for issue in security_issues) if security_issues else '- No obvious security issues detected'}

Recommendations:
- Manual review recommended for complete analysis
- Use Wireshark for detailed protocol inspection
- Check for encrypted communications

Fallback Reason: {reason}
"""
        
        return {
            "analysis": analysis_text,
            "timestamp": datetime.now().isoformat(),
            "mode": "fallback",
            "protocols": protocols_detected,
            "security_issues": security_issues,
            "reason": reason
        }

    def _generate_fallback_suggestions(self, findings: List[Dict], reason: str) -> List[str]:
        """Generate intelligent fallback suggestions when AI is unavailable"""
        suggestions = [
            f"🔄 **Analysis Status**: {reason}",
            "📊 **Offline Analysis Available**: Using local pattern matching and heuristics"
        ]
        
        # Analyze findings to provide specific suggestions
        finding_types = set()
        protocols = set()
        
        for finding in findings[:20]:  # Limit to avoid overwhelming output
            if isinstance(finding, dict):
                finding_types.add(finding.get('display_type', finding.get('type', 'Unknown')))
                protocols.add(finding.get('protocol', 'Unknown'))
        
        # Generate suggestions based on what was found
        if 'FLAG' in finding_types or 'POTENTIAL FLAG' in finding_types:
            suggestions.extend([
                "🏆 **Flag Analysis**: Review identified flags for format validation",
                "🔍 **Cross-Reference**: Check if flags match expected CTF format patterns",
                "📝 **Documentation**: Note flag locations and extraction methods"
            ])
        
        if 'CREDENTIAL' in finding_types:
            suggestions.extend([
                "🔐 **Credential Security**: Validate credential authenticity and scope",
                "🔒 **Access Testing**: Test credentials against identified services",
                "⚠️ **Security Review**: Assess credential exposure risks"
            ])
        
        if 'JWT' in finding_types or 'TOKEN' in finding_types:
            suggestions.extend([
                "🎫 **Token Analysis**: Decode JWT headers and payloads",
                "⏰ **Expiration Check**: Verify token validity periods",
                "🔑 **Signature Validation**: Check token signature algorithms"
            ])
        
        if 'HTTP' in protocols:
            suggestions.extend([
                "🌐 **HTTP Analysis**: Review request/response patterns",
                "📋 **Header Inspection**: Examine HTTP headers for anomalies",
                "🍪 **Session Management**: Analyze cookies and session tokens"
            ])
        
        if 'DNS' in protocols:
            suggestions.extend([
                "🌍 **DNS Investigation**: Check for DNS tunneling patterns",
                "📊 **Query Analysis**: Review unusual domain patterns",
                "🔍 **Subdomain Enumeration**: Look for hidden services"
            ])
        
        # General analysis suggestions
        suggestions.extend([
            "📈 **Statistical Analysis**: Review traffic volume and timing patterns",
            "🔄 **Stream Reconstruction**: Examine reconstructed TCP sessions",
            "📦 **Protocol Distribution**: Analyze protocol usage patterns",
            "🎯 **Targeted Search**: Use custom regex for specific patterns",
            "📚 **Documentation**: Review analysis results for manual insights"
        ])
        
        # Add fallback mode indicator
        suggestions.append("💡 **Note**: These are algorithmic suggestions. Full AI analysis will resume when service is available.")
        
        return suggestions[:12]  # Limit to reasonable number
    
    def _parse_suggestions(self, response: str) -> List[str]:
        """Parse AI suggestions into actionable steps"""
        
        suggestions = []
        
        # Split by common list indicators
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.startswith('-') or line.startswith('*') or 
                        line.startswith('1.') or line.startswith('2.') or
                        re.match(r'^\d+\.', line)):
                # Clean up the line
                clean_line = re.sub(r'^[-*\d.]+\s*', '', line)
                if clean_line:
                    suggestions.append(clean_line)
        
        # If no structured list found, split by sentences
        if not suggestions:
            sentences = re.split(r'[.!?]+', response)
            suggestions = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        return suggestions[:10]  # Limit to top 10 suggestions

    def explain_advanced(self, advanced: Dict[str, Any]) -> Dict[str, Any]:
        """Explain advanced analyzer results via AI when available; fallback to concise summary.

        Returns a dict with 'advanced_explanation' text and optional 'compact' highlights.
        """
        try:
            adv = advanced or {}
            # Build a compact JSON snippet to keep tokens bounded and privacy-safe
            compact = {
                'ipv6': {
                    'total': (adv.get('ipv6') or {}).get('total_ipv6', 0),
                    'tunnels': len(((adv.get('ipv6_tunnels') or {}).get('detected_tunnels') or [])),
                },
                'blockchain': {
                    'mining_severity': ((adv.get('blockchain') or {}).get('mining') or {}).get('severity'),
                    'btc_tx': ((adv.get('blockchain') or {}).get('bitcoin') or {}).get('transactions', 0),
                    'eth_tx': ((adv.get('blockchain') or {}).get('ethereum') or {}).get('transactions', 0),
                },
                'malware': len(((adv.get('malware') or {}).get('suspicious_patterns') or [])),
                'dlp': len(((adv.get('dlp') or {}).get('results') or [])),
                'ml': {
                    'beacons': len(((adv.get('ml_anomalies') or {}).get('beacon_flows') or [])),
                    'outliers': len(((adv.get('ml_anomalies') or {}).get('outlier_flows') or [])),
                },
                'rf': {
                    'wifi_deauth': ((adv.get('rf') or {}).get('wifi') or {}).get('deauth_frames', 0)
                },
                'databases_present': [k for k, v in (adv.get('databases') or {}).items() if v],
            }

            if self.api_key:
                prompt = (
                    "You are a concise security analyst. Summarize these advanced analyzer results in 6-10 bullets, "
                    "prioritizing risk areas (mining, malware/C2, PII/DLP, beaconing, IPv6 tunnels). Provide: "
                    "(a) prioritized bullets with severity and why, (b) 3-5 safe next steps (filters/inspection), "
                    "(c) 2 brief watchpoints. Keep it actionable.\n" +
                    json.dumps(compact)[:4000]
                )
                resp = self._call_openrouter(prompt)
                if resp:
                    return {'advanced_explanation': resp, 'compact': compact}

            # Offline fallback concise summary
            lines: List[str] = []
            try:
                sev = str(compact['blockchain'].get('mining_severity') or 'n/a')
                lines.append(f"Mining: {sev}; BTC tx: {compact['blockchain']['btc_tx']}; ETH tx: {compact['blockchain']['eth_tx']}")
            except Exception:
                pass
            try:
                lines.append(f"Malware patterns: {compact['malware']}")
            except Exception:
                pass
            try:
                lines.append(f"PII hits: {compact['dlp']}")
            except Exception:
                pass
            try:
                lines.append(f"IPv6 total={compact['ipv6']['total']}, tunnels={compact['ipv6']['tunnels']}")
            except Exception:
                pass
            try:
                lines.append(f"ML beacons={compact['ml']['beacons']}, outliers={compact['ml']['outliers']}")
            except Exception:
                pass
            try:
                lines.append(f"Wi-Fi deauth={compact['rf']['wifi_deauth']}")
            except Exception:
                pass
            return {'advanced_explanation': "; ".join([s for s in lines if s]), 'compact': compact, 'mode': 'offline'}
        except Exception as e:
            return {'advanced_explanation_error': str(e)}

    # --- Grounded, offline summary of overall results (no API required) ---
def grounded_explain(results: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a grounded, deterministic summary strictly from the results dict.

    Returns a dict containing:
    - totals: key counts (packets, findings, decoded items, streams, sessions)
    - highlights: compact noteworthy items (top flags/JWT/alerts)
    - exports: booleans/paths for available exports or artifacts
    - next_steps: conservative, safe follow-ups the analyst can take

    This function does not require any API access and avoids any network calls.
    """
    try:
        res = results or {}

        findings = res.get('findings') or []
        decoded = res.get('decoded_data') or []
        streams = res.get('reconstructed_streams') or {}
        sessions = res.get('sessions') or {}
        ctf = (res.get('ctf_analysis') or {}).get('flag_candidates', []) or []
        jwt_tokens = res.get('jwt_tokens') or []
        adv = res.get('advanced') or {}

        totals = {
            'total_packets': int(res.get('total_packets') or 0),
            'findings': len(findings),
            'decoded_items': len(decoded),
            'streams': len(streams.keys()) if isinstance(streams, dict) else 0,
            'sessions': len(sessions.keys()) if isinstance(sessions, dict) else 0,
            'flag_candidates': len(ctf),
            'jwt_tokens': len(jwt_tokens),
        }

        # Build a few compact highlights with defensive slicing
        highlights: Dict[str, Any] = {}
        if ctf:
            top_flags = []
            try:
                sorted_flags = sorted(ctf, key=lambda x: x.get('confidence', 0), reverse=True)
                for c in sorted_flags[:3]:
                    top_flags.append({
                        'flag': c.get('flag',''),
                        'confidence': c.get('confidence', 0),
                        'pattern': c.get('pattern','')
                    })
            except Exception:
                pass
            if top_flags:
                highlights['top_flags'] = top_flags

        if jwt_tokens:
            try:
                j0 = jwt_tokens[0]
                highlights['jwt_sample'] = {
                    'alg': (j0.get('header') or {}).get('alg'),
                    'iss': (j0.get('claims') or {}).get('iss'),
                    'sub': (j0.get('claims') or {}).get('sub')
                }
            except Exception:
                pass

        # Surface a couple of notable findings
        try:
            notable = []
            for f in findings[:200]:
                disp = (f.get('display_type') or f.get('type') or '').upper()
                if any(k in disp for k in ['FLAG', 'JWT', 'SUSPICIOUS', 'MALWARE', 'DLP', 'MINING']):
                    notable.append({
                        'type': disp[:20],
                        'protocol': f.get('protocol', 'Unknown'),
                        'confidence': f.get('confidence', 0),
                        'sample': str(f.get('data',''))[:120]
                    })
                if len(notable) >= 5:
                    break
            if notable:
                highlights['notable_findings'] = notable
        except Exception:
            pass

        # Advanced analyzer quick status
        if adv:
            try:
                mining = ((adv.get('blockchain') or {}).get('mining') or {}).get('severity')
                pii = len(((adv.get('dlp') or {}).get('results') or []))
                ipv6_tunnels = len(((adv.get('ipv6_tunnels') or {}).get('detected_tunnels') or []))
                highlights['advanced_status'] = {
                    'mining_severity': mining,
                    'pii_hits': pii,
                    'ipv6_tunnels': ipv6_tunnels
                }
            except Exception:
                pass

        # Exports/artifacts availability
        exports = {
            'streams_zip': bool((res.get('exports') or {}).get('streams_zip')),
            'graph_json': bool((res.get('graph_exports') or {}).get('json')),
            'graph_graphml': bool((res.get('graph_exports') or {}).get('graphml')),
            'html_report': any(str(k).lower() == 'html' for k in (res.get('report_exports') or {}).keys()) if isinstance(res.get('report_exports'), dict) else False,
            'ioc_json': bool((res.get('ioc_exports') or {}).get('json')),
            'ioc_csv': bool((res.get('ioc_exports') or {}).get('csv')),
        }

        # Conservative next steps
        next_steps: List[str] = []
        try:
            if totals['flag_candidates'] > 0:
                next_steps.append('Verify top flag candidates and cross-check with decoded chains')
            if totals['decoded_items'] > 0:
                next_steps.append('Review decoded items; prioritize multi-step decoding chains')
            if adv and highlights.get('advanced_status', {}).get('mining_severity') in ('high','medium'):
                next_steps.append('Inspect potential crypto-mining indicators; filter STRATUM-like flows')
            if totals['jwt_tokens'] > 0:
                next_steps.append('Inspect JWTs for algorithm, issuer, subject, and expiry claims')
            if totals['streams'] > 0:
                next_steps.append('Open largest printable HTTP/TCP streams for manual review')
            if not next_steps:
                next_steps.append('Run targeted searches (e.g., base64, DNS long queries) and re-run decoders')
        except Exception:
            pass

        return {
            'totals': totals,
            'highlights': highlights,
            'exports': exports,
            'next_steps': next_steps
        }
    except Exception as e:
        return {'error': f'grounded_explain failed: {str(e)}'}

    # --- Aggregator for extended analyzers (optional entrypoint) ---
    def analyze_new_features(self, packets: Any) -> Dict[str, Any]:
        """Run extended analyzer suites and return a summarized dict.

        This mirrors the standalone runner but is callable from the agent when needed.
        Safe to call without AI; imports are local and failures are tolerated.
        """
        summary: Dict[str, Any] = {}
        try:
            # IPv6
            try:
                from analyzers.protocols.ipv6 import (
                    analyze_ipv6_traffic,
                    detect_ipv6_tunneling,
                    analyze_icmpv6_packets,
                )
                summary['ipv6'] = analyze_ipv6_traffic(packets)
                summary['ipv6_tunnels'] = detect_ipv6_tunneling(packets)
                summary['icmpv6'] = analyze_icmpv6_packets(packets)
            except Exception:
                pass

            # Industrial
            try:
                from analyzers.protocols.industrial import (
                    analyze_dnp3_traffic, analyze_s7comm_traffic, analyze_bacnet_traffic,
                    analyze_opcua_traffic, analyze_profinet_traffic,
                )
                summary['industrial'] = {
                    'dnp3': analyze_dnp3_traffic(packets),
                    's7comm': analyze_s7comm_traffic(packets),
                    'bacnet': analyze_bacnet_traffic(packets),
                    'opcua': analyze_opcua_traffic(packets),
                    'profinet': analyze_profinet_traffic(packets),
                }
            except Exception:
                pass

            # Blockchain
            try:
                from analyzers.blockchain import (
                    analyze_bitcoin_traffic, analyze_ethereum_traffic, detect_crypto_mining,
                )
                summary['blockchain'] = {
                    'bitcoin': analyze_bitcoin_traffic(packets),
                    'ethereum': analyze_ethereum_traffic(packets),
                    'mining': detect_crypto_mining(packets),
                }
            except Exception:
                pass

            # RF
            try:
                from analyzers.rf import (
                    analyze_wifi_traffic, analyze_ble_traffic, analyze_zigbee_traffic,
                )
                summary['rf'] = {
                    'wifi': analyze_wifi_traffic(packets),
                    'ble': analyze_ble_traffic(packets),
                    'zigbee': analyze_zigbee_traffic(packets),
                }
            except Exception:
                pass

            # ML
            try:
                from analyzers.ml.traffic_anomaly import analyze_ml_anomalies
                summary['ml_anomalies'] = analyze_ml_anomalies(packets)
            except Exception:
                pass

            # Databases
            try:
                from analyzers.protocols.database import (
                    analyze_mysql_traffic, analyze_postgres_traffic, analyze_mongodb_traffic,
                    analyze_redis_traffic, analyze_mssql_traffic,
                )
                summary['databases'] = {
                    'mysql': analyze_mysql_traffic(packets),
                    'postgres': analyze_postgres_traffic(packets),
                    'mongodb': analyze_mongodb_traffic(packets),
                    'redis': analyze_redis_traffic(packets),
                    'mssql': analyze_mssql_traffic(packets),
                }
            except Exception:
                pass

            # Malware
            try:
                from analyzers.malware import detect_malware_traffic
                summary['malware'] = detect_malware_traffic(packets)
            except Exception:
                pass

            # Temporal
            try:
                from analyzers.temporal.time_patterns import analyze_time_patterns
                summary['temporal'] = analyze_time_patterns(packets)
            except Exception:
                pass

            # Fingerprinting
            try:
                from analyzers.fingerprinting import analyze_os_fingerprints, analyze_service_fingerprints
                summary['fingerprinting'] = {
                    'os': analyze_os_fingerprints(packets),
                    'services': analyze_service_fingerprints(packets),
                }
            except Exception:
                pass

            # DLP
            try:
                from analyzers.dlp.pii_detector import analyze_dlp
                summary['dlp'] = analyze_dlp(packets)
            except Exception:
                pass
        except Exception:
            return summary
        return summary
    
    def _ensemble_analysis(self, findings: List[Dict], packet_data: str) -> Dict[str, Any]:
        """Multi-model ensemble analysis for higher accuracy"""
        
        ensemble_results = []
        analysis_prompt = self._create_analysis_prompt(findings, packet_data)
        
        for model in self.ensemble_models[:3]:  # Use top 3 models
            try:
                response = self._call_openrouter(analysis_prompt, model)
                if response:
                    parsed = self._parse_ai_response(response, findings)
                    ensemble_results.append({
                        'model': model,
                        'analysis': parsed,
                        'confidence': self._calculate_model_confidence(parsed)
                    })
            except Exception as e:
                print(f"Model {model} failed: {e}")
                continue
        
        # Combine results with consensus scoring
        return self._combine_ensemble_results(ensemble_results, findings)
    
    def _calculate_model_confidence(self, analysis: Dict) -> float:
        """Calculate confidence score for model analysis"""
        base_confidence = 70.0
        
        # Boost confidence if structured analysis found
        if analysis.get('ai_analysis', {}).get('enhanced_findings'):
            base_confidence += 15.0
        
        # Boost if specific recommendations provided
        if analysis.get('ai_analysis', {}).get('recommendations'):
            base_confidence += 10.0
        
        return min(base_confidence, 95.0)
    
    def _combine_ensemble_results(self, ensemble_results: List[Dict], original_findings: List[Dict]) -> Dict[str, Any]:
        """Combine multiple model results with consensus scoring"""
        
        if not ensemble_results:
            return {"error": "No ensemble results available"}
        
        # Find consensus among models
        consensus_analysis = {
            "ensemble_analysis": {
                "models_used": [r['model'].split('/')[-1] for r in ensemble_results],
                "consensus_confidence": sum(r['confidence'] for r in ensemble_results) / len(ensemble_results),
                "individual_results": ensemble_results
            },
            "enhanced_findings": self._merge_enhanced_findings(ensemble_results),
            "consensus_recommendations": self._extract_consensus_recommendations(ensemble_results),
            "original_findings": original_findings,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        return consensus_analysis
    
    def _merge_enhanced_findings(self, ensemble_results: List[Dict]) -> List[Dict]:
        """Merge enhanced findings from multiple models"""
        merged_findings = []
        
        for result in ensemble_results:
            analysis = result.get('analysis', {}).get('ai_analysis', {})
            if isinstance(analysis, dict) and 'enhanced_findings' in analysis:
                findings = analysis['enhanced_findings']
                if isinstance(findings, list):
                    merged_findings.extend(findings)
        
        return merged_findings
    
    def _extract_consensus_recommendations(self, ensemble_results: List[Dict]) -> List[str]:
        """Extract consensus recommendations from ensemble"""
        all_recommendations = []
        
        for result in ensemble_results:
            analysis = result.get('analysis', {}).get('ai_analysis', {})
            if isinstance(analysis, dict) and 'recommendations' in analysis:
                recs = analysis['recommendations']
                if isinstance(recs, list):
                    all_recommendations.extend(recs)
        
        # Return unique recommendations
        return list(set(all_recommendations))[:8]
    
    def enable_ensemble_mode(self, enabled: bool = True):
        """Enable or disable ensemble analysis"""
        self.use_ensemble = enabled
    
    def set_confidence_thresholds(self, min_confidence: int = 75, flag_threshold: int = 85, credential_threshold: int = 90):
        """Set confidence thresholds for different finding types"""
        self.min_confidence_threshold = min_confidence
        self.flag_confidence_threshold = flag_threshold
        self.credential_confidence_threshold = credential_threshold
    
    def _filter_low_confidence_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter out findings below confidence thresholds"""
        
        if not self.enable_strict_filtering:
            return findings
        
        filtered_findings = []
        
        for finding in findings:
            confidence = finding.get('confidence', 0)
            finding_type = finding.get('type', '').lower()
            
            # Determine appropriate threshold
            if 'flag' in finding_type:
                threshold = self.flag_confidence_threshold
            elif any(cred_type in finding_type for cred_type in ['credential', 'password', 'token', 'api_key']):
                threshold = self.credential_confidence_threshold
            else:
                threshold = self.min_confidence_threshold
            
            # Only include findings above threshold
            if confidence >= threshold:
                filtered_findings.append(finding)
            else:
                # Log filtered finding for debugging
                print(f"Filtered low-confidence finding: {finding_type} ({confidence}% < {threshold}%)")
        
        return filtered_findings
    
    def _validate_finding_quality(self, finding: Dict) -> bool:
        """Validate finding quality to prevent false positives - VERY STRICT"""
        
        data = str(finding.get('data', '')).strip()
        finding_type = finding.get('type', '').lower()
        
        # Basic validation rules
        if len(data) < 3:
            return False
        
        # STRICT Flag validation
        if 'flag' in finding_type or finding.get('flag_candidate'):
            flag_data = finding.get('flag_candidate', data)
            
            # Must match exact flag patterns - UPDATED to be more inclusive
            valid_flag_patterns = [
                r'^flag\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',
                r'^[A-Za-z0-9_]{2,15}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Generic CTF format like TJDGW2023{...}
                r'^CTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',
                r'^DUCTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',
                r'^picoCTF\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',
                r'^HTB\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',
                r'^TJDGW2023\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Specific for current flag
                r'^[A-Z]{2,10}[0-9]{2,4}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$'  # Pattern like XXXNNNN{...}
            ]
            
            if not any(re.match(pattern, flag_data) for pattern in valid_flag_patterns):
                return False
            
            # Reject common false positives
            false_positive_patterns = [
                r'windows.*build',
                r'version.*\d+',
                r'system.*info',
                r'64-bit.*windows',
                r'microsoft.*corp',
                r'copyright.*\d{4}',
                r'all.*rights.*reserved',
                r'program.*files',
                r'temp.*folder',
                r'user.*profile'
            ]
            
            for fp_pattern in false_positive_patterns:
                if re.search(fp_pattern, flag_data.lower()):
                    return False
            
            # Must have meaningful content (not just system info) - REDUCED requirement
            if len(flag_data.split('{')[1].split('}')[0]) < 4:
                return False
        
        # STRICT Credential validation
        if any(cred_type in finding_type for cred_type in ['credential', 'password']):
            # Must be in proper context (not just random strings)
            if (len(data) < 6 or data.isdigit() or 
                data.lower() in ['password', 'admin', 'user', 'test', 'guest', 'root'] or
                'windows' in data.lower() or 'microsoft' in data.lower()):
                return False
        
        # STRICT Token validation
        if 'token' in finding_type or 'api_key' in finding_type:
            # Must have proper token characteristics
            if (len(data) < 16 or not re.search(r'[A-Za-z0-9+/=]{16,}', data) or
                'windows' in data.lower() or 'system' in data.lower()):
                return False
        
        return True
    
    # Specialized AI Agents
    def flag_hunter_analysis(self, packet_data: str, ctf_context: Dict = None) -> Dict[str, Any]:
        """Specialized flag hunting agent with CTF context awareness"""
        
        # Prepare context-aware prompt
        context_info = ""
        if ctf_context:
            if ctf_context.get('description'):
                context_info += f"\n🎯 CHALLENGE DESCRIPTION: {ctf_context['description']}"
            if ctf_context.get('hints'):
                context_info += f"\n💡 HINTS/CLUES: {ctf_context['hints']}"
            if ctf_context.get('category'):
                context_info += f"\n📂 CATEGORY: {ctf_context['category']}"
        
        flag_prompt = f"""SPECIALIZED FLAG HUNTING MISSION

You are XBOW-FlagHunter, an elite AI specialized ONLY in finding CTF flags. Analyze this data:
{context_info}

PACKET DATA:
```
{packet_data[:3000]}
```

FLAG HUNTING OBJECTIVES - EXTREME PRECISION REQUIRED:

CRITICAL: ONLY report flags that are 100% CERTAIN to be real CTF flags!

VALIDATION CHECKLIST (ALL must be true):
- Must match EXACT format: flag{{content}}, CTF{{content}}, HTB{{content}}, etc.
- Content inside {{}} must be 8+ characters of meaningful data
- Must NOT contain: windows, microsoft, build, version, system, copyright
- Must NOT be system information, file paths, or software details
- Must have reasonable entropy (not repeated characters)
- Must make sense in CTF context

EXAMPLES OF WHAT TO REJECT:
- flag{{64-bit Windows -H build 17763}} - This is system info, NOT a flag!
- flag{{Microsoft Corporation}} - This is company info, NOT a flag!
- flag{{C:\\Program Files}} - This is a file path, NOT a flag!
- flag{{aaaaaaaaaa}} - This is low entropy, NOT a flag!

EXAMPLES OF VALID FLAGS:
- flag{{h1dd3n_1n_dns_qu3ry}}
- CTF{{b4s364_d3c0d3d_s3cr3t}}
- HTB{{n3tw0rk_st3g4n0gr4phy}}

RESPONSE FORMAT (JSON):
{{
  "flag_candidates": [
    {{
      "flag": "flag{{actual_flag_here}}",
      "confidence": 95,
      "location": "DNS query field",
      "encoding": "base64",
      "reasoning": "Found base64 encoded data in DNS query that decodes to valid flag format",
      "validation_steps": "1. Extracted base64 from DNS query 2. Decoded successfully 3. Verified flag format",
      "poc": "Use Wireshark filter: dns.qry.name contains 'ZmxhZ3t0ZXN0fQ==' then decode base64",
      "exploitation_steps": "1. Open PCAP in Wireshark 2. Apply DNS filter 3. Extract base64 4. Decode using: echo 'ZmxhZ3t0ZXN0fQ==' | base64 -d",
      "tools_needed": "Wireshark, base64 decoder, text editor"
    }}
  ]
}}

POC REQUIREMENTS:
- Exact Wireshark filters to find the data
- Complete decoding commands with examples
- Step-by-step manual verification process
- Alternative tools and methods

REMEMBER: It's better to find ZERO flags than ONE false positive!
"""
        
        try:
            response = self._call_openrouter(flag_prompt)
            return {"flag_hunter_analysis": response, "agent": "FlagHunter"}
        except Exception as e:
            return {"error": f"Flag hunter failed: {str(e)}"}
    
    def credential_harvester_analysis(self, packet_data: str, ctf_context: Dict = None) -> Dict[str, Any]:
        """Specialized credential extraction agent with CTF context"""
        
        # Prepare context-aware prompt
        context_info = ""
        if ctf_context:
            if ctf_context.get('description'):
                context_info += f"\n🎯 CHALLENGE CONTEXT: {ctf_context['description']}"
            if ctf_context.get('hints'):
                context_info += f"\n💡 HINTS: {ctf_context['hints']}"
        
        cred_prompt = f"""CREDENTIAL HARVESTING MISSION

You are XBOW-CredHarvester, specialized in extracting authentication data. Analyze:
{context_info}

PACKET DATA:
```
{packet_data[:3000]}
```

EXTRACTION TARGETS - HIGH PRECISION REQUIRED:
1. HTTP Basic Auth (Authorization: Basic) - MUST decode properly
2. Form data (username/password pairs) - MUST be in proper form context
3. API keys and tokens - MUST have proper format and length
4. JWT tokens and session IDs - MUST validate structure
5. Database connection strings - MUST have proper syntax
6. SSH keys and certificates - MUST have proper headers/format
7. OAuth tokens and refresh tokens - MUST be in OAuth context

STRICT VALIDATION RULES:
- Credentials must be in proper authentication context
- Random strings are NOT credentials
- Common words (admin, password, user) are NOT valid credentials
- Must have minimum length and complexity requirements
- Confidence must be 90%+ for credentials or don't report
- Validate format before reporting (JWT structure, key format, etc.)

RESPONSE: JSON with credentials array, each containing:
- type: credential type
- username: if applicable (must be realistic)
- password/token: the sensitive data (must pass validation)
- protocol: where found
- confidence: 90-100% only (lower = don't report)
- context: surrounding data proving it's real
- validation: proof this is a real credential
- poc: proof-of-concept for using these credentials
- exploitation_method: how to use these credentials in the CTF context
- verification_steps: steps to verify credential validity
- attack_scenarios: potential ways to use these credentials

CREDENTIAL POC REQUIREMENTS:
- Show how to use the credentials (login attempts, API calls, etc.)
- Provide exact curl commands or tools needed
- Include authentication flow details
- Show potential privilege escalation paths
- Give defensive recommendations

CRITICAL: False credential reports are dangerous. Only report confirmed credentials.
"""
        
        try:
            response = self._call_openrouter(cred_prompt)
            return {"credential_analysis": response, "agent": "CredHarvester"}
        except Exception as e:
            return {"error": f"Credential harvester failed: {str(e)}"}
    
    def protocol_analyzer_analysis(self, packet_data: str, ctf_context: Dict = None) -> Dict[str, Any]:
        """Specialized protocol analysis agent with CTF context"""
        
        # Prepare context-aware prompt
        context_info = ""
        if ctf_context:
            if ctf_context.get('description'):
                context_info += f"\n🎯 CHALLENGE CONTEXT: {ctf_context['description']}"
            if ctf_context.get('hints'):
                context_info += f"\n💡 HINTS: {ctf_context['hints']}"
            if ctf_context.get('category'):
                context_info += f"\n📂 FOCUS AREA: {ctf_context['category']}"
        
        protocol_prompt = f"""DEEP PROTOCOL ANALYSIS

You are XBOW-ProtocolExpert, specialized in network protocol security analysis:
{context_info}

PACKET DATA:
```
{packet_data[:3000]}
```

PROTOCOL ANALYSIS:
1. Identify all protocols present
2. Find protocol violations and anomalies
3. Detect covert channels and tunneling
4. Analyze timing patterns
5. Check for protocol downgrade attacks
6. Find data exfiltration techniques
7. Identify command & control patterns

RESPONSE: JSON with protocol_analysis containing:
- protocols_detected: list of protocols
- anomalies: unusual patterns found
- covert_channels: hidden communication methods
- security_issues: vulnerabilities detected
- recommendations: security improvements
- exploitation_pocs: proof-of-concept exploits for found vulnerabilities
- attack_vectors: detailed attack methodologies
- wireshark_filters: specific filters to isolate interesting traffic
- manual_analysis_steps: step-by-step manual verification process

PROTOCOL POC REQUIREMENTS:
- Provide Wireshark display filters for interesting packets
- Give specific packet analysis techniques
- Show how to extract hidden data from protocol fields
- Include network reconnaissance methods
- Provide exploitation frameworks/tools recommendations

Focus on security implications and actionable exploitation techniques.
"""
        
        try:
            response = self._call_openrouter(protocol_prompt)
            return {"protocol_analysis": response, "agent": "ProtocolExpert"}
        except Exception as e:
            return {"error": f"Protocol analyzer failed: {str(e)}"}
    
    def behavioral_analysis(self, packet_data: str, context: str = "", ctf_context: Dict = None) -> Dict[str, Any]:
        """Behavioral analysis for anomaly detection with CTF context"""
        
        # Prepare context-aware prompt
        context_info = context
        if ctf_context:
            if ctf_context.get('description'):
                context_info += f"\n🎯 CTF CHALLENGE: {ctf_context['description']}"
            if ctf_context.get('hints'):
                context_info += f"\n💡 CLUES: {ctf_context['hints']}"
        
        behavior_prompt = f"""
🧠 BEHAVIORAL ANALYSIS ENGINE

Analyze network behavior patterns for anomalies and threats:

PACKET DATA:
```
{packet_data[:3000]}
```

CONTEXT: {context_info}

🎯 BEHAVIORAL ANALYSIS:
1. User behavior patterns (login times, access patterns)
2. Network flow anomalies (unusual destinations, protocols)
3. Data transfer patterns (size, frequency, timing)
4. Command execution sequences
5. Lateral movement indicators
6. Data exfiltration patterns
7. Attack progression analysis

RESPONSE: JSON with behavioral_analysis:
- anomalies_detected: list of unusual patterns
- risk_score: 0-100 overall risk assessment
- attack_indicators: signs of malicious activity
- user_behavior: analysis of user patterns
- recommendations: suggested actions
- timeline_analysis: chronological breakdown of suspicious activities
- correlation_pocs: proof-of-concept for correlating suspicious events
- investigation_steps: detailed steps for manual investigation
- forensic_artifacts: key artifacts for further analysis

🔧 BEHAVIORAL POC REQUIREMENTS:
- Provide timeline reconstruction techniques
- Show correlation analysis methods
- Give statistical analysis approaches for anomaly detection
- Include behavioral baseline establishment methods
- Provide incident response procedures

Identify subtle behavioral anomalies and provide actionable investigation paths.
"""
        
        try:
            response = self._call_openrouter(behavior_prompt)
            return {"behavioral_analysis": response, "agent": "BehaviorAnalyzer"}
        except Exception as e:
            return {"error": f"Behavioral analysis failed: {str(e)}"}
    
    def intelligent_false_positive_reduction(self, findings: List[Dict], packet_context: str = "") -> List[Dict]:
        """Option 5: Intelligent False Positive Reduction with CTF context awareness"""
        
        ctf_aware_prompt = f"""
🧠 INTELLIGENT FALSE POSITIVE ANALYZER

Analyze these findings to eliminate false positives using CTF context awareness:

FINDINGS TO VALIDATE:
{json.dumps(findings[:10], indent=2)}

PACKET CONTEXT:
```
{packet_context[:2000]}
```

🎯 FALSE POSITIVE DETECTION CRITERIA:

1. CTF CONTEXT VALIDATION:
   - Does this make sense in a CTF challenge?
   - Is this typical CTF content vs system noise?
   - Does complexity match expected challenge level?

2. PATTERN LEGITIMACY:
   - Real flags vs system artifacts
   - Intentional vs accidental patterns
   - Challenge-relevant vs OS/software noise

3. CONFIDENCE SCORING:
   - Statistical analysis of pattern entropy
   - Context relevance assessment
   - Cross-validation with known CTF techniques

4. CONTEXTUAL FILTERS:
   - Remove Windows system artifacts
   - Filter out software version strings
   - Eliminate network stack information
   - Remove compiler/build artifacts

RESPONSE FORMAT (JSON):
{{
  "validated_findings": [
    {{
      "original_finding": {{finding_data}},
      "validation_result": "VALID" | "FALSE_POSITIVE" | "UNCERTAIN",
      "confidence_adjustment": -20 to +20,
      "reasoning": "Detailed explanation",
      "ctf_relevance_score": 0-100,
      "false_positive_indicators": ["list of FP signals"],
      "validation_criteria_met": ["list of validation checks passed"]
    }}
  ],
  "filtering_summary": {{
    "original_count": 0,
    "validated_count": 0,
    "false_positive_count": 0,
    "uncertainty_count": 0
  }}
}}

⚠️ CRITICAL: Better to be conservative - reject suspicious findings rather than include false positives!
"""
        
        try:
            response = self._call_openrouter(ctf_aware_prompt)
            if response:
                parsed_response = self._parse_fp_reduction_response(response, findings)
                return parsed_response.get('validated_findings', findings)
            return findings
        except Exception as e:
            return findings  # Return original findings if analysis fails
    
    def multi_protocol_flag_reconstruction(self, packet_data: str, findings: List[Dict]) -> Dict[str, Any]:
        """Option 6: Multi-Protocol Flag Reconstruction for flags split across packets"""
        
        reconstruction_prompt = f"""
🔗 MULTI-PROTOCOL FLAG RECONSTRUCTION SYSTEM

Analyze packet data to reconstruct flags that may be split across multiple protocols or packets:

PACKET DATA:
```
{packet_data[:4000]}
```

CURRENT FINDINGS:
{json.dumps(findings[:5], indent=2)}

🎯 RECONSTRUCTION OBJECTIVES:

1. PACKET FRAGMENT ANALYSIS:
   - Identify partial flag fragments across different packets
   - Analyze TCP sequence numbers for proper ordering
   - Look for flags split across protocol boundaries

2. MULTI-PROTOCOL CORRELATION:
   - HTTP headers + DNS queries
   - TCP payload + UDP data
   - ICMP data + regular traffic
   - Email + web traffic combinations

3. RECONSTRUCTION TECHNIQUES:
   - TCP stream reassembly for fragmented flags
   - DNS query concatenation across multiple requests
   - HTTP header combination across requests/responses
   - Base64 data scattered across protocols

4. ENCODING CHAIN RECONSTRUCTION:
   - Part 1 in HTTP, Part 2 in DNS, combine and decode
   - Multi-layer encoding across different protocols
   - Time-based or sequence-based flag assembly

RESPONSE FORMAT (JSON):
{{
  "reconstructed_flags": [
    {{
      "flag_candidate": "complete_reconstructed_flag",
      "confidence": 85,
      "reconstruction_method": "TCP stream reassembly",
      "source_packets": ["packet1", "packet2", "packet3"],
      "protocols_involved": ["HTTP", "DNS"],
      "reconstruction_steps": ["step by step process"],
      "validation_poc": "Wireshark: tcp.stream eq 0 && http",
      "manual_verification": "detailed manual process",
      "encoding_chain": "base64 -> hex -> rot13"
    }}
  ],
  "fragment_analysis": {{
    "fragments_found": 0,
    "correlation_pairs": [],
    "reconstruction_confidence": 0
  }}
}}

🔧 RECONSTRUCTION POC REQUIREMENTS:
- Exact Wireshark filters to isolate relevant packets
- Step-by-step reassembly commands
- Tools needed for reconstruction (tcpdump, tshark, etc.)
- Validation methods for reconstructed flags
"""
        
        try:
            response = self._call_openrouter(reconstruction_prompt)
            return {"reconstruction_analysis": response, "agent": "FlagReconstructor"}
        except Exception as e:
            return {"error": f"Flag reconstruction failed: {str(e)}"}
    
    def behavioral_pattern_analysis(self, packet_data: str, timeline_data: List[Dict] = None) -> Dict[str, Any]:
        """Option 7: Behavioral Pattern Analysis for temporal and frequency patterns"""
        
        timeline_info = ""
        if timeline_data:
            timeline_info = f"\nTIMELINE DATA:\n{json.dumps(timeline_data[:10], indent=2)}"
        
        pattern_prompt = f"""
📊 BEHAVIORAL PATTERN ANALYSIS ENGINE

Analyze temporal and frequency patterns for advanced behavioral insights:

PACKET DATA:
```
{packet_data[:3000]}
```
{timeline_info}

🎯 PATTERN ANALYSIS OBJECTIVES:

1. TEMPORAL PATTERNS:
   - Communication timing patterns
   - Periodic behavior detection
   - Anomalous timing deviations
   - Day/hour based activity patterns

2. FREQUENCY ANALYSIS:
   - Request frequency patterns
   - Protocol usage frequency
   - Data size frequency distributions
   - Connection establishment patterns

3. BEHAVIORAL SIGNATURES:
   - User vs automated behavior
   - Attack pattern recognition
   - Data exfiltration patterns
   - Command and control patterns

4. ADVANCED ANALYTICS:
   - Statistical anomaly detection
   - Machine learning pattern recognition
   - Entropy analysis of communications
   - Clustering of similar behaviors

RESPONSE FORMAT (JSON):
{{
  "temporal_patterns": {{
    "periodic_behavior": [],
    "timing_anomalies": [],
    "peak_activity_times": [],
    "communication_rhythm": {{}}
  }},
  "frequency_analysis": {{
    "request_frequencies": {{}},
    "protocol_distribution": {{}},
    "size_patterns": {{}},
    "connection_patterns": {{}}
  }},
  "behavioral_insights": {{
    "user_behavior_score": 0,
    "automation_indicators": [],
    "attack_signatures": [],
    "risk_assessment": {{}}
  }},
  "recommendations": [
    "Based on pattern analysis, investigate X",
    "Unusual frequency detected in Y protocol"
  ]
}}

🔧 PATTERN ANALYSIS POC:
- Statistical analysis commands and tools
- Timeline visualization techniques
- Frequency analysis methods
- Behavioral baseline establishment
"""
        
        try:
            response = self._call_openrouter(pattern_prompt)
            return {"behavioral_patterns": response, "agent": "PatternAnalyzer"}
        except Exception as e:
            return {"error": f"Behavioral pattern analysis failed: {str(e)}"}
    
    def generate_attack_narrative(self, findings: List[Dict], packet_data: str, context: str = "") -> Dict[str, Any]:
        """Option 8: AI-Generated Attack Narratives for human-readable stories"""
        
        narrative_prompt = f"""
📖 ATTACK NARRATIVE GENERATOR

Create a human-readable story that explains the attack or CTF challenge based on the evidence:

FINDINGS SUMMARY:
{json.dumps(findings[:8], indent=2)}

PACKET EVIDENCE:
```
{packet_data[:2000]}
```

CONTEXT: {context}

🎯 NARRATIVE OBJECTIVES:

1. STORYTELLING ELEMENTS:
   - Clear beginning, middle, and end
   - Logical progression of events
   - Technical details in accessible language
   - Timeline of attack progression

2. EVIDENCE CORRELATION:
   - Connect findings to tell cohesive story
   - Explain how evidence supports conclusions
   - Identify gaps in the narrative
   - Suggest additional evidence to look for

3. ATTACK RECONSTRUCTION:
   - Attacker motivations and goals
   - Methods and techniques used
   - Defensive failures and successes
   - Impact assessment

4. AUDIENCE ADAPTATION:
   - Technical narrative for security professionals
   - Executive summary for management
   - Educational content for learning

RESPONSE FORMAT (JSON):
{{
  "executive_summary": "High-level overview for management",
  "technical_narrative": "Detailed technical story for security teams",
  "timeline_story": "Chronological sequence of events",
  "attack_methodology": "Explanation of techniques used",
  "evidence_correlation": "How findings support the narrative",
  "impact_assessment": "What was achieved or attempted",
  "lessons_learned": "Key takeaways and improvements",
  "further_investigation": "Recommended next steps",
  "narrative_confidence": 85,
  "story_completeness": "high|medium|low"
}}

🔧 NARRATIVE REQUIREMENTS:
- Make technical concepts accessible
- Use active voice and clear language
- Include specific evidence references
- Provide actionable insights
- Balance technical accuracy with readability
"""
        
        try:
            response = self._call_openrouter(narrative_prompt)
            return {"attack_narrative": response, "agent": "StoryTeller"}
        except Exception as e:
            return {"error": f"Attack narrative generation failed: {str(e)}"}
    
    def interactive_ai_assistant(self, user_question: str, analysis_context: Dict, conversation_history: List[Dict] = None) -> Dict[str, Any]:
        """Option 9: Interactive AI Assistant with chat-based guidance"""
        
        history_context = ""
        if conversation_history:
            history_context = f"\nCONVERSATION HISTORY:\n{json.dumps(conversation_history[-5:], indent=2)}"
        
        assistant_prompt = f"""
🤖 INTERACTIVE AI ASSISTANT - XBOW CONSULTANT

You are an expert CTF and cybersecurity consultant providing personalized guidance.

USER QUESTION: {user_question}

CURRENT ANALYSIS CONTEXT:
{json.dumps(analysis_context, indent=2)}
{history_context}

🎯 ASSISTANT OBJECTIVES:

1. PERSONALIZED GUIDANCE:
   - Understand user's skill level and adapt responses
   - Provide step-by-step instructions appropriate to experience
   - Offer multiple solution approaches
   - Encourage learning and skill development

2. CONTEXTUAL AWARENESS:
   - Reference current analysis findings
   - Build on previous conversation
   - Maintain conversation continuity
   - Provide relevant follow-up questions

3. PRACTICAL ASSISTANCE:
   - Give specific commands and tools
   - Provide exact Wireshark filters
   - Suggest debugging approaches
   - Offer verification methods

4. EDUCATIONAL VALUE:
   - Explain reasoning behind suggestions
   - Teach underlying concepts
   - Reference learning resources
   - Encourage best practices

RESPONSE FORMAT (JSON):
{{
  "direct_answer": "Immediate response to user question",
  "step_by_step_guide": [
    "Step 1: Specific action",
    "Step 2: Next action"
  ],
  "technical_details": "Deep technical explanation",
  "tools_and_commands": [
    "wireshark: specific filter",
    "bash: exact command"
  ],
  "learning_resources": [
    "Link or reference to learn more"
  ],
  "follow_up_questions": [
    "Would you like me to explain X?",
    "Should we explore Y next?"
  ],
  "confidence_level": 90,
  "difficulty_assessment": "beginner|intermediate|advanced",
  "estimated_time": "Expected time to complete suggestion"
}}

🔧 ASSISTANT REQUIREMENTS:
- Be encouraging and supportive
- Provide practical, actionable advice
- Maintain professional but friendly tone
- Adapt complexity to user needs
- Always include verification steps
"""
        
        try:
            response = self._call_openrouter(assistant_prompt)
            return {"assistant_response": response, "agent": "InteractiveAssistant"}
        except Exception as e:
            return {"error": f"Interactive assistant failed: {str(e)}"}
    
    def predictive_analysis(self, current_findings: List[Dict], attack_context: Dict, packet_data: str) -> Dict[str, Any]:
        """Option 11: Predictive Analysis for next attack step predictions"""
        
        prediction_prompt = f"""
🔮 PREDICTIVE ATTACK ANALYSIS ENGINE

Predict likely next attack steps based on current evidence and attack patterns:

CURRENT FINDINGS:
{json.dumps(current_findings[:10], indent=2)}

ATTACK CONTEXT:
{json.dumps(attack_context, indent=2)}

PACKET DATA:
```
{packet_data[:3000]}
```

🎯 PREDICTION OBJECTIVES:

1. ATTACK PROGRESSION ANALYSIS:
   - Identify current attack phase
   - Map to known attack frameworks (MITRE ATT&CK)
   - Predict logical next steps
   - Assess attack sophistication level

2. THREAT MODELING:
   - Attacker capabilities assessment
   - Target asset identification
   - Potential impact scenarios
   - Risk probability calculations

3. DEFENSIVE PREDICTIONS:
   - Likely detection evasion attempts
   - Expected lateral movement patterns
   - Probable persistence mechanisms
   - Data exfiltration methods

4. TIMELINE FORECASTING:
   - Expected attack duration
   - Critical decision points
   - Time-sensitive defensive windows
   - Escalation triggers

RESPONSE FORMAT (JSON):
{{
  "attack_phase_assessment": {{
    "current_phase": "reconnaissance|initial_access|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact",
    "phase_confidence": 85,
    "mitre_techniques": ["T1005", "T1083"]
  }},
  "next_step_predictions": [
    {{
      "predicted_action": "Lateral movement to domain controller",
      "probability": 75,
      "timeframe": "within 2-4 hours",
      "indicators_to_watch": ["SMB connections", "Admin share access"],
      "defensive_recommendations": ["Monitor privileged account usage"]
    }}
  ],
  "risk_assessment": {{
    "overall_risk_score": 85,
    "potential_impact": "high|medium|low",
    "attack_sophistication": "advanced|intermediate|basic",
    "time_criticality": "immediate|urgent|moderate|low"
  }},
  "defensive_priorities": [
    "Immediate action 1",
    "Short-term action 2",
    "Long-term action 3"
  ],
  "monitoring_recommendations": [
    "Watch for specific network patterns",
    "Monitor specific system events"
  ]
}}

🔧 PREDICTION REQUIREMENTS:
- Base predictions on solid evidence
- Provide confidence levels for all predictions
- Include actionable defensive recommendations
- Reference industry-standard frameworks
- Consider multiple attack scenarios
"""
        
        try:
            response = self._call_openrouter(prediction_prompt)
            return {"predictive_analysis": response, "agent": "PredictiveAnalyzer"}
        except Exception as e:
            return {"error": f"Predictive analysis failed: {str(e)}"}
    
    def _parse_fp_reduction_response(self, response: str, original_findings: List[Dict]) -> Dict[str, Any]:
        """Parse false positive reduction response"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return parsed
        except Exception as e:
            print(f"Failed to parse FP reduction response: {e}")
        
        # Fallback: return original findings
        return {
            "validated_findings": original_findings,
            "filtering_summary": {
                "original_count": len(original_findings),
                "validated_count": len(original_findings),
                "false_positive_count": 0,
                "uncertainty_count": 0
            }
        }

    def comprehensive_ai_analysis(self, packet_data: str, findings: List[Dict], ctf_context: Dict = None, user_question: str = None, conversation_history: List[Dict] = None) -> Dict[str, Any]:
        """Comprehensive AI analysis using all implemented improvement features"""
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "analysis_components": [],
            "overall_confidence": 0,
            "recommendations": [],
            "errors": []
        }
        
        try:
            # 1. Multi-Agent Specialized Analysis (Option 1)
            specialist_results = {}
            for specialist_name, config in self.specialist_modes.items():
                try:
                    # Use appropriate specialist based on findings
                    finding_types = [f.get('type', '').lower() for f in findings]
                    if any(focus_area in str(finding_types).lower() for focus_area in config['focus']):
                        if 'steganography' in config['focus']:
                            specialist_results[specialist_name] = self.flag_hunter_analysis(packet_data, ctf_context)
                        elif 'web' in config['focus']:
                            specialist_results[specialist_name] = self.protocol_analyzer_analysis(packet_data, ctf_context)
                        elif 'credential' in config['focus']:
                            specialist_results[specialist_name] = self.credential_harvester_analysis(packet_data, ctf_context)
                        else:
                            specialist_results[specialist_name] = self.behavioral_analysis(packet_data, "", ctf_context)
                        results["analysis_components"].append(f"Specialist: {specialist_name}")
                except Exception as e:
                    results["errors"].append(f"Specialist {specialist_name} failed: {str(e)}")
            
            results["specialist_analysis"] = specialist_results
            
            # 2. Progressive Hint System (Option 2)
            try:
                progress_percentage = min(len(findings) * 20, 100)  # Estimate progress
                challenge_context = ctf_context.get('description', '') if ctf_context else ''
                progressive_hints = self.generate_progressive_hints(findings, progress_percentage, challenge_context)
                results["progressive_hints"] = progressive_hints
                results["analysis_components"].append("Progressive Hints Generated")
            except Exception as e:
                results["errors"].append(f"Progressive hints failed: {str(e)}")
            
            # 5. Intelligent False Positive Reduction (Option 5)
            try:
                validated_findings = self.intelligent_false_positive_reduction(findings, packet_data)
                results["validated_findings"] = validated_findings
                results["analysis_components"].append("False Positive Reduction")
            except Exception as e:
                results["errors"].append(f"False positive reduction failed: {str(e)}")
                results["validated_findings"] = findings  # Fallback to original
            
            # 6. Multi-Protocol Flag Reconstruction (Option 6)
            try:
                reconstruction_analysis = self.multi_protocol_flag_reconstruction(packet_data, findings)
                results["flag_reconstruction"] = reconstruction_analysis
                results["analysis_components"].append("Flag Reconstruction")
            except Exception as e:
                results["errors"].append(f"Flag reconstruction failed: {str(e)}")
            
            # 7. Behavioral Pattern Analysis (Option 7)
            try:
                # Create timeline data from findings
                timeline_data = [{
                    "timestamp": datetime.now().isoformat(),
                    "event": f.get('type', 'unknown'),
                    "data": str(f.get('data', ''))[:100]
                } for f in findings[:10]]
                
                behavioral_patterns = self.behavioral_pattern_analysis(packet_data, timeline_data)
                results["behavioral_patterns"] = behavioral_patterns
                results["analysis_components"].append("Behavioral Pattern Analysis")
            except Exception as e:
                results["errors"].append(f"Behavioral pattern analysis failed: {str(e)}")
            
            # 8. AI-Generated Attack Narratives (Option 8)
            try:
                context_str = ctf_context.get('description', '') if ctf_context else 'Network traffic analysis'
                attack_narrative = self.generate_attack_narrative(findings, packet_data, context_str)
                results["attack_narrative"] = attack_narrative
                results["analysis_components"].append("Attack Narrative Generated")
            except Exception as e:
                results["errors"].append(f"Attack narrative generation failed: {str(e)}")
            
            # 9. Interactive AI Assistant (Option 9)
            if user_question:
                try:
                    analysis_context = {
                        "findings_count": len(findings),
                        "packet_data_length": len(packet_data),
                        "ctf_context": ctf_context,
                        "components_analyzed": results["analysis_components"]
                    }
                    assistant_response = self.interactive_ai_assistant(user_question, analysis_context, conversation_history)
                    results["assistant_response"] = assistant_response
                    results["analysis_components"].append("Interactive Assistant Response")
                except Exception as e:
                    results["errors"].append(f"Interactive assistant failed: {str(e)}")
            
            # 11. Predictive Analysis (Option 11)
            try:
                attack_context = {
                    "findings_count": len(findings),
                    "protocols_detected": list(set(f.get('protocol', 'unknown') for f in findings)),
                    "challenge_type": ctf_context.get('category', 'unknown') if ctf_context else 'unknown'
                }
                predictive_analysis = self.predictive_analysis(findings, attack_context, packet_data)
                results["predictive_analysis"] = predictive_analysis
                results["analysis_components"].append("Predictive Analysis")
            except Exception as e:
                results["errors"].append(f"Predictive analysis failed: {str(e)}")
            
            # Calculate overall confidence
            component_count = len(results["analysis_components"])
            error_count = len(results["errors"])
            
            if component_count > 0:
                success_rate = (component_count - error_count) / component_count
                results["overall_confidence"] = min(int(success_rate * 100), 95)
            
            # Generate comprehensive recommendations
            recommendations = [
                f"🏆 Completed {component_count} AI analysis components",
                f"📊 Analysis confidence: {results['overall_confidence']}%"
            ]
            
            if results.get("validated_findings"):
                recommendations.append(f"✅ {len(results['validated_findings'])} findings validated after false positive reduction")
            
            if results.get("progressive_hints"):
                recommendations.append(f"💡 {len(results['progressive_hints'])} progressive hints generated")
            
            if error_count > 0:
                recommendations.append(f"⚠️ {error_count} components had errors - check error details")
            
            results["recommendations"] = recommendations
            
            # Add comprehensive analysis metadata for enhanced JSON response
            results["analysis_metadata"] = {
                "total_components_executed": component_count,
                "successful_components": component_count - error_count,
                "failed_components": error_count,
                "success_rate_percentage": round((component_count - error_count) / component_count * 100, 2) if component_count > 0 else 0,
                "analysis_duration_estimate": "comprehensive_mode",
                "api_calls_made": component_count,
                "model_used": self.model,
                "ensemble_enabled": self.use_ensemble,
                "ctf_context_provided": ctf_context is not None,
                "user_interaction_requested": user_question is not None,
                "packet_data_size_chars": len(packet_data),
                "original_findings_count": len(findings),
                "analysis_scope": "comprehensive_with_all_improvements"
            }
            
            # Add detailed component summary
            results["component_summary"] = {
                "executed_components": results["analysis_components"],
                "component_details": {
                    "multi_agent_specialists": len(specialist_results) if 'specialist_analysis' in results else 0,
                    "progressive_hints_generated": len(results.get("progressive_hints", [])),
                    "validated_findings_count": len(results.get("validated_findings", [])),
                    "reconstructed_flags_found": len(results.get("flag_reconstruction", {}).get("reconstructed_flags", [])),
                    "behavioral_patterns_detected": len(results.get("behavioral_patterns", {}).get("patterns", [])),
                    "narrative_sections_generated": len(results.get("attack_narrative", {}).get("sections", [])),
                    "predictive_scenarios_analyzed": len(results.get("predictive_analysis", {}).get("scenarios", []))
                },
                "error_summary": {
                    "total_errors": error_count,
                    "error_details": results["errors"],
                    "critical_failures": [err for err in results["errors"] if "failed" in err.lower()],
                    "warnings": [err for err in results["errors"] if "warning" in err.lower()]
                }
            }
            
            # Add quality metrics
            results["quality_metrics"] = {
                "confidence_distribution": {
                    "high_confidence_findings": len([f for f in results.get("validated_findings", []) if f.get("confidence", 0) >= 85]),
                    "medium_confidence_findings": len([f for f in results.get("validated_findings", []) if 70 <= f.get("confidence", 0) < 85]),
                    "low_confidence_findings": len([f for f in results.get("validated_findings", []) if f.get("confidence", 0) < 70])
                },
                "analysis_completeness": {
                    "components_attempted": len(results["analysis_components"]) + error_count,
                    "components_successful": len(results["analysis_components"]),
                    "completeness_percentage": round(len(results["analysis_components"]) / (len(results["analysis_components"]) + error_count) * 100, 2) if (len(results["analysis_components"]) + error_count) > 0 else 0
                },
                "findings_quality": {
                    "false_positive_reduction_applied": "validated_findings" in results,
                    "multi_protocol_analysis_performed": "flag_reconstruction" in results,
                    "behavioral_analysis_completed": "behavioral_patterns" in results,
                    "specialist_analysis_coverage": len(specialist_results)
                }
            }
            
        except Exception as e:
            results["errors"].append(f"Comprehensive analysis failed: {str(e)}")
            results["overall_confidence"] = 0
        
        return results
    
    def get_available_ai_improvements(self) -> Dict[str, Any]:
        """Get information about available AI improvement features"""
        
        improvements = {
            "1": {
                "name": "Multi-Agent Specialized Analysis",
                "description": "Specialized AI agents for different CTF categories",
                "status": "implemented",
                "specialists": list(self.specialist_modes.keys())
            },
            "2": {
                "name": "Progressive Hint System",
                "description": "Context-aware hints based on analysis progress",
                "status": "implemented",
                "features": ["Beginner hints", "Intermediate guidance", "Expert techniques", "Context-specific advice"]
            },
            "5": {
                "name": "Intelligent False Positive Reduction",
                "description": "CTF-aware filtering to eliminate false positives",
                "status": "implemented",
                "features": ["CTF context validation", "Pattern legitimacy assessment", "Confidence scoring"]
            },
            "6": {
                "name": "Multi-Protocol Flag Reconstruction",
                "description": "Reconstruct flags split across multiple packets/protocols",
                "status": "implemented",
                "features": ["TCP stream reassembly", "DNS query correlation", "HTTP header combination"]
            },
            "7": {
                "name": "Behavioral Pattern Analysis",
                "description": "Temporal and frequency pattern analysis",
                "status": "implemented",
                "features": ["Timing analysis", "Frequency patterns", "Behavioral signatures"]
            },
            "8": {
                "name": "AI-Generated Attack Narratives",
                "description": "Human-readable stories explaining the attack",
                "status": "implemented",
                "features": ["Technical narratives", "Executive summaries", "Timeline stories"]
            },
            "9": {
                "name": "Interactive AI Assistant",
                "description": "Chat-based guidance and consultation",
                "status": "implemented",
                "features": ["Personalized guidance", "Step-by-step instructions", "Contextual awareness"]
            },
            "11": {
                "name": "Predictive Analysis",
                "description": "Predict next attack steps and recommend defenses",
                "status": "implemented",
                "features": ["Attack progression prediction", "Risk assessment", "Defensive recommendations"]
            }
        }
        
        return {
            "total_improvements": len(improvements),
            "implemented_count": len([i for i in improvements.values() if i["status"] == "implemented"]),
            "improvements": improvements,
            "usage_example": "Use comprehensive_ai_analysis() to access all features simultaneously"
        }

class AgentConfig:
    """Configuration management for the AI agent"""
    
    @staticmethod
    def load_config() -> Dict[str, Any]:
        """Load agent configuration"""
        try:
            with open('.flagsniff_config.json', 'r') as f:
                return json.load(f)
        except:
            return {}
    
    @staticmethod
    def save_config(config: Dict[str, Any]):
        """Save agent configuration"""
        try:
            with open('.flagsniff_config.json', 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Failed to save config: {e}")
    
    @staticmethod
    def get_api_key() -> Optional[str]:
        """Get API key from config or environment"""
        import os
        
        config = AgentConfig.load_config()
        # Check for both LongCat and OpenRouter keys for backward compatibility
        api_key = config.get('longcat_api_key') or config.get('openrouter_api_key')
        
        if not api_key:
            api_key = os.getenv('LONGCAT_API_KEY') or os.getenv('OPENROUTER_API_KEY')
        
        return api_key

def create_agent(api_key: str = None, model: str = "LongCat-Flash-Chat") -> Optional[FlagSniffAgent]:
    """Factory function to create AI agent with enhanced error handling
    
    Following enhanced AI analysis error handling guidelines:
    - Pre-analysis dependency validation
    - Phase-by-phase initialization with specific error catching
    - Intelligent fallback modes for graceful degradation
    """
    
    # Phase 1: Pre-analysis dependency validation
    try:
        if not api_key:
            api_key = AgentConfig.get_api_key()
        
        if not api_key:
            # No API key available - this is expected behavior, not an error
            return None
        
        # Validate API key format
        if not isinstance(api_key, str) or len(api_key) < 10:
            print("⚠️ Warning: API key appears to be invalid format")
            return None
            
        # Support LongCat (ak_, lc-) and OpenRouter key formats
        if not (api_key.startswith('ak_') or api_key.startswith('lc-') or api_key.startswith('sk-or-v1-')):
            print("⚠️ Warning: API key should start with 'ak_' or 'lc-' (LongCat) or 'sk-or-v1-' (OpenRouter)")
    
    except Exception as e:
        print(f"❌ Dependency validation failed: {str(e)[:100]}...")
        return None
    
    # Phase 2: Agent initialization with error catching
    try:
        # Get endpoint from config if available
        config = AgentConfig.load_config()
        base_url = config.get('api_endpoint', 'https://api.longcat.chat/openai/v1/chat/completions')
        # Pre-resolve API host to avoid repeated failures when DNS is unavailable
        try:
            parsed = urlparse(base_url)
            host = parsed.hostname
            if not host:
                print(f"❌ Invalid API endpoint: {base_url}")
                return None
            socket.gethostbyname(host)
        except Exception as dns_err:
            print(f"🌐 Skipping AI: endpoint resolution failed for {base_url} ({dns_err})")
            return None
        
        agent = FlagSniffAgent(api_key, model, base_url=base_url)
        
        # Phase 3: Validation test (optional lightweight test)
        # This could be expanded to include a simple API test if needed
        if hasattr(agent, 'api_key') and agent.api_key:
            return agent
        else:
            print("⚠️ Warning: Agent created but API key not properly set")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error during agent creation: {str(e)[:100]}...")
        return None
    except ValueError as e:
        print(f"📊 Configuration error: {str(e)[:100]}...")
        return None
    except Exception as e:
        print(f"❌ Unexpected error during agent creation: {str(e)[:100]}...")
        return None