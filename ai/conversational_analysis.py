"""
Conversational Analysis Interface
Enables interactive chat-based analysis with context preservation
"""

import json
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
import re

@dataclass
class ConversationMessage:
    """Represents a single message in the conversation"""
    message_id: str
    timestamp: float
    role: str  # 'user' or 'assistant'
    content: str
    context_used: Dict[str, Any] = field(default_factory=dict)
    analysis_type: Optional[str] = None
    confidence: Optional[float] = None

@dataclass
class AnalysisContext:
    """Maintains analysis context for conversation"""
    pcap_file: Optional[str] = None
    findings: List[Dict] = field(default_factory=list)
    packet_data: List[Dict] = field(default_factory=list)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    current_focus: Optional[str] = None
    user_preferences: Dict[str, Any] = field(default_factory=dict)

class ConversationMemory:
    """Manages conversation history and context"""
    
    def __init__(self, max_history: int = 50):
        self.max_history = max_history
        self.messages: deque = deque(maxlen=max_history)
        self.context_snapshots: Dict[str, AnalysisContext] = {}
        self.conversation_id = str(uuid.uuid4())
        
    def add_message(self, role: str, content: str, context_used: Dict = None, 
                   analysis_type: str = None, confidence: float = None) -> str:
        """Add a message to conversation history"""
        
        message_id = str(uuid.uuid4())
        message = ConversationMessage(
            message_id=message_id,
            timestamp=time.time(),
            role=role,
            content=content,
            context_used=context_used or {},
            analysis_type=analysis_type,
            confidence=confidence
        )
        
        self.messages.append(message)
        return message_id
    
    def get_recent_messages(self, count: int = 5) -> List[ConversationMessage]:
        """Get recent messages for context"""
        return list(self.messages)[-count:]
    
    def get_conversation_summary(self) -> str:
        """Generate a summary of the conversation"""
        if not self.messages:
            return "No conversation history"
        
        topics_discussed = set()
        analysis_types = set()
        
        for message in self.messages:
            if message.analysis_type:
                analysis_types.add(message.analysis_type)
            
            # Extract topics from content
            content_lower = message.content.lower()
            if 'flag' in content_lower:
                topics_discussed.add('flags')
            if 'credential' in content_lower:
                topics_discussed.add('credentials')
            if 'network' in content_lower:
                topics_discussed.add('network_analysis')
        
        summary = f"Conversation covers: {', '.join(topics_discussed) if topics_discussed else 'general analysis'}"
        if analysis_types:
            summary += f". Analysis types: {', '.join(analysis_types)}"
        
        return summary

class ConversationalAnalyzer:
    """Main conversational analysis engine"""
    
    def __init__(self, ai_agent=None):
        self.ai_agent = ai_agent
        self.active_conversations: Dict[str, ConversationMemory] = {}
        self.context_managers: Dict[str, AnalysisContext] = {}
        
        # Predefined conversation patterns
        self.conversation_patterns = {
            'flag_inquiry': r'(flag|flags|find.*flag|flag.*found)',
            'credential_inquiry': r'(credential|password|username|auth)',
            'network_inquiry': r'(network|packet|protocol|traffic)',
            'help_request': r'(help|how.*do|what.*is|explain)',
            'analysis_request': r'(analyze|examine|investigate|check)'
        }
        
        # Response templates
        self.response_templates = {
            'flag_summary': "I found {count} flag-related findings in the analysis: {details}",
            'credential_summary': "Detected {count} credential exposures: {details}",
            'network_summary': "Network analysis shows {protocol_count} protocols: {protocols}",
            'no_findings': "I didn't find any {category} in the current analysis. Would you like me to look for something specific?",
            'clarification': "Could you clarify what specific aspect of {topic} you'd like me to analyze?"
        }
    
    def start_conversation(self, analysis_results: Dict[str, Any], 
                          packet_data: List[Dict] = None) -> str:
        """Start a new conversation with analysis context"""
        
        conversation_id = str(uuid.uuid4())
        
        # Initialize conversation memory
        memory = ConversationMemory()
        self.active_conversations[conversation_id] = memory
        
        # Initialize analysis context
        context = AnalysisContext(
            findings=analysis_results.get('findings', []),
            packet_data=packet_data or [],
            analysis_results=analysis_results
        )
        self.context_managers[conversation_id] = context
        
        # Add welcome message
        welcome_msg = self._generate_welcome_message(analysis_results)
        memory.add_message('assistant', welcome_msg, 
                          context_used={'analysis_summary': True})
        
        return conversation_id
    
    def process_user_message(self, conversation_id: str, user_message: str) -> Dict[str, Any]:
        """Process a user message and generate response"""
        
        if conversation_id not in self.active_conversations:
            return {'error': 'Conversation not found'}
        
        memory = self.active_conversations[conversation_id]
        context = self.context_managers[conversation_id]
        
        # Add user message to history
        memory.add_message('user', user_message)
        
        # Analyze user intent
        intent = self._analyze_user_intent(user_message)
        
        # Generate contextual response
        response_data = self._generate_contextual_response(
            user_message, intent, context, memory
        )
        
        # Add assistant response to history
        memory.add_message(
            'assistant', 
            response_data['response'],
            context_used=response_data.get('context_used', {}),
            analysis_type=intent,
            confidence=response_data.get('confidence', 0.8)
        )
        
        return {
            'response': response_data['response'],
            'intent': intent,
            'context_used': response_data.get('context_used', {}),
            'follow_up_suggestions': response_data.get('follow_up_suggestions', []),
            'confidence': response_data.get('confidence', 0.8)
        }
    
    def _generate_welcome_message(self, analysis_results: Dict[str, Any]) -> str:
        """Generate personalized welcome message"""
        
        total_findings = len(analysis_results.get('findings', []))
        total_packets = analysis_results.get('total_packets', 0)
        
        protocols = set()
        flag_count = 0
        credential_count = 0
        
        for finding in analysis_results.get('findings', []):
            if finding.get('protocol'):
                protocols.add(finding['protocol'])
            if finding.get('type') == 'flag':
                flag_count += 1
            elif finding.get('type') == 'credential':
                credential_count += 1
        
        welcome = f"Hello! I've analyzed {total_packets} packets and found {total_findings} interesting findings. "
        
        if flag_count > 0:
            welcome += f"I discovered {flag_count} potential flags. "
        if credential_count > 0:
            welcome += f"I also found {credential_count} credential exposures. "
        if protocols:
            welcome += f"The traffic includes {', '.join(list(protocols)[:3])} protocols. "
        
        welcome += "What would you like to explore?"
        
        return welcome
    
    def _analyze_user_intent(self, message: str) -> str:
        """Analyze user intent from message"""
        
        message_lower = message.lower()
        
        for intent, pattern in self.conversation_patterns.items():
            if re.search(pattern, message_lower):
                return intent
        
        return 'general_inquiry'
    
    def _generate_contextual_response(self, user_message: str, intent: str, 
                                    context: AnalysisContext, 
                                    memory: ConversationMemory) -> Dict[str, Any]:
        """Generate contextual response based on intent and context"""
        
        response_data = {
            'response': '',
            'context_used': {},
            'follow_up_suggestions': [],
            'confidence': 0.8
        }
        
        if intent == 'flag_inquiry':
            response_data = self._handle_flag_inquiry(user_message, context)
        
        elif intent == 'credential_inquiry':
            response_data = self._handle_credential_inquiry(user_message, context)
        
        elif intent == 'network_inquiry':
            response_data = self._handle_network_inquiry(user_message, context)
        
        elif intent == 'help_request':
            response_data = self._handle_help_request(user_message, context, memory)
        
        elif intent == 'analysis_request':
            response_data = self._handle_analysis_request(user_message, context)
        
        else:
            response_data = self._handle_general_inquiry(user_message, context)
        
        return response_data
    
    def _handle_flag_inquiry(self, message: str, context: AnalysisContext) -> Dict[str, Any]:
        """Handle flag-related inquiries"""
        
        flag_findings = [f for f in context.findings if f.get('type') == 'flag']
        
        if not flag_findings:
            return {
                'response': "I didn't find any flags in the current analysis. Would you like me to look for specific flag patterns or check for encoded flags?",
                'context_used': {'findings_checked': True},
                'follow_up_suggestions': [
                    "Search for encoded flags",
                    "Check for flag patterns in specific protocols",
                    "Analyze flag reconstruction possibilities"
                ],
                'confidence': 0.9
            }
        
        # Summarize flag findings
        flag_details = []
        for i, flag in enumerate(flag_findings[:3], 1):
            flag_details.append(f"{i}. {flag.get('data', 'Unknown flag')} (confidence: {flag.get('confidence', 0)}%)")
        
        response = f"I found {len(flag_findings)} flag(s):\n" + "\n".join(flag_details)
        
        if len(flag_findings) > 3:
            response += f"\n... and {len(flag_findings) - 3} more flags."
        
        # Check for flag reconstruction results
        if context.analysis_results.get('flag_reconstruction'):
            reconstruction = context.analysis_results['flag_reconstruction']
            if reconstruction.get('reconstructed_flags'):
                response += f"\n\nAdditionally, I reconstructed {len(reconstruction['reconstructed_flags'])} distributed flags using advanced techniques."
        
        return {
            'response': response,
            'context_used': {'flag_findings': flag_findings},
            'follow_up_suggestions': [
                "Tell me more about the flag reconstruction",
                "Which flag has the highest confidence?",
                "Show me the packet details for these flags"
            ],
            'confidence': 0.95
        }
    
    def _handle_credential_inquiry(self, message: str, context: AnalysisContext) -> Dict[str, Any]:
        """Handle credential-related inquiries"""
        
        credential_findings = [f for f in context.findings if f.get('type') in ['credential', 'token']]
        
        if not credential_findings:
            return {
                'response': "No credentials were detected in the analysis. This could mean the traffic is well-secured or credentials are properly encrypted.",
                'context_used': {'credential_check': True},
                'follow_up_suggestions': [
                    "Check for authentication mechanisms",
                    "Look for encrypted authentication",
                    "Analyze session tokens"
                ],
                'confidence': 0.9
            }
        
        # Analyze credential types
        protocols = set(f.get('protocol', 'Unknown') for f in credential_findings)
        
        response = f"I found {len(credential_findings)} credential exposures across {len(protocols)} protocols: {', '.join(protocols)}. "
        
        # Security assessment
        cleartext_protocols = [p for p in protocols if p in ['FTP', 'TELNET', 'HTTP']]
        if cleartext_protocols:
            response += f"⚠️ WARNING: Credentials transmitted over insecure protocols: {', '.join(cleartext_protocols)}. "
        
        return {
            'response': response,
            'context_used': {'credential_findings': credential_findings},
            'follow_up_suggestions': [
                "What security risks do these credentials pose?",
                "How can these credential exposures be prevented?",
                "Show me the specific credential data"
            ],
            'confidence': 0.9
        }
    
    def _handle_network_inquiry(self, message: str, context: AnalysisContext) -> Dict[str, Any]:
        """Handle network-related inquiries"""
        
        protocols = set(f.get('protocol', 'Unknown') for f in context.findings)
        packet_count = len(context.packet_data) if context.packet_data else context.analysis_results.get('total_packets', 0)
        
        response = f"Network analysis shows {packet_count} packets across {len(protocols)} protocols: {', '.join(list(protocols)[:5])}. "
        
        # Protocol security assessment
        secure_protocols = [p for p in protocols if p in ['HTTPS', 'SSH', 'SFTP']]
        insecure_protocols = [p for p in protocols if p in ['HTTP', 'FTP', 'TELNET']]
        
        if secure_protocols:
            response += f"Secure protocols detected: {', '.join(secure_protocols)}. "
        if insecure_protocols:
            response += f"⚠️ Insecure protocols found: {', '.join(insecure_protocols)}. "
        
        return {
            'response': response,
            'context_used': {'network_analysis': True, 'protocols': list(protocols)},
            'follow_up_suggestions': [
                "What are the security implications?",
                "Show me the traffic patterns",
                "Analyze specific protocol vulnerabilities"
            ],
            'confidence': 0.85
        }
    
    def _handle_help_request(self, message: str, context: AnalysisContext, memory: ConversationMemory) -> Dict[str, Any]:
        """Handle help and explanation requests"""
        
        capabilities = [
            "🔍 Explain analysis findings and their significance",
            "🚩 Help you understand flag discoveries and reconstruction",
            "🔐 Analyze credential exposures and security implications", 
            "🌐 Interpret network traffic patterns and protocols",
            "💡 Provide recommendations for security improvements",
            "🎯 Guide you through CTF challenge solving approaches"
        ]
        
        response = "I can help you with:\n\n" + "\n".join(capabilities)
        response += "\n\nJust ask me about any aspect of the analysis, and I'll provide detailed explanations with context from your data."
        
        return {
            'response': response,
            'context_used': {'help_provided': True},
            'follow_up_suggestions': [
                "Explain the most critical findings",
                "What should I investigate first?",
                "How can I improve security based on these findings?"
            ],
            'confidence': 1.0
        }
    
    def _handle_analysis_request(self, message: str, context: AnalysisContext) -> Dict[str, Any]:
        """Handle specific analysis requests"""
        
        # Extract what they want to analyze
        message_lower = message.lower()
        
        if 'specific' in message_lower or 'detail' in message_lower:
            # They want detailed analysis
            critical_findings = [f for f in context.findings if f.get('confidence', 0) > 80]
            
            if critical_findings:
                response = f"Here are the {len(critical_findings)} highest confidence findings:\n\n"
                for i, finding in enumerate(critical_findings[:3], 1):
                    response += f"{i}. {finding.get('type', 'Unknown').upper()}: {finding.get('data', 'No data')[:100]}...\n"
                    response += f"   Confidence: {finding.get('confidence', 0)}% | Protocol: {finding.get('protocol', 'Unknown')}\n\n"
            else:
                response = "No high-confidence findings available. Would you like me to analyze lower confidence findings or search for specific patterns?"
        
        else:
            # General analysis summary
            total_findings = len(context.findings)
            finding_types = set(f.get('type', 'Unknown') for f in context.findings)
            
            response = f"Analysis summary: {total_findings} findings across {len(finding_types)} categories: {', '.join(finding_types)}. "
            response += "What specific aspect would you like me to analyze further?"
        
        return {
            'response': response,
            'context_used': {'analysis_summary': True},
            'follow_up_suggestions': [
                "Focus on the highest risk findings",
                "Analyze specific protocols",
                "Look for attack patterns"
            ],
            'confidence': 0.8
        }
    
    def _handle_general_inquiry(self, message: str, context: AnalysisContext) -> Dict[str, Any]:
        """Handle general inquiries"""
        
        # Use AI agent if available for more sophisticated responses
        if self.ai_agent:
            try:
                # Create context for AI
                ai_context = {
                    'findings_summary': f"{len(context.findings)} findings analyzed",
                    'protocols': list(set(f.get('protocol', '') for f in context.findings)),
                    'user_question': message
                }
                
                # Note: This would call the AI agent in a real implementation
                response = f"Based on the analysis of {len(context.findings)} findings, I can help you understand: {message}. Could you be more specific about what aspect you'd like to explore?"
                
            except Exception:
                response = "I'd be happy to help! Could you specify what aspect of the analysis you're interested in?"
        else:
            response = "I'd be happy to help! Could you specify what aspect of the analysis you're interested in?"
        
        return {
            'response': response,
            'context_used': {'general_response': True},
            'follow_up_suggestions': [
                "Ask about flags or credentials",
                "Inquire about network security",
                "Request analysis explanations"
            ],
            'confidence': 0.7
        }
    
    def get_conversation_history(self, conversation_id: str) -> List[Dict]:
        """Get conversation history for display"""
        
        if conversation_id not in self.active_conversations:
            return []
        
        memory = self.active_conversations[conversation_id]
        
        return [
            {
                'role': msg.role,
                'content': msg.content,
                'timestamp': msg.timestamp,
                'analysis_type': msg.analysis_type,
                'confidence': msg.confidence
            }
            for msg in memory.messages
        ]
    
    def end_conversation(self, conversation_id: str) -> Dict[str, Any]:
        """End conversation and return summary"""
        
        if conversation_id not in self.active_conversations:
            return {'error': 'Conversation not found'}
        
        memory = self.active_conversations[conversation_id]
        summary = memory.get_conversation_summary()
        
        # Clean up
        del self.active_conversations[conversation_id]
        del self.context_managers[conversation_id]
        
        return {
            'summary': summary,
            'message_count': len(memory.messages),
            'conversation_id': conversation_id
        }

# Factory function
def create_conversational_analyzer(ai_agent=None) -> ConversationalAnalyzer:
    """Create conversational analyzer instance"""
    return ConversationalAnalyzer(ai_agent)