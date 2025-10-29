"""Multi-Agent System for CTF Challenge Solving"""

import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
import time
import json
import uuid

class Agent:
    """Base class for specialized CTF agents"""
    
    def __init__(self, agent_id: str, name: str, description: str, capabilities: List[str]):
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.capabilities = capabilities
        self.knowledge_base = {}
        self.observations = []
        self.tasks = []
        self.messages = []
    
    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data according to agent's capabilities"""
        raise NotImplementedError("Subclasses must implement process()")
    
    def observe(self, observation: Dict[str, Any]):
        """Add an observation to the agent's observation list"""
        self.observations.append({
            'timestamp': time.time(),
            'data': observation
        })
    
    def add_task(self, task: Dict[str, Any]):
        """Add a task to the agent's task list"""
        self.tasks.append({
            'task_id': task.get('task_id', str(uuid.uuid4())),
            'timestamp': time.time(),
            'status': 'pending',
            'data': task
        })
    
    def get_next_task(self) -> Optional[Dict[str, Any]]:
        """Get the next pending task"""
        for task in self.tasks:
            if task['status'] == 'pending':
                return task
        return None
    
    def update_task_status(self, task_id: str, status: str, result: Optional[Dict[str, Any]] = None):
        """Update the status of a task"""
        for task in self.tasks:
            if task['task_id'] == task_id:
                task['status'] = status
                if result:
                    task['result'] = result
                task['updated_at'] = time.time()
                break
    
    def add_to_knowledge_base(self, key: str, value: Any):
        """Add information to the agent's knowledge base"""
        self.knowledge_base[key] = value
    
    def get_from_knowledge_base(self, key: str) -> Optional[Any]:
        """Get information from the agent's knowledge base"""
        return self.knowledge_base.get(key)
    
    def send_message(self, to_agent_id: str, message_type: str, content: Dict[str, Any]):
        """Send a message to another agent"""
        message = {
            'message_id': str(uuid.uuid4()),
            'from_agent_id': self.agent_id,
            'to_agent_id': to_agent_id,
            'timestamp': time.time(),
            'message_type': message_type,
            'content': content
        }
        self.messages.append(message)
        return message
    
    def get_unread_messages(self) -> List[Dict[str, Any]]:
        """Get all unread messages for this agent"""
        unread = []
        for message in self.messages:
            if message.get('to_agent_id') == self.agent_id and not message.get('read', False):
                unread.append(message)
                message['read'] = True
        return unread

class NetworkAnalysisAgent(Agent):
    """Agent specialized in network traffic analysis"""
    
    def __init__(self, agent_id: str = None):
        super().__init__(
            agent_id or f"network_{str(uuid.uuid4())[:8]}",
            "Network Analysis Agent",
            "Specializes in analyzing network traffic and protocols",
            ["pcap_analysis", "http_analysis", "dns_analysis", "protocol_identification"]
        )
        self.network_decoder = None  # Will be set by the coordinator
    
    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process network data"""
        result = {}
        
        if 'pcap_file' in data:
            # Process PCAP file
            if self.network_decoder:
                result['http_analysis'] = self.network_decoder.analyze_http_responses(data['packet_data'])
                result['dns_analysis'] = self.network_decoder.analyze_dns_queries(data['packet_data'])
                result['suspicious_packets'] = self.network_decoder.identify_suspicious_packets(data['packet_data'])
        
        if 'http_responses' in data:
            # Analyze HTTP responses
            result['http_findings'] = self._analyze_http_responses(data['http_responses'])
        
        if 'dns_queries' in data:
            # Analyze DNS queries
            result['dns_findings'] = self._analyze_dns_queries(data['dns_queries'])
        
        return result
    
    def _analyze_http_responses(self, http_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze HTTP responses for hidden data"""
        findings = {
            'suspicious_headers': [],
            'hidden_comments': [],
            'base64_content': [],
            'potential_flags': []
        }
        
        for response in http_responses:
            # Check headers
            if 'headers' in response:
                for header, value in response['headers'].items():
                    if header.lower() not in ['content-type', 'content-length', 'date', 'server', 'connection']:
                        findings['suspicious_headers'].append({
                            'header': header,
                            'value': value,
                            'response_id': response.get('id')
                        })
            
            # Check for hidden comments
            if 'body' in response and response['body']:
                import re
                comments = re.findall(r'<!--(.+?)-->', response['body'], re.DOTALL)
                if comments:
                    findings['hidden_comments'].extend([{
                        'comment': comment.strip(),
                        'response_id': response.get('id')
                    } for comment in comments])
                
                # Check for Base64 content
                base64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', response['body'])
                if base64_patterns:
                    findings['base64_content'].extend([{
                        'content': pattern,
                        'response_id': response.get('id')
                    } for pattern in base64_patterns])
                
                # Check for potential flags
                flag_patterns = re.findall(r'flag\{[^}]+\}|CTF\{[^}]+\}', response['body'], re.IGNORECASE)
                if flag_patterns:
                    findings['potential_flags'].extend([{
                        'flag': pattern,
                        'response_id': response.get('id')
                    } for pattern in flag_patterns])
        
        return findings
    
    def _analyze_dns_queries(self, dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze DNS queries for hidden data"""
        findings = {
            'suspicious_domains': [],
            'encoded_subdomains': [],
            'potential_data_exfiltration': []
        }
        
        for query in dns_queries:
            # Check for suspicious domains
            if 'query' in query:
                domain = query['query']
                
                # Check for very long subdomains (potential data exfiltration)
                parts = domain.split('.')
                for part in parts:
                    if len(part) > 30:
                        findings['potential_data_exfiltration'].append({
                            'subdomain': part,
                            'domain': domain,
                            'query_id': query.get('id')
                        })
                
                # Check for encoded subdomains
                import base64
                for part in parts:
                    try:
                        # Try to decode as base64
                        decoded = base64.b64decode(part + '=' * (-len(part) % 4)).decode('utf-8')
                        if any(c.isprintable() for c in decoded):
                            findings['encoded_subdomains'].append({
                                'subdomain': part,
                                'decoded': decoded,
                                'encoding': 'base64',
                                'query_id': query.get('id')
                            })
                    except Exception:
                        pass
        
        return findings

class CryptoAnalysisAgent(Agent):
    """Agent specialized in cryptographic analysis"""
    
    def __init__(self, agent_id: str = None):
        super().__init__(
            agent_id or f"crypto_{str(uuid.uuid4())[:8]}",
            "Cryptographic Analysis Agent",
            "Specializes in cryptographic analysis and decoding",
            ["encoding_detection", "decoding", "cipher_analysis", "hash_identification"]
        )
        self.encoding_decoder = None  # Will be set by the coordinator
    
    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process cryptographic data"""
        result = {}
        
        if 'encoded_data' in data:
            # Try to decode the data
            result['decoded_data'] = self._decode_data(data['encoded_data'])
        
        if 'cipher_text' in data:
            # Try to analyze and break ciphers
            result['cipher_analysis'] = self._analyze_cipher(data['cipher_text'])
        
        if 'hash_values' in data:
            # Identify hash types
            result['hash_identification'] = self._identify_hashes(data['hash_values'])
        
        return result
    
    def _decode_data(self, encoded_data: List[str]) -> List[Dict[str, Any]]:
        """Try to decode data using various encoding schemes"""
        results = []
        
        for data_item in encoded_data:
            if self.encoding_decoder:
                possible_encodings = self.encoding_decoder.detect_encoding(data_item)
                decoded_results = []
                
                for encoding in possible_encodings:
                    try:
                        decoder = self.encoding_decoder.decoders.get(encoding)
                        if decoder:
                            decoded = decoder(data_item)
                            decoded_results.append({
                                'encoding': encoding,
                                'decoded': decoded
                            })
                    except Exception:
                        pass
                
                results.append({
                    'original': data_item,
                    'decoded_results': decoded_results
                })
        
        return results
    
    def _analyze_cipher(self, cipher_text: str) -> Dict[str, Any]:
        """Analyze and try to break common ciphers"""
        results = {
            'possible_ciphers': [],
            'decryption_attempts': []
        }
        
        # Check for Caesar cipher
        caesar_results = []
        for shift in range(1, 26):
            decrypted = ''.join([chr((ord(c) - ord('a') - shift) % 26 + ord('a')) if c.islower() 
                               else chr((ord(c) - ord('A') - shift) % 26 + ord('A')) if c.isupper() 
                               else c for c in cipher_text])
            caesar_results.append({
                'shift': shift,
                'decrypted': decrypted
            })
        
        results['decryption_attempts'].append({
            'cipher': 'caesar',
            'results': caesar_results
        })
        
        # Check for Vigenère cipher (simplified approach)
        # This would require frequency analysis and is more complex
        
        # Check for transposition ciphers
        # This would require trying different key lengths
        
        return results
    
    def _identify_hashes(self, hash_values: List[str]) -> List[Dict[str, Any]]:
        """Identify hash types based on patterns"""
        results = []
        
        for hash_value in hash_values:
            hash_type = 'unknown'
            confidence = 0
            
            # MD5
            if len(hash_value) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
                hash_type = 'md5'
                confidence = 90
            
            # SHA-1
            elif len(hash_value) == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
                hash_type = 'sha1'
                confidence = 90
            
            # SHA-256
            elif len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
                hash_type = 'sha256'
                confidence = 90
            
            # SHA-512
            elif len(hash_value) == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
                hash_type = 'sha512'
                confidence = 90
            
            results.append({
                'hash': hash_value,
                'identified_type': hash_type,
                'confidence': confidence
            })
        
        return results

class WebAnalysisAgent(Agent):
    """Agent specialized in web application analysis"""
    
    def __init__(self, agent_id: str = None):
        super().__init__(
            agent_id or f"web_{str(uuid.uuid4())[:8]}",
            "Web Analysis Agent",
            "Specializes in web application analysis",
            ["http_analysis", "javascript_analysis", "html_analysis", "web_vulnerability_detection"]
        )
    
    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process web data"""
        result = {}
        
        if 'html_content' in data:
            # Analyze HTML content
            result['html_analysis'] = self._analyze_html(data['html_content'])
        
        if 'javascript_content' in data:
            # Analyze JavaScript content
            result['javascript_analysis'] = self._analyze_javascript(data['javascript_content'])
        
        if 'http_requests' in data:
            # Analyze HTTP requests for vulnerabilities
            result['vulnerability_analysis'] = self._analyze_vulnerabilities(data['http_requests'])
        
        return result
    
    def _analyze_html(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML content for hidden data"""
        import re
        findings = {
            'hidden_inputs': [],
            'comments': [],
            'suspicious_scripts': [],
            'potential_flags': []
        }
        
        # Find hidden inputs
        hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', html_content)
        for input_tag in hidden_inputs:
            value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag)
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag)
            
            if value_match and name_match:
                findings['hidden_inputs'].append({
                    'name': name_match.group(1),
                    'value': value_match.group(1)
                })
        
        # Find comments
        comments = re.findall(r'<!--(.+?)-->', html_content, re.DOTALL)
        findings['comments'] = [comment.strip() for comment in comments]
        
        # Find suspicious scripts
        scripts = re.findall(r'<script[^>]*>(.+?)</script>', html_content, re.DOTALL)
        for script in scripts:
            if 'eval(' in script or 'document.cookie' in script or 'localStorage' in script:
                findings['suspicious_scripts'].append(script)
        
        # Find potential flags
        flag_patterns = re.findall(r'flag\{[^}]+\}|CTF\{[^}]+\}', html_content, re.IGNORECASE)
        findings['potential_flags'] = flag_patterns
        
        return findings
    
    def _analyze_javascript(self, javascript_content: str) -> Dict[str, Any]:
        """Analyze JavaScript content for hidden data"""
        import re
        findings = {
            'obfuscated_code': False,
            'suspicious_functions': [],
            'encoded_strings': [],
            'potential_flags': []
        }
        
        # Check for obfuscation
        if ('eval(' in javascript_content and 'function(' in javascript_content) or \
           ('\\x' in javascript_content and javascript_content.count('\\x') > 10):
            findings['obfuscated_code'] = True
        
        # Check for suspicious functions
        suspicious_funcs = ['eval', 'atob', 'btoa', 'escape', 'unescape', 'fromCharCode']
        for func in suspicious_funcs:
            if func + '(' in javascript_content:
                # Find the function call and its arguments
                func_calls = re.findall(r'{}\(([^)]+)\)'.format(func), javascript_content)
                for call in func_calls:
                    findings['suspicious_functions'].append({
                        'function': func,
                        'arguments': call
                    })
        
        # Check for encoded strings
        encoded_patterns = re.findall(r'[\'"](\\x[0-9a-fA-F]{2})+[\'"]', javascript_content)
        findings['encoded_strings'] = encoded_patterns
        
        # Find potential flags
        flag_patterns = re.findall(r'flag\{[^}]+\}|CTF\{[^}]+\}', javascript_content, re.IGNORECASE)
        findings['potential_flags'] = flag_patterns
        
        return findings
    
    def _analyze_vulnerabilities(self, http_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze HTTP requests for common vulnerabilities"""
        findings = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'path_traversal': []
        }
        
        for request in http_requests:
            # Check for SQL injection
            sql_patterns = ["'", "--", ";", "/*", "*/", "UNION", "SELECT", "OR 1=1", "' OR '1'='1"]
            for pattern in sql_patterns:
                if 'params' in request and any(pattern in str(v).upper() for v in request['params'].values()):
                    findings['sql_injection'].append({
                        'request_id': request.get('id'),
                        'pattern': pattern,
                        'params': request['params']
                    })
            
            # Check for XSS
            xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "onclick="]
            for pattern in xss_patterns:
                if 'params' in request and any(pattern in str(v) for v in request['params'].values()):
                    findings['xss'].append({
                        'request_id': request.get('id'),
                        'pattern': pattern,
                        'params': request['params']
                    })
            
            # Check for command injection
            cmd_patterns = [";", "|", "&", "`", "$("]
            for pattern in cmd_patterns:
                if 'params' in request and any(pattern in str(v) for v in request['params'].values()):
                    findings['command_injection'].append({
                        'request_id': request.get('id'),
                        'pattern': pattern,
                        'params': request['params']
                    })
            
            # Check for path traversal
            path_patterns = ["../", "..\\"]
            for pattern in path_patterns:
                if 'params' in request and any(pattern in str(v) for v in request['params'].values()):
                    findings['path_traversal'].append({
                        'request_id': request.get('id'),
                        'pattern': pattern,
                        'params': request['params']
                    })
        
        return findings

class BinaryAnalysisAgent(Agent):
    """Agent specialized in binary analysis"""
    
    def __init__(self, agent_id: str = None):
        super().__init__(
            agent_id or f"binary_{str(uuid.uuid4())[:8]}",
            "Binary Analysis Agent",
            "Specializes in binary file analysis",
            ["string_extraction", "file_format_analysis", "embedded_file_detection"]
        )
    
    def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process binary data"""
        result = {}
        
        if 'binary_file' in data:
            # Extract strings from binary
            result['extracted_strings'] = self._extract_strings(data['binary_file'])
            
            # Analyze file format
            result['file_format'] = self._analyze_file_format(data['binary_file'])
            
            # Detect embedded files
            result['embedded_files'] = self._detect_embedded_files(data['binary_file'])
        
        return result
    
    def _extract_strings(self, binary_file: str) -> List[str]:
        """Extract printable strings from binary file"""
        # This would typically use the 'strings' command or similar
        # For simulation, we'll return a placeholder
        return ["Simulated string extraction from binary file"]
    
    def _analyze_file_format(self, binary_file: str) -> Dict[str, Any]:
        """Analyze the format of a binary file"""
        # This would typically use file signatures to identify file types
        # For simulation, we'll return a placeholder
        return {
            'format': 'unknown',
            'details': {}
        }
    
    def _detect_embedded_files(self, binary_file: str) -> List[Dict[str, Any]]:
        """Detect embedded files within a binary file"""
        # This would typically look for file signatures within the binary
        # For simulation, we'll return a placeholder
        return []

class MultiAgentCoordinator:
    """Coordinates multiple specialized agents for CTF challenge solving"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.agents = {}
        self.message_queue = []
        self.knowledge_base = {}
        self.workflow_history = []
    
    def register_agent(self, agent: Agent):
        """Register an agent with the coordinator"""
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent: {agent.name} ({agent.agent_id})")
    
    def dispatch_task(self, agent_id: str, task: Dict[str, Any]) -> str:
        """Dispatch a task to a specific agent"""
        if agent_id not in self.agents:
            raise ValueError(f"Agent {agent_id} not registered")
        
        task_id = task.get('task_id', str(uuid.uuid4()))
        task['task_id'] = task_id
        
        self.agents[agent_id].add_task(task)
        
        self.logger.info(f"Dispatched task {task_id} to agent {agent_id}")
        
        self.workflow_history.append({
            'action': 'task_dispatched',
            'timestamp': time.time(),
            'agent_id': agent_id,
            'task_id': task_id,
            'task_type': task.get('type')
        })
        
        return task_id
    
    def dispatch_by_capability(self, capability: str, task: Dict[str, Any]) -> Optional[str]:
        """Dispatch a task to an agent with a specific capability"""
        for agent_id, agent in self.agents.items():
            if capability in agent.capabilities:
                return self.dispatch_task(agent_id, task)
        
        self.logger.warning(f"No agent found with capability: {capability}")
        return None
    
    def process_agent_tasks(self):
        """Process pending tasks for all agents"""
        results = {}
        
        for agent_id, agent in self.agents.items():
            task = agent.get_next_task()
            if task:
                self.logger.info(f"Processing task {task['task_id']} for agent {agent_id}")
                
                try:
                    # Process the task
                    result = agent.process(task['data'])
                    
                    # Update task status
                    agent.update_task_status(task['task_id'], 'completed', result)
                    
                    # Add to results
                    results[task['task_id']] = {
                        'agent_id': agent_id,
                        'result': result
                    }
                    
                    # Update knowledge base
                    self._update_knowledge_base(agent_id, task['task_id'], result)
                    
                    # Record in workflow history
                    self.workflow_history.append({
                        'action': 'task_completed',
                        'timestamp': time.time(),
                        'agent_id': agent_id,
                        'task_id': task['task_id'],
                        'result_summary': self._summarize_result(result)
                    })
                    
                except Exception as e:
                    self.logger.error(f"Error processing task {task['task_id']} for agent {agent_id}: {str(e)}")
                    agent.update_task_status(task['task_id'], 'failed', {'error': str(e)})
                    
                    # Record in workflow history
                    self.workflow_history.append({
                        'action': 'task_failed',
                        'timestamp': time.time(),
                        'agent_id': agent_id,
                        'task_id': task['task_id'],
                        'error': str(e)
                    })
        
        return results
    
    def _update_knowledge_base(self, agent_id: str, task_id: str, result: Dict[str, Any]):
        """Update the global knowledge base with task results"""
        # Add to global knowledge base
        self.knowledge_base[f"{agent_id}_{task_id}"] = result
        
        # Extract and categorize findings
        self._extract_findings(result)
    
    def _extract_findings(self, result: Dict[str, Any]):
        """Extract and categorize findings from task results"""
        # Extract potential flags
        if 'potential_flags' in result:
            if 'flags' not in self.knowledge_base:
                self.knowledge_base['flags'] = []
            self.knowledge_base['flags'].extend(result['potential_flags'])
        
        # Extract decoded data
        if 'decoded_data' in result:
            if 'decoded_data' not in self.knowledge_base:
                self.knowledge_base['decoded_data'] = []
            self.knowledge_base['decoded_data'].extend(result['decoded_data'])
        
        # Extract suspicious findings
        for key in ['suspicious_packets', 'suspicious_headers', 'suspicious_domains', 'suspicious_scripts']:
            if key in result:
                if 'suspicious_findings' not in self.knowledge_base:
                    self.knowledge_base['suspicious_findings'] = {}
                if key not in self.knowledge_base['suspicious_findings']:
                    self.knowledge_base['suspicious_findings'][key] = []
                self.knowledge_base['suspicious_findings'][key].extend(result[key])
    
    def _summarize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of task results"""
        summary = {}
        
        # Count items in each category
        for key, value in result.items():
            if isinstance(value, list):
                summary[key] = len(value)
            elif isinstance(value, dict):
                summary[key] = {k: len(v) if isinstance(v, list) else v for k, v in value.items()}
            else:
                summary[key] = value
        
        return summary
    
    def send_message(self, from_agent_id: str, to_agent_id: str, message_type: str, content: Dict[str, Any]):
        """Send a message from one agent to another"""
        if from_agent_id not in self.agents:
            raise ValueError(f"Agent {from_agent_id} not registered")
        
        if to_agent_id not in self.agents:
            raise ValueError(f"Agent {to_agent_id} not registered")
        
        message = self.agents[from_agent_id].send_message(to_agent_id, message_type, content)
        self.message_queue.append(message)
        
        # Deliver the message to the recipient
        self.agents[to_agent_id].messages.append(message)
        
        self.logger.info(f"Message sent from {from_agent_id} to {to_agent_id}: {message_type}")
        
        self.workflow_history.append({
            'action': 'message_sent',
            'timestamp': time.time(),
            'from_agent_id': from_agent_id,
            'to_agent_id': to_agent_id,
            'message_type': message_type
        })
        
        return message['message_id']
    
    def broadcast_message(self, from_agent_id: str, message_type: str, content: Dict[str, Any]):
        """Broadcast a message from one agent to all other agents"""
        if from_agent_id not in self.agents:
            raise ValueError(f"Agent {from_agent_id} not registered")
        
        message_ids = []
        
        for to_agent_id in self.agents:
            if to_agent_id != from_agent_id:
                message_id = self.send_message(from_agent_id, to_agent_id, message_type, content)
                message_ids.append(message_id)
        
        return message_ids
    
    def process_messages(self):
        """Process all pending messages"""
        for agent_id, agent in self.agents.items():
            unread_messages = agent.get_unread_messages()
            
            for message in unread_messages:
                self.logger.info(f"Agent {agent_id} processing message {message['message_id']} from {message['from_agent_id']}")
                
                # Record in workflow history
                self.workflow_history.append({
                    'action': 'message_processed',
                    'timestamp': time.time(),
                    'agent_id': agent_id,
                    'message_id': message['message_id'],
                    'from_agent_id': message['from_agent_id'],
                    'message_type': message['message_type']
                })
    
    def get_agent_by_capability(self, capability: str) -> Optional[Agent]:
        """Get an agent with a specific capability"""
        for agent in self.agents.values():
            if capability in agent.capabilities:
                return agent
        return None
    
    def get_workflow_history(self) -> List[Dict[str, Any]]:
        """Get the workflow history"""
        return self.workflow_history
    
    def get_knowledge_base(self) -> Dict[str, Any]:
        """Get the global knowledge base"""
        return self.knowledge_base
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report of findings"""
        report = {
            'timestamp': time.time(),
            'agents': {},
            'findings': {},
            'potential_flags': [],
            'workflow_summary': self._generate_workflow_summary(),
            'recommendations': []
        }
        
        # Summarize agent activities
        for agent_id, agent in self.agents.items():
            report['agents'][agent_id] = {
                'name': agent.name,
                'tasks_completed': sum(1 for task in agent.tasks if task['status'] == 'completed'),
                'tasks_failed': sum(1 for task in agent.tasks if task['status'] == 'failed'),
                'tasks_pending': sum(1 for task in agent.tasks if task['status'] == 'pending')
            }
        
        # Compile findings
        if 'flags' in self.knowledge_base:
            report['potential_flags'] = self.knowledge_base['flags']
        
        if 'decoded_data' in self.knowledge_base:
            report['findings']['decoded_data'] = self.knowledge_base['decoded_data']
        
        if 'suspicious_findings' in self.knowledge_base:
            report['findings']['suspicious'] = self.knowledge_base['suspicious_findings']
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations()
        
        return report
    
    def _generate_workflow_summary(self) -> Dict[str, Any]:
        """Generate a summary of the workflow history"""
        summary = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'total_messages': 0,
            'agent_activity': {}
        }
        
        # Count tasks and messages
        for event in self.workflow_history:
            if event['action'] == 'task_dispatched':
                summary['total_tasks'] += 1
                
                if event['agent_id'] not in summary['agent_activity']:
                    summary['agent_activity'][event['agent_id']] = {
                        'tasks_dispatched': 0,
                        'tasks_completed': 0,
                        'tasks_failed': 0,
                        'messages_sent': 0,
                        'messages_received': 0
                    }
                
                summary['agent_activity'][event['agent_id']]['tasks_dispatched'] += 1
            
            elif event['action'] == 'task_completed':
                summary['completed_tasks'] += 1
                if event['agent_id'] in summary['agent_activity']:
                    summary['agent_activity'][event['agent_id']]['tasks_completed'] += 1
            
            elif event['action'] == 'task_failed':
                summary['failed_tasks'] += 1
                if event['agent_id'] in summary['agent_activity']:
                    summary['agent_activity'][event['agent_id']]['tasks_failed'] += 1
            
            elif event['action'] == 'message_sent':
                summary['total_messages'] += 1
                if event['from_agent_id'] in summary['agent_activity']:
                    summary['agent_activity'][event['from_agent_id']]['messages_sent'] += 1
                if event['to_agent_id'] in summary['agent_activity']:
                    summary['agent_activity'][event['to_agent_id']]['messages_received'] += 1
        
        return summary
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Check for potential flags
        if 'flags' in self.knowledge_base and self.knowledge_base['flags']:
            recommendations.append("Review potential flags found in the analysis")
        
        # Check for decoded data
        if 'decoded_data' in self.knowledge_base and self.knowledge_base['decoded_data']:
            recommendations.append("Examine decoded data for hidden information")
        
        # Check for suspicious findings
        if 'suspicious_findings' in self.knowledge_base:
            suspicious = self.knowledge_base['suspicious_findings']
            
            if 'suspicious_packets' in suspicious and suspicious['suspicious_packets']:
                recommendations.append("Investigate suspicious network packets")
            
            if 'suspicious_headers' in suspicious and suspicious['suspicious_headers']:
                recommendations.append("Examine unusual HTTP headers for hidden information")
            
            if 'suspicious_domains' in suspicious and suspicious['suspicious_domains']:
                recommendations.append("Look into suspicious DNS queries and domains")
            
            if 'suspicious_scripts' in suspicious and suspicious['suspicious_scripts']:
                recommendations.append("Analyze suspicious JavaScript code for hidden functionality")
        
        return recommendations

# Example usage
def create_multi_agent_system(logger=None):
    """Create and configure a multi-agent system for CTF challenges"""
    coordinator = MultiAgentCoordinator(logger)
    
    # Create specialized agents
    network_agent = NetworkAnalysisAgent()
    crypto_agent = CryptoAnalysisAgent()
    web_agent = WebAnalysisAgent()
    binary_agent = BinaryAnalysisAgent()
    
    # Register agents with the coordinator
    coordinator.register_agent(network_agent)
    coordinator.register_agent(crypto_agent)
    coordinator.register_agent(web_agent)
    coordinator.register_agent(binary_agent)
    
    return coordinator, {
        'network': network_agent,
        'crypto': crypto_agent,
        'web': web_agent,
        'binary': binary_agent
    }