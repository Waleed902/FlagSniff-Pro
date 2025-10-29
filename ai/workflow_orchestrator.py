"""Workflow Orchestrator for Multi-Step CTF Analysis"""

import logging
from typing import Dict, List, Any, Optional, Callable
import time

class WorkflowStep:
    """Represents a single step in a CTF analysis workflow"""
    
    def __init__(self, name: str, description: str, function: Callable, 
                 required_inputs: List[str] = None, produces_outputs: List[str] = None):
        self.name = name
        self.description = description
        self.function = function
        self.required_inputs = required_inputs or []
        self.produces_outputs = produces_outputs or []
        self.status = "pending"  # pending, in_progress, completed, failed
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
    
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """Check if this step can be executed with the current context"""
        return all(input_key in context for input_key in self.required_inputs)
    
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute this workflow step"""
        self.status = "in_progress"
        self.start_time = time.time()
        
        try:
            # Extract required inputs from context
            inputs = {key: context[key] for key in self.required_inputs if key in context}
            
            # Execute the function
            self.result = self.function(**inputs)
            
            # Update status
            self.status = "completed"
            
            # Update context with produced outputs
            for output_key in self.produces_outputs:
                if output_key in self.result:
                    context[output_key] = self.result[output_key]
            
            return self.result
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            raise
        finally:
            self.end_time = time.time()

class WorkflowOrchestrator:
    """Orchestrates multi-step CTF analysis workflows"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.workflows = {}
        self.current_workflow = None
        self.context = {}
        self.steps_history = []
        self.callbacks = {}
    
    def register_workflow(self, workflow_id: str, name: str, description: str):
        """Register a new workflow"""
        self.workflows[workflow_id] = {
            'id': workflow_id,
            'name': name,
            'description': description,
            'steps': []
        }
    
    def add_step(self, workflow_id: str, step: WorkflowStep):
        """Add a step to a workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} does not exist")
        
        self.workflows[workflow_id]['steps'].append(step)
    
    def register_callback(self, event: str, callback: Callable):
        """Register a callback for workflow events"""
        self.callbacks[event] = callback
    
    def _trigger_callback(self, event: str, data: Dict[str, Any]):
        """Trigger a registered callback"""
        if event in self.callbacks and callable(self.callbacks[event]):
            self.callbacks[event](data)
    
    def start_workflow(self, workflow_id: str, initial_context: Dict[str, Any] = None):
        """Start a workflow with optional initial context"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} does not exist")
        
        self.current_workflow = self.workflows[workflow_id]
        self.context = initial_context or {}
        self.steps_history = []
        
        self.logger.info(f"Starting workflow: {self.current_workflow['name']}")
        self._trigger_callback('workflow_started', {
            'workflow_id': workflow_id,
            'name': self.current_workflow['name']
        })
        
        return self.execute_next_step()
    
    def execute_next_step(self):
        """Execute the next available step in the current workflow"""
        if not self.current_workflow:
            raise ValueError("No workflow is currently active")
        
        # Find the next executable step
        for step in self.current_workflow['steps']:
            if step.status == "pending" and step.can_execute(self.context):
                self.logger.info(f"Executing step: {step.name}")
                
                self._trigger_callback('step_started', {
                    'step_name': step.name,
                    'description': step.description
                })
                
                try:
                    result = step.execute(self.context)
                    
                    self.steps_history.append({
                        'name': step.name,
                        'status': step.status,
                        'start_time': step.start_time,
                        'end_time': step.end_time,
                        'duration': step.end_time - step.start_time if step.end_time else None
                    })
                    
                    self._trigger_callback('step_completed', {
                        'step_name': step.name,
                        'result': result
                    })
                    
                    return result
                except Exception as e:
                    self.logger.error(f"Step {step.name} failed: {str(e)}")
                    
                    self._trigger_callback('step_failed', {
                        'step_name': step.name,
                        'error': str(e)
                    })
                    
                    raise
        
        # If we get here, there are no more executable steps
        all_completed = all(step.status == "completed" for step in self.current_workflow['steps'])
        
        if all_completed:
            self.logger.info(f"Workflow {self.current_workflow['name']} completed successfully")
            
            self._trigger_callback('workflow_completed', {
                'workflow_id': self.current_workflow['id'],
                'name': self.current_workflow['name'],
                'steps_history': self.steps_history,
                'context': self.context
            })
            
            return {
                'status': 'completed',
                'workflow': self.current_workflow['name'],
                'steps_history': self.steps_history,
                'context': self.context
            }
        else:
            # Some steps couldn't be executed due to missing inputs
            pending_steps = [step.name for step in self.current_workflow['steps'] 
                            if step.status == "pending"]
            
            self.logger.warning(f"Workflow {self.current_workflow['name']} has pending steps: {pending_steps}")
            
            missing_inputs = {}
            for step in self.current_workflow['steps']:
                if step.status == "pending":
                    missing = [input_key for input_key in step.required_inputs 
                              if input_key not in self.context]
                    if missing:
                        missing_inputs[step.name] = missing
            
            self._trigger_callback('workflow_blocked', {
                'workflow_id': self.current_workflow['id'],
                'name': self.current_workflow['name'],
                'pending_steps': pending_steps,
                'missing_inputs': missing_inputs
            })
            
            return {
                'status': 'blocked',
                'workflow': self.current_workflow['name'],
                'pending_steps': pending_steps,
                'missing_inputs': missing_inputs,
                'steps_history': self.steps_history
            }
    
    def execute_all_steps(self):
        """Execute all possible steps in the current workflow"""
        if not self.current_workflow:
            raise ValueError("No workflow is currently active")
        
        result = None
        made_progress = True
        
        # Keep executing steps as long as we're making progress
        while made_progress:
            # Track the number of completed steps before this iteration
            completed_before = sum(1 for step in self.current_workflow['steps'] 
                                 if step.status == "completed")
            
            # Try to execute the next step
            try:
                result = self.execute_next_step()
            except Exception as e:
                self.logger.error(f"Workflow execution failed: {str(e)}")
                return {
                    'status': 'failed',
                    'error': str(e),
                    'steps_history': self.steps_history
                }
            
            # Check if we made progress
            completed_after = sum(1 for step in self.current_workflow['steps'] 
                                if step.status == "completed")
            made_progress = completed_after > completed_before
            
            # If we got a 'completed' status, we're done
            if isinstance(result, dict) and result.get('status') == 'completed':
                break
        
        return result
    
    def get_workflow_status(self):
        """Get the current status of the active workflow"""
        if not self.current_workflow:
            return {'status': 'no_active_workflow'}
        
        total_steps = len(self.current_workflow['steps'])
        completed_steps = sum(1 for step in self.current_workflow['steps'] 
                             if step.status == "completed")
        failed_steps = sum(1 for step in self.current_workflow['steps'] 
                          if step.status == "failed")
        pending_steps = sum(1 for step in self.current_workflow['steps'] 
                           if step.status == "pending")
        in_progress_steps = sum(1 for step in self.current_workflow['steps'] 
                               if step.status == "in_progress")
        
        progress_percentage = (completed_steps / total_steps) * 100 if total_steps > 0 else 0
        
        return {
            'workflow_id': self.current_workflow['id'],
            'name': self.current_workflow['name'],
            'total_steps': total_steps,
            'completed_steps': completed_steps,
            'failed_steps': failed_steps,
            'pending_steps': pending_steps,
            'in_progress_steps': in_progress_steps,
            'progress_percentage': progress_percentage,
            'steps_history': self.steps_history
        }
    
    def reset_workflow(self):
        """Reset the current workflow to its initial state"""
        if not self.current_workflow:
            return
        
        # Reset all steps
        for step in self.current_workflow['steps']:
            step.status = "pending"
            step.result = None
            step.error = None
            step.start_time = None
            step.end_time = None
        
        # Clear history and context
        self.steps_history = []
        self.context = {}
        
        self.logger.info(f"Reset workflow: {self.current_workflow['name']}")
        
        self._trigger_callback('workflow_reset', {
            'workflow_id': self.current_workflow['id'],
            'name': self.current_workflow['name']
        })

    def list_workflows(self):
        """Return a list of registered workflows"""
        return list(self.workflows.values())

# Example CTF workflow creation
def create_network_ctf_workflow(orchestrator, packet_parser, pattern_matcher, 
                              network_decoder, encoding_decoder, ctf_analyzer):
    """Create a workflow for network-based CTF challenges"""
    # Register the workflow
    orchestrator.register_workflow(
        'network_ctf',
        'Network CTF Challenge Analysis',
        'Multi-step workflow for analyzing network-based CTF challenges'
    )
    
    # Define step functions
    def parse_packets(pcap_file):
        return {'packet_data_list': packet_parser.parse_pcap(pcap_file)}
    
    def search_patterns(packet_data_list):
        patterns = {}
        for pattern_type in ['flags', 'credentials', 'tokens', 'emails']:
            patterns[pattern_type] = pattern_matcher.search_pattern(pattern_type, packet_data_list)
        return {'patterns': patterns}
    
    def analyze_http(packet_data_list):
        return {'http_analysis': network_decoder.analyze_http_responses(packet_data_list)}
    
    def extract_patterns(packet_data_list, http_analysis):
        # Extract first letters, last letters, text between markers, etc.
        return {'extracted_patterns': network_decoder.extract_patterns(packet_data_list)}
    
    def decode_data(packet_data_list, extracted_patterns):
        # Try to decode potential encoded data
        decoded_items = []
        for pattern in extracted_patterns:
            if 'data' in pattern:
                possible_encodings = encoding_decoder.detect_encoding(pattern['data'])
                for encoding in possible_encodings:
                    try:
                        decoder = encoding_decoder.decoders.get(encoding)
                        if decoder:
                            decoded = decoder(pattern['data'])
                            decoded_items.append({
                                'original': pattern['data'],
                                'decoded': decoded,
                                'encoding': encoding
                            })
                    except Exception:
                        pass
        return {'decoded_data': decoded_items}
    
    def identify_flags(patterns, decoded_data):
        # Combine all potential flags
        potential_flags = patterns.get('flags', [])
        
        # Check decoded data for flag patterns
        for item in decoded_data:
            if 'decoded' in item and re.search(r'flag\{[^}]+\}|CTF\{[^}]+\}', item['decoded'], re.IGNORECASE):
                potential_flags.append({
                    'data': item['decoded'],
                    'source': 'decoded_data',
                    'encoding': item.get('encoding')
                })
        
        return {'potential_flags': potential_flags}
    
    def run_ctf_analysis(packet_data_list, potential_flags, decoded_data):
        # Run the full CTF analyzer
        return ctf_analyzer.analyze(packet_data_list, challenge_type='network')
    
    # Add steps to the workflow
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Parse PCAP',
        'Parse PCAP file and extract packet data',
        parse_packets,
        ['pcap_file'],
        ['packet_data_list']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Search Patterns',
        'Search for common patterns in packet data',
        search_patterns,
        ['packet_data_list'],
        ['patterns']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Analyze HTTP',
        'Analyze HTTP traffic for hidden data',
        analyze_http,
        ['packet_data_list'],
        ['http_analysis']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Extract Patterns',
        'Extract patterns like first letters, text between markers, etc.',
        extract_patterns,
        ['packet_data_list', 'http_analysis'],
        ['extracted_patterns']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Decode Data',
        'Decode potential encoded data',
        decode_data,
        ['packet_data_list', 'extracted_patterns'],
        ['decoded_data']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Identify Flags',
        'Identify potential flags',
        identify_flags,
        ['patterns', 'decoded_data'],
        ['potential_flags']
    ))
    
    orchestrator.add_step('network_ctf', WorkflowStep(
        'Run CTF Analysis',
        'Run specialized CTF analysis',
        run_ctf_analysis,
        ['packet_data_list', 'potential_flags', 'decoded_data'],
        ['ctf_findings', 'hints', 'workflow_steps']
    ))
    
    return orchestrator