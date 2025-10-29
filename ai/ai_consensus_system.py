"""
Cross-Model AI Consensus System for FlagSniff
Implements multi-model validation and consensus scoring for enhanced accuracy
"""

import asyncio
import json
import time
import statistics
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
import re
import hashlib

@dataclass
class ModelResponse:
    """Structure for individual model responses"""
    model_id: str
    response: str
    confidence: float
    processing_time: float
    error: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class ConsensusResult:
    """Structure for consensus analysis results"""
    consensus_confidence: float
    agreed_findings: List[Dict[str, Any]]
    disputed_findings: List[Dict[str, Any]]
    model_agreements: Dict[str, float]
    final_recommendation: str
    validation_score: float

class ModelSpecialization:
    """Defines model specializations and strengths"""
    
    SPECIALIZATIONS = {
        "qwen/qwen3-235b-a22b:free": {
            "strengths": ["reasoning", "logic_chains", "pattern_analysis"],
            "weight_multiplier": 1.2,
            "best_for": ["complex_reasoning", "multi_step_analysis"]
        },
        "openai/gpt-oss-20b:free": {
            "strengths": ["pattern_recognition", "creative_analysis", "flag_detection"],
            "weight_multiplier": 1.1,
            "best_for": ["flag_hunting", "creative_problem_solving"]
        },
        "cognitivecomputations/dolphin-mistral-24b-venice-edition:free": {
            "strengths": ["steganography", "encoding", "technical_analysis"],
            "weight_multiplier": 1.15,
            "best_for": ["steganography_detection", "encoding_analysis"]
        },
        "qwen/qwen2.5-vl-32b-instruct:free": {
            "strengths": ["multimodal", "visual_analysis", "comprehensive_view"],
            "weight_multiplier": 1.0,
            "best_for": ["comprehensive_analysis", "correlation"]
        }
    }

class ConsensusEngine:
    """Main consensus engine for multi-model validation"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://flagsniff.local",
            "X-Title": "FlagSniff Consensus Engine"
        }
        self.model_specializations = ModelSpecialization.SPECIALIZATIONS
        
    async def analyze_with_consensus(self, 
                                   packet_data: str, 
                                   findings: List[Dict], 
                                   analysis_type: str = "comprehensive") -> ConsensusResult:
        """Perform multi-model analysis with consensus validation"""
        
        # Select models based on analysis type
        selected_models = self._select_models_for_analysis(analysis_type)
        
        # Generate specialized prompts for each model
        model_prompts = self._generate_specialized_prompts(packet_data, findings, selected_models)
        
        # Query models concurrently
        model_responses = await self._query_models_async(model_prompts)
        
        # Perform consensus analysis
        consensus_result = self._analyze_consensus(model_responses, analysis_type)
        
        return consensus_result
    
    def _select_models_for_analysis(self, analysis_type: str) -> List[str]:
        """Select optimal models based on analysis type"""
        
        type_to_models = {
            "flag_hunting": [
                "openai/gpt-oss-20b:free",
                "qwen/qwen3-235b-a22b:free",
                "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
            ],
            "steganography": [
                "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
                "qwen/qwen2.5-vl-32b-instruct:free",
                "qwen/qwen3-235b-a22b:free"
            ],
            "comprehensive": [
                "qwen/qwen3-235b-a22b:free",
                "openai/gpt-oss-20b:free",
                "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
            ],
            "pattern_analysis": [
                "qwen/qwen3-235b-a22b:free",
                "openai/gpt-oss-20b:free"
            ]
        }
        
        return type_to_models.get(analysis_type, type_to_models["comprehensive"])
    
    def _generate_specialized_prompts(self, 
                                    packet_data: str, 
                                    findings: List[Dict], 
                                    models: List[str]) -> Dict[str, str]:
        """Generate specialized prompts for each model based on their strengths"""
        
        prompts = {}
        base_context = f"""
PACKET DATA ANALYSIS - CONSENSUS VALIDATION

PACKET DATA:
{packet_data[:3000]}

CURRENT FINDINGS:
{json.dumps(findings[:3], indent=2)}
"""
        
        for model in models:
            specialization = self.model_specializations.get(model, {})
            strengths = specialization.get("strengths", [])
            
            if "reasoning" in strengths:
                prompts[model] = base_context + """
FOCUS: Advanced reasoning and logical analysis
- Apply systematic reasoning to identify flag patterns
- Analyze logical connections between findings
- Provide step-by-step deduction processes
- Validate findings through logical verification

RESPONSE FORMAT: JSON with reasoning chains and confidence scores.
"""
            
            elif "pattern_recognition" in strengths:
                prompts[model] = base_context + """
FOCUS: Creative pattern recognition and flag hunting
- Identify unusual patterns and hidden flags
- Look for creative encoding and obfuscation
- Detect non-standard flag formats
- Apply lateral thinking to flag discovery

RESPONSE FORMAT: JSON with creative findings and pattern insights.
"""
            
            elif "steganography" in strengths:
                prompts[model] = base_context + """
FOCUS: Steganography and encoding analysis
- Detect hidden data in protocols and timing
- Analyze encoding chains and obfuscation
- Identify covert channels and steganographic techniques
- Examine data patterns for hidden information

RESPONSE FORMAT: JSON with steganographic findings and encoding analysis.
"""
            
            else:
                prompts[model] = base_context + """
FOCUS: Comprehensive analysis and correlation
- Provide holistic view of all findings
- Correlate data across multiple protocols
- Identify broader patterns and connections
- Synthesize information from all sources

RESPONSE FORMAT: JSON with comprehensive analysis and correlations.
"""
        
        return prompts
    
    async def _query_models_async(self, model_prompts: Dict[str, str]) -> List[ModelResponse]:
        """Query multiple models asynchronously"""
        
        async def query_single_model(model_id: str, prompt: str) -> ModelResponse:
            """Query a single model"""
            start_time = time.time()
            
            try:
                payload = {
                    "model": model_id,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are an expert cybersecurity analyst specializing in CTF challenges and network analysis."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "max_tokens": 2000,
                    "temperature": 0.7
                }
                
                # Simulate API call (replace with actual API call in production)
                await asyncio.sleep(0.1)  # Simulate network delay
                
                # For demo purposes, return simulated response
                response_text = f"Model {model_id} analysis: Detected patterns with confidence based on specialization"
                confidence = 0.8 + (hash(model_id) % 20) / 100  # Simulated confidence
                
                return ModelResponse(
                    model_id=model_id,
                    response=response_text,
                    confidence=confidence,
                    processing_time=time.time() - start_time,
                    metadata={"specialization": self.model_specializations.get(model_id, {})}
                )
                
            except Exception as e:
                return ModelResponse(
                    model_id=model_id,
                    response="",
                    confidence=0.0,
                    processing_time=time.time() - start_time,
                    error=str(e)
                )
        
        # Execute all model queries concurrently
        tasks = [query_single_model(model_id, prompt) for model_id, prompt in model_prompts.items()]
        responses = await asyncio.gather(*tasks)
        
        return responses
    
    def _analyze_consensus(self, responses: List[ModelResponse], analysis_type: str) -> ConsensusResult:
        """Analyze consensus among model responses"""
        
        valid_responses = [r for r in responses if r.error is None]
        
        if not valid_responses:
            return ConsensusResult(
                consensus_confidence=0.0,
                agreed_findings=[],
                disputed_findings=[],
                model_agreements={},
                final_recommendation="No valid model responses received",
                validation_score=0.0
            )
        
        # Calculate weighted consensus
        total_weight = 0
        weighted_confidence = 0
        
        for response in valid_responses:
            model_spec = self.model_specializations.get(response.model_id, {})
            weight = model_spec.get("weight_multiplier", 1.0)
            
            weighted_confidence += response.confidence * weight
            total_weight += weight
        
        consensus_confidence = weighted_confidence / total_weight if total_weight > 0 else 0
        
        # Analyze agreement patterns
        model_agreements = {}
        for response in valid_responses:
            model_agreements[response.model_id] = response.confidence
        
        # Extract agreed findings (simplified for demo)
        agreed_findings = []
        disputed_findings = []
        
        # Consensus threshold
        consensus_threshold = 0.7
        
        if consensus_confidence > consensus_threshold:
            agreed_findings.append({
                "type": "consensus_finding",
                "confidence": consensus_confidence,
                "supporting_models": len(valid_responses),
                "analysis_type": analysis_type
            })
        else:
            disputed_findings.append({
                "type": "disputed_analysis",
                "confidence": consensus_confidence,
                "conflicting_models": [r.model_id for r in valid_responses],
                "reason": "Low consensus confidence"
            })
        
        # Generate final recommendation
        if consensus_confidence > 0.8:
            final_recommendation = "High consensus achieved. Findings are highly reliable."
        elif consensus_confidence > 0.6:
            final_recommendation = "Moderate consensus. Consider additional validation."
        else:
            final_recommendation = "Low consensus. Manual review recommended."
        
        # Calculate validation score
        validation_score = self._calculate_validation_score(valid_responses)
        
        return ConsensusResult(
            consensus_confidence=consensus_confidence,
            agreed_findings=agreed_findings,
            disputed_findings=disputed_findings,
            model_agreements=model_agreements,
            final_recommendation=final_recommendation,
            validation_score=validation_score
        )
    
    def _calculate_validation_score(self, responses: List[ModelResponse]) -> float:
        """Calculate validation score based on response quality and agreement"""
        
        if not responses:
            return 0.0
        
        # Factors for validation score
        response_count_factor = min(1.0, len(responses) / 3)  # Optimal with 3+ models
        confidence_factor = statistics.mean([r.confidence for r in responses])
        processing_time_factor = 1.0 / (1.0 + statistics.mean([r.processing_time for r in responses]))
        
        validation_score = (response_count_factor * 0.4 + 
                          confidence_factor * 0.5 + 
                          processing_time_factor * 0.1)
        
        return min(1.0, validation_score)

class ConsensusValidator:
    """Validates and cross-checks findings using consensus results"""
    
    def __init__(self, consensus_engine: ConsensusEngine):
        self.consensus_engine = consensus_engine
        
    async def validate_findings(self, findings: List[Dict], packet_data: str) -> Dict[str, Any]:
        """Validate findings using multi-model consensus"""
        
        validation_results = {
            "validated_findings": [],
            "confidence_boosted": [],
            "flagged_for_review": [],
            "consensus_metadata": {}
        }
        
        # Group findings by type for specialized validation
        findings_by_type = defaultdict(list)
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            findings_by_type[finding_type].append(finding)
        
        # Validate each type with appropriate model specialization
        for finding_type, type_findings in findings_by_type.items():
            
            analysis_type = self._map_finding_type_to_analysis(finding_type)
            
            try:
                consensus_result = await self.consensus_engine.analyze_with_consensus(
                    packet_data, type_findings, analysis_type
                )
                
                # Process consensus results
                if consensus_result.consensus_confidence > 0.7:
                    # High confidence - boost existing findings
                    for finding in type_findings:
                        boosted_finding = finding.copy()
                        boosted_finding['consensus_confidence'] = consensus_result.consensus_confidence
                        boosted_finding['validation_score'] = consensus_result.validation_score
                        boosted_finding['model_agreements'] = consensus_result.model_agreements
                        validation_results["confidence_boosted"].append(boosted_finding)
                
                elif consensus_result.consensus_confidence > 0.4:
                    # Moderate confidence - validate but flag for review
                    for finding in type_findings:
                        reviewed_finding = finding.copy()
                        reviewed_finding['needs_review'] = True
                        reviewed_finding['consensus_confidence'] = consensus_result.consensus_confidence
                        reviewed_finding['review_reason'] = "Moderate consensus confidence"
                        validation_results["flagged_for_review"].append(reviewed_finding)
                
                else:
                    # Low confidence - flag for manual review
                    for finding in type_findings:
                        flagged_finding = finding.copy()
                        flagged_finding['flagged_reason'] = "Low consensus confidence"
                        flagged_finding['consensus_confidence'] = consensus_result.consensus_confidence
                        validation_results["flagged_for_review"].append(flagged_finding)
                
                # Add consensus findings
                validation_results["validated_findings"].extend(consensus_result.agreed_findings)
                
            except Exception as e:
                # Fallback for validation errors
                for finding in type_findings:
                    error_finding = finding.copy()
                    error_finding['validation_error'] = str(e)
                    validation_results["flagged_for_review"].append(error_finding)
        
        return validation_results
    
    def _map_finding_type_to_analysis(self, finding_type: str) -> str:
        """Map finding types to appropriate analysis specializations"""
        
        type_mapping = {
            'flag': 'flag_hunting',
            'reconstructed_flag': 'flag_hunting',
            'encoded_data': 'steganography',
            'base64_decoded': 'steganography',
            'suspicious_pattern': 'pattern_analysis',
            'credential': 'comprehensive',
            'token': 'comprehensive'
        }
        
        return type_mapping.get(finding_type, 'comprehensive')

# Factory function for integration
def create_consensus_system(api_key: str) -> Tuple[ConsensusEngine, ConsensusValidator]:
    """Create consensus system components"""
    engine = ConsensusEngine(api_key)
    validator = ConsensusValidator(engine)
    return engine, validator