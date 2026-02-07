"""
Aegis_WAF Multi-Agent Security System

This package provides a CAMEL-AI based multi-agent debate system for
evaluating user prompts for security threats and policy compliance.

Components:
- IntentAnalyst: Adversarial reasoning agent for detecting malicious intent
- PolicyAuditor: Compliance agent for policy enforcement  
- SecurityCouncil: Orchestrator managing the debate and final verdict
"""

from .schemas import (
    AgentMessage,
    AgentAnalysis,
    DebateTranscript,
    DebateResult,
    RiskAssessment,
    LatencyBreakdown,
    ScanResult,
    AgentVote,
    CouncilResult,
    OutputValidationResult,
    Explanation,
    RequestMetadata,
    AegisResponse,
)
from .intent_analyst import IntentAnalyst
from .policy_auditor import PolicyAuditor
from .security_council import SecurityCouncil, evaluate_prompt

__all__ = [
    "AgentMessage",
    "AgentAnalysis",
    "DebateTranscript",
    "DebateResult",
    "RiskAssessment",
    "LatencyBreakdown",
    "ScanResult",
    "AgentVote",
    "CouncilResult",
    "OutputValidationResult",
    "Explanation",
    "RequestMetadata",
    "AegisResponse",
    "IntentAnalyst",
    "PolicyAuditor",
    "SecurityCouncil",
    "evaluate_prompt",
]
