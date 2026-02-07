"""
Pydantic schemas for agent communication and debate results.
"""
from datetime import datetime, timezone
from typing import Literal, Optional
import uuid

from pydantic import BaseModel, Field


class AgentMessage(BaseModel):
    """Single message in the debate transcript."""
    agent: str = Field(..., description="Name of the agent (intent_analyst or policy_auditor)")
    content: str = Field(..., description="Message content")
    timestamp: datetime = Field(default_factory=datetime.now)
    
    
class DebateTranscript(BaseModel):
    """Full debate history between agents."""
    messages: list[AgentMessage] = Field(default_factory=list)
    turn_count: int = Field(default=0)
    
    def add_message(self, agent: str, content: str) -> None:
        self.messages.append(AgentMessage(agent=agent, content=content))
        self.turn_count += 1


class RiskAssessment(BaseModel):
    """Risk assessment from Llama Guard."""
    score: float = Field(..., ge=0.0, le=1.0, description="Risk score 0.0-1.0")
    category: Optional[str] = Field(None, description="Threat category if detected")
    is_safe: bool = Field(..., description="Whether the prompt is safe")
    raw_response: Optional[str] = Field(None, description="Raw model response")


class AgentAnalysis(BaseModel):
    """Analysis output from an individual agent."""
    agent_name: str
    assessment: Literal["SAFE", "UNSAFE", "UNCERTAIN"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    concerns: list[str] = Field(default_factory=list)


class DebateResult(BaseModel):
    """Final verdict from the Security Council."""
    verdict: Literal["ALLOW", "BLOCK"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    transcript: DebateTranscript
    intent_analysis: Optional[AgentAnalysis] = None
    policy_analysis: Optional[AgentAnalysis] = None
    vote_record: Optional["VoteRecord"] = None
    mode: Literal["light", "full"] = Field(default="light")
    consensus_reached: bool = Field(default=False)
    turns_used: int = Field(default=0)


# =============================================================================
# Unified Aegis WAF Response Schema (verification-schema.json)
# =============================================================================

class LatencyBreakdown(BaseModel):
    """Per-layer latency in milliseconds."""
    fast_scan: int = 0
    intent_classification: int = 0
    camel_verification: int = 0
    output_validation: int = 0
    session_update: int = 0
    total: int = 0


class ScanResult(BaseModel):
    """Layer 1 fast scan results."""
    patterns_checked: int = 0
    patterns_matched: list[str] = Field(default_factory=list)
    entropy_flag: bool = False


class AgentVote(BaseModel):
    """Individual agent vote within the security council."""
    agent: str
    decision: str
    confidence: float = 0.0
    reasoning: str = ""


class CouncilResult(BaseModel):
    """CAMEL debate / security council results."""
    agents: list[str] = Field(default_factory=list)
    rounds_completed: int = 0
    consensus_reached: Optional[bool] = None
    consensus_score: Optional[float] = None
    votes: list[AgentVote] = Field(default_factory=list)


class OutputValidationResult(BaseModel):
    """Layer 3.5 output validation results."""
    pii_scrubbed: bool = False
    secrets_detected: bool = False
    tools_blocked: list[str] = Field(default_factory=list)
    modifications: list[str] = Field(default_factory=list)


class Explanation(BaseModel):
    """Human-readable explanation of the decision."""
    reason_code: str = "CLEAN"
    triggered_layers: list[int] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    human_summary: str = ""
    suggestion: Optional[str] = None


class RequestMetadata(BaseModel):
    """Request tracking metadata."""
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    session_id: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    waf_version: str = "1.0.0"


class AegisResponse(BaseModel):
    """Unified response schema for all Aegis WAF tiers."""
    decision: Literal["ALLOW", "BLOCK", "SANITIZED"] = "ALLOW"
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    route: Literal["FAST_TRACK", "LIGHT_CAMEL", "FULL_CAMEL"] = "FAST_TRACK"
    latency_ms: LatencyBreakdown = Field(default_factory=LatencyBreakdown)
    scan: ScanResult = Field(default_factory=ScanResult)
    council: CouncilResult = Field(default_factory=CouncilResult)
    output_validation: OutputValidationResult = Field(default_factory=OutputValidationResult)
    explanation: Explanation = Field(default_factory=Explanation)
    metadata: RequestMetadata = Field(default_factory=RequestMetadata)
class VoteRecord(BaseModel):
    agent_analyses: list[AgentAnalysis] = Field(default_factory=list)
    vote_breakdown: dict[str, int] = Field(default_factory=dict)
    
    def add_vote(self, analysis: AgentAnalysis) -> None:
        self.agent_analyses.append(analysis)
        self.vote_breakdown[analysis.assessment] = self.vote_breakdown.get(analysis.assessment, 0) + 1
    
    def get_majority(self) -> Optional[str]:
        if not self.vote_breakdown:
            return None
        return max(self.vote_breakdown, key=self.vote_breakdown.get)
    
    def get_consensus_count(self) -> int:
        if not self.vote_breakdown:
            return 0
        return max(self.vote_breakdown.values())

