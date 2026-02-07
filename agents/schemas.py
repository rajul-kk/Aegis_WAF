"""
Pydantic schemas for agent communication and debate results.
"""
from datetime import datetime
from typing import Literal, Optional
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
    consensus_reached: bool = Field(default=False)
    turns_used: int = Field(default=0)
