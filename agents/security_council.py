"""
Security Council - Variable-agent orchestration based on risk level.
Supports light mode (2 agents) and full mode (5 agents).
Returns unified AegisResponse format for consistency with production API.
"""
import os
import time
from typing import Optional, Literal

from dotenv import load_dotenv

from .schemas import (
    AgentAnalysis, 
    DebateResult, 
    DebateTranscript, 
    VoteRecord,
    AegisResponse,
    LatencyBreakdown,
    ScanResult,
    CouncilResult,
    AgentVote,
    OutputValidationResult,
    Explanation,
    RequestMetadata,
)
from .intent_analyst import IntentAnalyst
from .policy_auditor import PolicyAuditor
from .adversarial_tester import AdversarialTester
from .context_analyzer import ContextAnalyzer
from .data_guardian import DataGuardian
from .preprocessor import preprocess_prompt

load_dotenv()


class SecurityCouncil:
    
    def __init__(
        self,
        mode: Literal["light", "full"] = "light",
        max_turns: int = 5,
        timeout_seconds: float = 10.0,
        consensus_threshold: float = 0.7,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.mode = mode
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds
        self.consensus_threshold = consensus_threshold
        
        self.intent_analyst = IntentAnalyst(api_key=api_key, base_url=base_url, model=model)
        self.policy_auditor = PolicyAuditor(api_key=api_key, base_url=base_url, model=model)
        
        if mode == "full":
            self.adversarial_tester = AdversarialTester(api_key=api_key, base_url=base_url)
            self.context_analyzer = ContextAnalyzer(api_key=api_key, base_url=base_url)
            self.data_guardian = DataGuardian(api_key=api_key, base_url=base_url)
    
    def evaluate(self, prompt: str) -> AegisResponse:
        preprocessed_prompt, decodings = preprocess_prompt(prompt)
        
        if decodings:
            print(f"[PREPROCESSOR] Decoded: {', '.join(decodings)}")
        
        if self.mode == "light":
            return self._evaluate_light(preprocessed_prompt, decodings)
        else:
            return self._evaluate_full(preprocessed_prompt, decodings)
    
    def _evaluate_light(self, prompt: str, decodings: list[str]) -> AegisResponse:
        start_time = time.time()
        transcript = DebateTranscript()
        
        if decodings:
            transcript.add_message(
                agent="preprocessor",
                content=f"Applied decodings: {', '.join(decodings)}"
            )
        
        intent_analysis = self.intent_analyst.analyze(prompt)
        transcript.add_message(
            agent="intent_analyst",
            content=f"Assessment: {intent_analysis.assessment}\n"
                   f"Confidence: {intent_analysis.confidence}\n"
                   f"Reasoning: {intent_analysis.reasoning}"
        )
        
        policy_analysis = self.policy_auditor.audit(prompt, intent_analysis)
        transcript.add_message(
            agent="policy_auditor",
            content=f"Assessment: {policy_analysis.assessment}\n"
                   f"Confidence: {policy_analysis.confidence}\n"
                   f"Reasoning: {policy_analysis.reasoning}"
        )
        
        consensus_reached = self._check_consensus(intent_analysis, policy_analysis)
        
        verdict, confidence, reasoning = self._calculate_verdict(
            intent_analysis, 
            policy_analysis, 
            consensus_reached
        )
        
        camel_latency = int((time.time() - start_time) * 1000)
        
        return AegisResponse(
            decision="BLOCK" if verdict == "BLOCK" else "ALLOW",
            risk_score=confidence,
            route="LIGHT_CAMEL",
            latency_ms=LatencyBreakdown(
                camel_verification=camel_latency,
                total=camel_latency
            ),
            scan=ScanResult(),
            council=CouncilResult(
                agents=["intent_analyst", "policy_auditor"],
                rounds_completed=transcript.turn_count,
                consensus_reached=consensus_reached,
                consensus_score=confidence,
                votes=[
                    AgentVote(
                        agent="intent_analyst",
                        decision=intent_analysis.assessment,
                        confidence=intent_analysis.confidence,
                        reasoning=intent_analysis.reasoning
                    ),
                    AgentVote(
                        agent="policy_auditor",
                        decision=policy_analysis.assessment,
                        confidence=policy_analysis.confidence,
                        reasoning=policy_analysis.reasoning
                    )
                ]
            ),
            output_validation=OutputValidationResult(),
            explanation=Explanation(
                reason_code="CAMEL_BLOCK" if verdict == "BLOCK" else "CAMEL_ALLOW",
                triggered_layers=[1, 2, 3] if verdict == "BLOCK" else [],
                evidence=[
                    intent_analysis.reasoning[:100] + "...",
                    policy_analysis.reasoning[:100] + "..."
                ],
                human_summary=f"{'Blocked' if verdict == 'BLOCK' else 'Allowed'} by security council (2 agents, {transcript.turn_count} rounds)"
            ),
            metadata=RequestMetadata()
        )
    
    def _evaluate_full(self, prompt: str, decodings: list[str]) -> AegisResponse:
        start_time = time.time()
        transcript = DebateTranscript()
        vote_record = VoteRecord()
        
        if decodings:
            transcript.add_message(
                agent="preprocessor",
                content=f"Applied decodings: {', '.join(decodings)}"
            )
        
        print("[COUNCIL] Running full 5-agent mode")
        
        intent_analysis = self.intent_analyst.analyze(prompt)
        vote_record.add_vote(intent_analysis)
        transcript.add_message(
            agent="intent_analyst",
            content=f"Assessment: {intent_analysis.assessment}\n"
                   f"Confidence: {intent_analysis.confidence}\n"
                   f"Reasoning: {intent_analysis.reasoning}"
        )
        
        policy_analysis = self.policy_auditor.audit(prompt)
        vote_record.add_vote(policy_analysis)
        transcript.add_message(
            agent="policy_auditor",
            content=f"Assessment: {policy_analysis.assessment}\n"
                   f"Confidence: {policy_analysis.confidence}\n"
                   f"Reasoning: {policy_analysis.reasoning}"
        )
        
        adv_analysis = self.adversarial_tester.analyze(prompt)
        vote_record.add_vote(adv_analysis)
        transcript.add_message(
            agent="adversarial_tester",
            content=f"Assessment: {adv_analysis.assessment}\n"
                   f"Confidence: {adv_analysis.confidence}\n"
                   f"Reasoning: {adv_analysis.reasoning}"
        )
        
        ctx_analysis = self.context_analyzer.analyze(prompt)
        vote_record.add_vote(ctx_analysis)
        transcript.add_message(
            agent="context_analyzer",
            content=f"Assessment: {ctx_analysis.assessment}\n"
                   f"Confidence: {ctx_analysis.confidence}\n"
                   f"Reasoning: {ctx_analysis.reasoning}"
        )
        
        data_analysis = self.data_guardian.analyze(prompt)
        vote_record.add_vote(data_analysis)
        transcript.add_message(
            agent="data_guardian",
            content=f"Assessment: {data_analysis.assessment}\n"
                   f"Confidence: {data_analysis.confidence}\n"
                   f"Reasoning: {data_analysis.reasoning}"
        )
        
        majority_vote = vote_record.get_majority()
        consensus_count = vote_record.get_consensus_count()
        total_agents = len(vote_record.agent_analyses)
        
        print(f"[COUNCIL] Vote: {vote_record.vote_breakdown} | Majority: {majority_vote} ({consensus_count}/{total_agents})")
        
        consensus_reached = consensus_count >= 3
        
        if majority_vote == "SAFE":
            verdict = "ALLOW"
        else:
            verdict = "BLOCK"
        
        avg_confidence = sum(a.confidence for a in vote_record.agent_analyses) / len(vote_record.agent_analyses)
        
        camel_latency = int((time.time() - start_time) * 1000)
        
        return AegisResponse(
            decision="BLOCK" if verdict == "BLOCK" else "ALLOW",
            risk_score=avg_confidence,
            route="FULL_CAMEL",
            latency_ms=LatencyBreakdown(
                camel_verification=camel_latency,
                total=camel_latency
            ),
            scan=ScanResult(),
            council=CouncilResult(
                agents=[a.agent_name for a in vote_record.agent_analyses],
                rounds_completed=transcript.turn_count,
                consensus_reached=consensus_reached,
                consensus_score=avg_confidence,
                votes=[
                    AgentVote(
                        agent=a.agent_name,
                        decision=a.assessment,
                        confidence=a.confidence,
                        reasoning=a.reasoning
                    ) for a in vote_record.agent_analyses
                ]
            ),
            output_validation=OutputValidationResult(),
            explanation=Explanation(
                reason_code="CAMEL_BLOCK" if verdict == "BLOCK" else "CAMEL_ALLOW",
                triggered_layers=[1, 2, 3] if verdict == "BLOCK" else [],
                evidence=[a.reasoning[:100] + "..." for a in vote_record.agent_analyses[:3]],
                human_summary=f"{'Blocked' if verdict == 'BLOCK' else 'Allowed'} by security council (5 agents, {consensus_count}/{total_agents} consensus)"
            ),
            metadata=RequestMetadata()
        )
    
    def _check_consensus(
        self, 
        intent_analysis: AgentAnalysis, 
        policy_analysis: AgentAnalysis
    ) -> bool:
        if intent_analysis.assessment != policy_analysis.assessment:
            return False
        
        if intent_analysis.confidence < self.consensus_threshold:
            return False
        if policy_analysis.confidence < self.consensus_threshold:
            return False
        
        return True
    
    def _calculate_verdict(
        self,
        intent_analysis: AgentAnalysis,
        policy_analysis: AgentAnalysis,
        consensus_reached: bool
    ) -> tuple[str, float, str]:
        if consensus_reached:
            if intent_analysis.assessment == "SAFE":
                verdict = "ALLOW"
            else:
                verdict = "BLOCK"
            confidence = (intent_analysis.confidence + policy_analysis.confidence) / 2
            reasoning = (
                f"Consensus reached. Both agents agree: {intent_analysis.assessment}.\n\n"
                f"Intent Analyst: {intent_analysis.reasoning}\n\n"
                f"Policy Auditor: {policy_analysis.reasoning}"
            )
        else:
            if "UNSAFE" in [intent_analysis.assessment, policy_analysis.assessment]:
                verdict = "BLOCK"
                reasoning = (
                    f"No consensus. Defaulting to BLOCK due to safety concerns.\n\n"
                    f"Intent Analyst ({intent_analysis.assessment}): {intent_analysis.reasoning}\n\n"
                    f"Policy Auditor ({policy_analysis.assessment}): {policy_analysis.reasoning}"
                )
            elif "UNCERTAIN" in [intent_analysis.assessment, policy_analysis.assessment]:
                verdict = "BLOCK"
                reasoning = (
                    f"No consensus. Defaulting to BLOCK due to uncertainty.\n\n"
                    f"Intent Analyst ({intent_analysis.assessment}): {intent_analysis.reasoning}\n\n"
                    f"Policy Auditor ({policy_analysis.assessment}): {policy_analysis.reasoning}"
                )
            else:
                verdict = "ALLOW"
                reasoning = (
                    f"No formal consensus but both agents assess as SAFE.\n\n"
                    f"Intent Analyst: {intent_analysis.reasoning}\n\n"
                    f"Policy Auditor: {policy_analysis.reasoning}"
                )
            
            confidence = min(intent_analysis.confidence, policy_analysis.confidence) * 0.8
        
        return verdict, confidence, reasoning


def evaluate_prompt(prompt: str, **kwargs) -> AegisResponse:
    council = SecurityCouncil(**kwargs)
    return council.evaluate(prompt)
