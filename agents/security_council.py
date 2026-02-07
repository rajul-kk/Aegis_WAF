"""
Security Council - Orchestrates the debate between Intent Analyst and Policy Auditor.

Manages turn limits, consensus detection, and final verdict generation.
"""
import os
import time
from typing import Optional

from dotenv import load_dotenv

from .schemas import AgentAnalysis, DebateResult, DebateTranscript
from .intent_analyst import IntentAnalyst
from .policy_auditor import PolicyAuditor
from .preprocessor import preprocess_prompt

load_dotenv()


class SecurityCouncil:
    
    def __init__(
        self,
        max_turns: int = 5,
        timeout_seconds: float = 10.0,
        consensus_threshold: float = 0.7,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds
        self.consensus_threshold = consensus_threshold
        
        self.intent_analyst = IntentAnalyst(
            api_key=api_key,
            base_url=base_url,
            model=model,
        )
        self.policy_auditor = PolicyAuditor(
            api_key=api_key,
            base_url=base_url,
            model=model,
        )
    
    def evaluate(self, prompt: str) -> DebateResult:
        preprocessed_prompt, decodings = preprocess_prompt(prompt)
        
        if decodings:
            print(f"[PREPROCESSOR] Decoded: {', '.join(decodings)}")
        
        start_time = time.time()
        transcript = DebateTranscript()
        
        if decodings:
            transcript.add_message(
                agent="preprocessor",
                content=f"Applied decodings: {', '.join(decodings)}"
            )
        
        intent_analysis = self.intent_analyst.analyze(preprocessed_prompt)
        transcript.add_message(
            agent="intent_analyst",
            content=f"Assessment: {intent_analysis.assessment}\n"
                   f"Confidence: {intent_analysis.confidence}\n"
                   f"Reasoning: {intent_analysis.reasoning}"
        )
        
        policy_analysis = self.policy_auditor.audit(preprocessed_prompt, intent_analysis)
        transcript.add_message(
            agent="policy_auditor",
            content=f"Assessment: {policy_analysis.assessment}\n"
                   f"Confidence: {policy_analysis.confidence}\n"
                   f"Reasoning: {policy_analysis.reasoning}"
        )
        
        if self._check_consensus(intent_analysis, policy_analysis):
            return self._build_result(
                intent_analysis=intent_analysis,
                policy_analysis=policy_analysis,
                transcript=transcript,
                consensus_reached=True,
            )
        
        current_intent = intent_analysis
        current_policy = policy_analysis
        
        for turn in range(2, self.max_turns):
            if time.time() - start_time > self.timeout_seconds:
                break
            
            current_intent = self.intent_analyst.respond_to_auditor(prompt, current_policy)
            transcript.add_message(
                agent="intent_analyst",
                content=f"Assessment: {current_intent.assessment}\n"
                       f"Confidence: {current_intent.confidence}\n"
                       f"Reasoning: {current_intent.reasoning}"
            )
            
            if self._check_consensus(current_intent, current_policy):
                return self._build_result(
                    intent_analysis=current_intent,
                    policy_analysis=current_policy,
                    transcript=transcript,
                    consensus_reached=True,
                )
            
            if time.time() - start_time > self.timeout_seconds:
                break
            
            current_policy = self.policy_auditor.respond_to_analyst(prompt, current_intent)
            transcript.add_message(
                agent="policy_auditor",
                content=f"Assessment: {current_policy.assessment}\n"
                       f"Confidence: {current_policy.confidence}\n"
                       f"Reasoning: {current_policy.reasoning}"
            )
            
            if self._check_consensus(current_intent, current_policy):
                return self._build_result(
                    intent_analysis=current_intent,
                    policy_analysis=current_policy,
                    transcript=transcript,
                    consensus_reached=True,
                )
        
        return self._build_result(
            intent_analysis=current_intent,
            policy_analysis=current_policy,
            transcript=transcript,
            consensus_reached=False,
        )
    
    def _check_consensus(
        self, 
        intent_analysis: AgentAnalysis, 
        policy_analysis: AgentAnalysis
    ) -> bool:
        """Check if agents have reached consensus."""
        if intent_analysis.assessment != policy_analysis.assessment:
            return False
        
        if intent_analysis.confidence < self.consensus_threshold:
            return False
        if policy_analysis.confidence < self.consensus_threshold:
            return False
        
        return True
    
    def _build_result(
        self,
        intent_analysis: AgentAnalysis,
        policy_analysis: AgentAnalysis,
        transcript: DebateTranscript,
        consensus_reached: bool,
    ) -> DebateResult:
        """Build the final debate result."""
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
        
        return DebateResult(
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            transcript=transcript,
            intent_analysis=intent_analysis,
            policy_analysis=policy_analysis,
            consensus_reached=consensus_reached,
            turns_used=transcript.turn_count,
        )


def evaluate_prompt(prompt: str, **kwargs) -> DebateResult:
    council = SecurityCouncil(**kwargs)
    return council.evaluate(prompt)
