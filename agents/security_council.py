"""
Security Council - Variable-agent orchestration based on risk level.
Supports light mode (2 agents) and full mode (5 agents).
"""
import os
import time
from typing import Optional, Literal

from dotenv import load_dotenv

from .schemas import AgentAnalysis, DebateResult, DebateTranscript, VoteRecord
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
    
    def evaluate(self, prompt: str) -> DebateResult:
        preprocessed_prompt, decodings = preprocess_prompt(prompt)
        
        if decodings:
            print(f"[PREPROCESSOR] Decoded: {', '.join(decodings)}")
        
        if self.mode == "light":
            return self._evaluate_light(preprocessed_prompt, decodings)
        else:
            return self._evaluate_full(preprocessed_prompt, decodings)
    
    def _evaluate_light(self, prompt: str, decodings: list[str]) -> DebateResult:
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
        
        if self._check_consensus(intent_analysis, policy_analysis):
            return self._build_result(
                intent_analysis=intent_analysis,
                policy_analysis=policy_analysis,
                transcript=transcript,
                consensus_reached=True,
                mode="light"
            )
        
        return self._build_result(
            intent_analysis=intent_analysis,
            policy_analysis=policy_analysis,
            transcript=transcript,
            consensus_reached=False,
            mode="light"
        )
    
    def _evaluate_full(self, prompt: str, decodings: list[str]) -> DebateResult:
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
        
        reasoning = self._build_full_reasoning(vote_record, majority_vote, consensus_reached)
        
        return DebateResult(
            verdict=verdict,
            confidence=avg_confidence,
            reasoning=reasoning,
            transcript=transcript,
            vote_record=vote_record,
            consensus_reached=consensus_reached,
            turns_used=transcript.turn_count,
            mode="full"
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
    
    def _build_result(
        self,
        intent_analysis: AgentAnalysis,
        policy_analysis: AgentAnalysis,
        transcript: DebateTranscript,
        consensus_reached: bool,
        mode: Literal["light", "full"]
    ) -> DebateResult:
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
            mode=mode
        )
    
    def _build_full_reasoning(self, vote_record: VoteRecord, majority: str, consensus: bool) -> str:
        lines = []
        lines.append(f"5-Agent Council Vote: {vote_record.vote_breakdown}")
        lines.append(f"Majority Decision: {majority}")
        lines.append(f"Consensus: {'Yes' if consensus else 'No'} ({vote_record.get_consensus_count()}/5 agents agree)")
        lines.append("")
        
        for analysis in vote_record.agent_analyses:
            lines.append(f"**{analysis.agent_name.upper()}** [{analysis.assessment}, {analysis.confidence:.2f}]")
            lines.append(f"{analysis.reasoning[:200]}...")
            lines.append("")
        
        return "\n".join(lines)


def evaluate_prompt(prompt: str, **kwargs) -> DebateResult:
    council = SecurityCouncil(**kwargs)
    return council.evaluate(prompt)
