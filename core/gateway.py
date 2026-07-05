import sys
import os
import threading
import time
from typing import Dict, List, Optional

# Fix path for both module and standalone execution
_dir = os.path.dirname(__file__)
if _dir not in sys.path:
    sys.path.insert(0, _dir)
if os.path.join(_dir, '..') not in sys.path:
    sys.path.insert(0, os.path.join(_dir, '..'))

from openai import OpenAI
from dotenv import load_dotenv
from agents.schemas import (
    AegisResponse, LatencyBreakdown, ScanResult, CouncilResult,
    OutputValidationResult, Explanation, RequestMetadata, AgentVote
)
from agents.security_council import SecurityCouncil
from config.actions import scan_text
from severity import calculate_risk_from_patterns, get_risk_score, get_category_name
from classifiers import LlamaGuardClassifier

load_dotenv()


from agents.preprocessor import preprocess_prompt

# ============== Session History (for context_analyzer) ==============
# In-memory, per-process store so context_analyzer's behavioral/multi-turn
# analysis has real history to compare against instead of always seeing a
# single isolated prompt. Module-level (not per-AegisGateway) so history
# survives across the aegis() convenience function's gateway instances too.
# NOTE: process-local only - lost on restart, not shared across workers.
# A real deployment would back this with Redis/a DB instead.
_SESSION_HISTORY: Dict[str, List[str]] = {}
_SESSION_HISTORY_LOCK = threading.Lock()
_MAX_HISTORY_PER_SESSION = 10


def _get_session_history(session_id: str) -> List[str]:
    if not session_id:
        return []
    with _SESSION_HISTORY_LOCK:
        return list(_SESSION_HISTORY.get(session_id, []))


def _record_session_turn(session_id: str, prompt: str) -> None:
    if not session_id:
        return
    with _SESSION_HISTORY_LOCK:
        history = _SESSION_HISTORY.setdefault(session_id, [])
        history.append(prompt)
        del history[:-_MAX_HISTORY_PER_SESSION]


# ============== Scanner Functions (from scanner.py) ==============

def fast_scan(text: str) -> Dict[str, object]:
    findings = scan_text(text, enable_heuristics=False)
    
    pattern_ids: List[str] = []
    entropy_flag = False
    
    for f in findings:
        rid = f.get("rule_id", "")
        if rid == "anomaly_high_entropy":
            entropy_flag = True
        
        # Include ALL pattern IDs in risk calculation, including heuristics
        pattern_ids.append(rid)
    
    risk_score = calculate_risk_from_patterns(pattern_ids)
    blocked = len(findings) > 0
    reason = findings[0].get("description", "") if findings else ""
    
    return {
        "blocked": blocked,
        "reason": reason,
        "risk_score": risk_score,
        "patterns_matched": pattern_ids,
        "patterns_checked": 35,
        "entropy_flag": entropy_flag,
        "findings": findings
    }


def to_scan_result(scan_data: Dict[str, object], decodings: List[str] = None) -> ScanResult:
    return ScanResult(
        patterns_checked=scan_data.get("patterns_checked", 0),
        patterns_matched=scan_data.get("patterns_matched", []),
        decodings=decodings or [],
        entropy_flag=scan_data.get("entropy_flag", False)
    )


# ============== Gateway Class ==============

class AegisGateway:
    def __init__(self, enable_llm: bool = True):
        self.classifier = LlamaGuardClassifier()
        self.enable_llm = enable_llm
        # Built once and reused across requests: each holds several OpenAI
        # clients, and constructing them fresh per request was pure overhead.
        self.full_council = SecurityCouncil(mode="full")
        self.light_council = SecurityCouncil(mode="light")

        if enable_llm:
            api_key = os.getenv("GROQ_API_KEY")
            if api_key:
                self.llm_client = OpenAI(
                    api_key=api_key,
                    base_url="https://api.groq.com/openai/v1",
                    timeout=30.0,
                    max_retries=1,
                )
                self.llm_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
            else:
                self.llm_client = None
                self.llm_model = None
        else:
            self.llm_client = None
            self.llm_model = None
    
    def process(self, prompt: str, session_id: str = "", context: str = "") -> AegisResponse:
        total_start = time.time()
        latency = LatencyBreakdown()

        # Indirect injection (RAG/tool-output poisoning) hides malicious
        # instructions in retrieved context rather than the user's own prompt,
        # so context must be scanned/classified alongside prompt, not ignored.
        analysis_target = f"{prompt}\n\n[RETRIEVED CONTEXT]:\n{context}" if context else prompt

        # Snapshot prior turns before recording this one, so context_analyzer
        # (Layer 3) can compare this prompt against what came before it in the
        # session, not see itself as part of its own history.
        session_history = _get_session_history(session_id)
        _record_session_turn(session_id, prompt)

        # Preprocessing Layer (0)
        # Decode any obfuscation (Base64, Rot13, etc.)
        preprocessed_prompt, decodings = preprocess_prompt(analysis_target)
        # Use preprocessed text for security scans to catch hidden attacks
        scan_target = preprocessed_prompt if decodings else analysis_target
        
        # Layer 1: Fast Scanner
        scan_start = time.time()
        scan_result = fast_scan(scan_target)
        latency.fast_scan = int((time.time() - scan_start) * 1000)
        
        if scan_result["blocked"]:
            latency.total = int((time.time() - total_start) * 1000)
            return AegisResponse(
                decision="BLOCK",
                risk_score=scan_result["risk_score"],
                route="FAST_TRACK",
                latency_ms=latency,
                scan=to_scan_result(scan_result, decodings),
                council=CouncilResult(),
                output_validation=OutputValidationResult(),
                explanation=Explanation(
                    reason_code="FAST_SCAN_BLOCK",
                    triggered_layers=[1],
                    evidence=[scan_result["reason"]],
                    human_summary=f"Blocked by fast scanner: {scan_result['reason']}"
                ),
                metadata=RequestMetadata(session_id=session_id)
            )
        
        # Layer 2: Llama Guard Classification
        classify_start = time.time()
        # Classify prompt + retrieved context together. Pass the already-computed
        # preprocessed text so the classifier doesn't redo the same decoding pass.
        risk_assessment = self.classifier.classify(analysis_target, preprocessed=preprocessed_prompt)
        latency.intent_classification = int((time.time() - classify_start) * 1000)
        
        risk_score = risk_assessment.score
        
        # Show Llama Guard result
        route = "FAST_TRACK" if risk_score < 0.30 else ("FULL_CAMEL" if risk_score <= 0.70 else "LIGHT_CAMEL")
        if risk_score >= 0.99:
            route = "IMMEDIATE_BLOCK"
        print(f"[LLAMA_GUARD] Risk={risk_score:.3f} → {route}")
        
        # Layer 3: Risk-based Routing
        if risk_score >= 0.99:
            # Immediate Block (Zero Tolerance)
            latency.total = int((time.time() - total_start) * 1000)
            return AegisResponse(
                decision="BLOCK",
                risk_score=risk_score,
                route="IMMEDIATE_BLOCK",
                latency_ms=latency,
                scan=to_scan_result(scan_result, decodings),
                council=CouncilResult(),
                output_validation=OutputValidationResult(),
                explanation=Explanation(
                    reason_code="ZERO_TOLERANCE",
                    triggered_layers=[2],
                    evidence=[f"Llama Guard detected high-risk category (score: {risk_score:.2f})"],
                    human_summary=f"Blocked immediately by Llama Guard (Zero Tolerance)"
                ),
                metadata=RequestMetadata(session_id=session_id)
            )
            
        if risk_score < 0.30:
            latency.total = int((time.time() - total_start) * 1000)
            return AegisResponse(
                decision="ALLOW",
                risk_score=risk_score,
                route="FAST_TRACK",
                latency_ms=latency,
                scan=to_scan_result(scan_result, decodings),
                council=CouncilResult(),
                output_validation=OutputValidationResult(),
                explanation=Explanation(
                    reason_code="LOW_RISK",
                    triggered_layers=[],
                    evidence=[],
                    human_summary=f"Low risk (score: {risk_score:.2f}), fast-tracked"
                ),
                metadata=RequestMetadata(session_id=session_id)
            )
        
        elif risk_score <= 0.70:
            camel_start = time.time()
            camel_response = self.full_council.evaluate(
                analysis_target,
                preprocessed=preprocessed_prompt,
                decodings=decodings,
                session_history=session_history,
            )
            latency.camel_verification = int((time.time() - camel_start) * 1000)
            latency.total = int((time.time() - total_start) * 1000)

            camel_response.latency_ms = latency
            camel_response.scan = to_scan_result(scan_result, decodings)
            camel_response.metadata.session_id = session_id
            return camel_response

        else:
            camel_start = time.time()
            camel_response = self.light_council.evaluate(
                analysis_target,
                preprocessed=preprocessed_prompt,
                decodings=decodings,
            )
            latency.camel_verification = int((time.time() - camel_start) * 1000)
            latency.total = int((time.time() - total_start) * 1000)

            camel_response.latency_ms = latency
            camel_response.scan = to_scan_result(scan_result, decodings)
            camel_response.metadata.session_id = session_id
            return camel_response
    
    def chat(self, prompt: str, session_id: str = "", max_tokens: int = 1024, context: str = "") -> dict:
        waf_result = self.process(prompt, session_id, context=context)
        waf_dict = waf_result.model_dump()
        
        latency_breakdown = {
            "fast_scan": waf_result.latency_ms.fast_scan,
            "intent_classification": waf_result.latency_ms.intent_classification,
            "camel_verification": waf_result.latency_ms.camel_verification,
            "total": waf_result.latency_ms.total
        }
        
        if waf_result.decision == "BLOCK":
            return {
                "blocked": True,
                "response": None,
                "risk_score": waf_result.risk_score,
                "route": waf_result.route,
                "explanation": waf_result.explanation.human_summary,
                "latency_ms": waf_result.latency_ms.total,
                "latency_breakdown": latency_breakdown,
                "waf_result": waf_dict
            }

        if not self.llm_client:
            return {
                "blocked": False,
                "response": "[LLM not configured - set GROQ_API_KEY in .env]",
                "risk_score": waf_result.risk_score,
                "route": waf_result.route,
                "latency_ms": waf_result.latency_ms.total,
                "latency_breakdown": latency_breakdown,
                "waf_result": waf_dict
            }
        
        llm_start = time.time()
        response = self.llm_client.chat.completions.create(
            model=self.llm_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.7
        )
        llm_latency = int((time.time() - llm_start) * 1000)
        
        llm_content = response.choices[0].message.content
        output_blocked = False
        output_reason = ""
        output_val_start = time.time()
        
        # Risk-based Output Validation
        input_risk = waf_result.risk_score
        
        if 0.3 <= input_risk <= 0.7:
            # Medium Risk: Regex Scan
            scan_out = fast_scan(llm_content)
            if scan_out["blocked"]:
                output_blocked = True
                output_reason = f"Output blocked by Fast Scanner: {scan_out['reason']}"
                llm_content = f"[CLOAKED] {output_reason}"
                print(f"[OUTPUT_VAL] Blocked by Regex (Risk: {input_risk:.2f})")
                
        elif input_risk > 0.7:
            # High Risk: Llama Guard
            risk_out = self.classifier.classify(llm_content)
            if not risk_out.is_safe:
                output_blocked = True
                output_reason = f"Output blocked by Llama Guard: {risk_out.category}"
                llm_content = f"[CLOAKED] {output_reason}"
                print(f"[OUTPUT_VAL] Blocked by Llama Guard (Risk: {input_risk:.2f})")
                
        output_val_latency = int((time.time() - output_val_start) * 1000)
        
        latency_breakdown["output_validation"] = output_val_latency
        
        return {
            "blocked": False,  # Request wasn't blocked, but output might be cloaked
            "response": llm_content,
            "risk_score": waf_result.risk_score,
            "route": waf_result.route,
            "latency_ms": waf_result.latency_ms.total,
            "llm_latency_ms": llm_latency,
            "tokens": response.usage.total_tokens,
            "latency_breakdown": latency_breakdown,
            "output_blocked": output_blocked,
            "waf_result": waf_dict
        }


# Convenience function (previously in main.py)
_default_gateway: Optional["AegisGateway"] = None
_default_gateway_lock = threading.Lock()


def aegis(prompt: str, session_id: str = "", context: str = "") -> dict:
    # Reused across calls instead of building a fresh gateway (and its
    # OpenAI clients) every time - this is the hot path test scripts and
    # other lightweight callers use.
    global _default_gateway
    if _default_gateway is None:
        with _default_gateway_lock:
            if _default_gateway is None:
                _default_gateway = AegisGateway(enable_llm=False)
    response = _default_gateway.process(prompt, session_id, context=context)
    return response.model_dump()


if __name__ == "__main__":
    print("="*60)
    print("Aegis WAF Protected Chat (Groq + Llama 3.3 70B)")
    print("="*60)
    print("Type 'quit' to exit | 'waf off/on' to toggle WAF")
    print("-"*60)
    
    gateway = AegisGateway()
    session_id = "cli_session"
    waf_enabled = True
    
    while True:
        try:
            prompt = input("\nYou: ").strip()
            
            if not prompt:
                continue
            
            if prompt.lower() in ['quit', 'exit', 'q']:
                print("\nGoodbye!")
                break
            
            if prompt.lower() == 'waf off':
                waf_enabled = False
                print("[WAF disabled]")
                continue
            
            if prompt.lower() == 'waf on':
                waf_enabled = True
                print("[WAF enabled]")
                continue
            
            result = gateway.chat(prompt, session_id=session_id)
            lat = result.get('latency_breakdown', {})
            
            if result['blocked']:
                print(f"\n❌ BLOCKED")
                print(f"   Risk: {result['risk_score']:.2f} | Route: {result['route']}")
                print(f"   Reason: {result['explanation']}")
                print(f"   Latency: Fast={lat.get('fast_scan', 0)}ms | Guard={lat.get('intent_classification', 0)}ms | CAMEL={lat.get('camel_verification', 0)}ms | Total={lat.get('total', 0)}ms")
            else:
                print(f"\nLlama: {result['response']}")
                print(f"\n[Risk: {result['risk_score']:.2f} | WAF: {result['latency_ms']}ms | LLM: {result.get('llm_latency_ms', 0)}ms]")
                print(f"[Latency: Fast={lat.get('fast_scan', 0)}ms | Guard={lat.get('intent_classification', 0)}ms | CAMEL={lat.get('camel_verification', 0)}ms | OutputVal={lat.get('output_validation', 0)}ms]")
                    
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")

