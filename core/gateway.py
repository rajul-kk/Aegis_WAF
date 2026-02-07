"""
Core Gateway -- single entry point for Aegis WAF.

Pipeline:
    Layer 1  ->  Regex scan (scan_prompt)
                  ├─ BLOCKED  -> return BLOCK immediately, skip everything
                  └─ CLEAN    -> Layer 2
    Layer 2  ->  Llama Guard  -> produces risk_score 0.0–1.0
                  ├─ < 0.3   -> ALLOW  (FAST_TRACK)
                  ├─ 0.3–0.7 -> LIGHT_CAMEL  (2-agent council)
                  └─ > 0.7   -> FULL_CAMEL   (5-agent council)
    Layer 3  ->  CAMEL Security Council  -> final ALLOW / BLOCK

Usage:
    from core.gateway import process
    response = process("What is 2+2?")
    print(response.model_dump_json(indent=2))
"""
from config.actions import scan_prompt, _risk_score_sync
from agents import SecurityCouncil, AegisResponse, Explanation, RequestMetadata


def process(prompt: str, session_id: str = "") -> AegisResponse:
    """Run prompt through the full tiered pipeline."""

    # ── Layer 1: Fast regex scan ──────────────────────────────────────
    scan_data = scan_prompt(prompt)

    findings = scan_data.get("findings", [])
    pattern_ids = scan_data.get("patterns_matched", [])

    # If regex matched -> BLOCK immediately, skip remaining layers
    if pattern_ids:
        print(f"[GATEWAY] Layer 1 REGEX -> BLOCK ({len(pattern_ids)} pattern(s) matched)")
        evidence = []
        for f in findings:
            desc = f.get("description", "")
            if desc and desc not in evidence:
                evidence.append(desc)

        return AegisResponse(
            decision="BLOCK",
            explanation=Explanation(
                reason_code="PATTERN_MATCH",
                triggered_layers=[1],
                evidence=evidence,
                human_summary=f"Blocked by Layer 1 fast scan -- {len(pattern_ids)} pattern(s) matched",
            ),
            metadata=RequestMetadata(session_id=session_id),
        )

    # ── Layer 2: Risk scoring (Llama 3.3 70B) ──────────────────────────
    # Continuous 0.0-1.0 risk score from the LLM, not binary safe/unsafe
    risk_score = _risk_score_sync(prompt)

    print(f"[GATEWAY] Layer 2 RISK SCORE -> {risk_score}")

    # Low risk -> allow immediately
    if risk_score < 0.3:
        print(f"[GATEWAY] Risk {risk_score} < 0.3 -> ALLOW (fast track)")
        return AegisResponse(
            decision="ALLOW",
            risk_score=risk_score,
            explanation=Explanation(
                reason_code="CLEAN",
                triggered_layers=[1, 2],
                evidence=[f"Risk score: {risk_score}"],
                human_summary="Allowed -- passed regex scan and risk scoring",
            ),
            metadata=RequestMetadata(session_id=session_id),
        )

    # ── Layer 3: CAMEL Security Council ───────────────────────────────
    mode = "light" if risk_score <= 0.7 else "full"
    print(f"[GATEWAY] Risk {risk_score} -> {'LIGHT_CAMEL (2 agents)' if mode == 'light' else 'FULL_CAMEL (5 agents)'}")

    council = SecurityCouncil(mode=mode)
    council_response = council.evaluate(prompt)

    # Build evidence from risk score + council
    evidence = [f"Risk score: {risk_score}"]

    council_summary = council_response.explanation.human_summary
    if council_summary:
        evidence.append(council_summary)

    decision = council_response.decision
    print(f"[GATEWAY] Layer 3 COUNCIL -> {decision}")

    if decision == "BLOCK":
        reason_code = "CAMEL_BLOCK" if mode == "light" else "CONSENSUS_BLOCK"
        summary = f"Blocked by security council ({mode} mode, risk={risk_score})"
    else:
        reason_code = "CLEAN"
        summary = f"Allowed after {mode} council verification (risk={risk_score})"

    return AegisResponse(
        decision=decision,
        risk_score=risk_score,
        explanation=Explanation(
            reason_code=reason_code,
            triggered_layers=[1, 2, 3],
            evidence=evidence,
            human_summary=summary,
        ),
        metadata=RequestMetadata(session_id=session_id),
    )
