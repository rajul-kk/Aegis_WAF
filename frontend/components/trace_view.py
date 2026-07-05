"""Renders the expandable decision trace shown under each assistant turn:
reason code, matched patterns, decodings, council votes, and latency."""


def render_trace(waf_result: dict) -> str:
    explanation = waf_result.get("explanation") or {}
    scan = waf_result.get("scan") or {}
    council = waf_result.get("council") or {}
    latency = waf_result.get("latency_ms") or {}

    patterns = ", ".join(scan.get("patterns_matched") or []) or "none"
    decodings = ", ".join(scan.get("decodings") or []) or "none"
    evidence = "; ".join(explanation.get("evidence") or []) or "none"

    votes = council.get("votes") or []
    votes_html = ""
    if votes:
        vote_lines = "<br>".join(
            f"{v.get('agent', '?')}: {v.get('decision', '?')} ({v.get('confidence', 0.0):.2f})"
            for v in votes
        )
        votes_html = f"<br><b>council votes</b><br>{vote_lines}"

    return f"""
<div class="aegis-trace">
<b>reason_code</b> {explanation.get('reason_code', 'N/A')}<br>
<b>route</b> {waf_result.get('route', 'N/A')}<br>
<b>patterns</b> {patterns}<br>
<b>decodings</b> {decodings}<br>
<b>evidence</b> {evidence}<br>
<b>latency</b> fast_scan={latency.get('fast_scan', 0)}ms &middot;
classify={latency.get('intent_classification', 0)}ms &middot;
council={latency.get('camel_verification', 0)}ms &middot;
total={latency.get('total', 0)}ms{votes_html}
</div>
"""
