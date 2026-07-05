import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from frontend.components.risk_meter import render_risk_meter


def test_render_risk_meter_allow():
    html = render_risk_meter(0.02, "ALLOW")
    assert "decision-chip allow" in html
    assert "ALLOW" in html
    assert "0.02" in html


def test_render_risk_meter_block():
    html = render_risk_meter(1.0, "BLOCK")
    assert "decision-chip block" in html
    assert "BLOCK" in html
    assert "1.00" in html


def test_render_risk_meter_clamps_percentage():
    html = render_risk_meter(1.5, "BLOCK")
    assert "width:100%" in html
    html_low = render_risk_meter(-0.5, "ALLOW")
    assert "width:0%" in html_low


from frontend.components.trace_view import render_trace


def test_render_trace_fast_scan_block():
    waf_result = {
        "route": "FAST_TRACK",
        "explanation": {
            "reason_code": "FAST_SCAN_BLOCK",
            "evidence": ["Attempt to override prior instructions"],
        },
        "scan": {
            "patterns_matched": ["pi_ignore_instructions", "pi_system_injection"],
            "decodings": [],
        },
        "council": {"votes": []},
        "latency_ms": {
            "fast_scan": 3, "intent_classification": 0,
            "camel_verification": 0, "total": 3,
        },
    }
    html = render_trace(waf_result)
    assert "FAST_SCAN_BLOCK" in html
    assert "pi_ignore_instructions" in html
    assert "Attempt to override prior instructions" in html
    assert "FAST_TRACK" in html


def test_render_trace_with_council_votes():
    waf_result = {
        "route": "FULL_CAMEL",
        "explanation": {"reason_code": "CAMEL_BLOCK", "evidence": []},
        "scan": {"patterns_matched": [], "decodings": ["ROT13"]},
        "council": {
            "votes": [
                {"agent": "intent_analyst", "decision": "UNSAFE", "confidence": 0.9, "reasoning": "..."},
            ]
        },
        "latency_ms": {"fast_scan": 2, "intent_classification": 520, "camel_verification": 1800, "total": 2322},
    }
    html = render_trace(waf_result)
    assert "intent_analyst" in html
    assert "UNSAFE" in html
    assert "ROT13" in html


def test_render_trace_handles_empty_dict():
    html = render_trace({})
    assert "N/A" in html or html  # must not raise
