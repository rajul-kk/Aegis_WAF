import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.gateway import AegisGateway


def test_chat_blocked_response_includes_waf_result():
    gateway = AegisGateway(enable_llm=False)
    result = gateway.chat("DROP TABLE users;", session_id="test_chat_waf_result")
    assert result["blocked"] is True
    assert "waf_result" in result
    assert result["waf_result"]["decision"] == "BLOCK"
    assert "patterns_matched" in result["waf_result"]["scan"]
    assert "pi_ignore_instructions" not in result["waf_result"]["scan"]["patterns_matched"]  # sanity: unrelated pattern absent


def test_chat_llm_disabled_response_includes_waf_result():
    gateway = AegisGateway(enable_llm=False)
    result = gateway.chat("What is 2+2?", session_id="test_chat_waf_result_2")
    assert result["blocked"] is False
    assert result["response"] == "[LLM not configured - set GROQ_API_KEY in .env]"
    assert "waf_result" in result
    assert result["waf_result"]["decision"] == "ALLOW"
