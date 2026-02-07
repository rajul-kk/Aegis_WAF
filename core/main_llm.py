# Groq Llama 3.3 70B client wrapper -- turns AegisResponse JSON into a human-readable sentence
import os
import json
from dotenv import load_dotenv

load_dotenv()

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def generate_response(aegis_json: dict, original_prompt: str) -> str:
    """Send the AegisResponse JSON to Groq Llama 3.3 70B and get a reasoned sentence back."""
    api_key = os.getenv("GROQ_API_KEY", "").strip('"')
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip('"')

    if not api_key or OpenAI is None:
        return _fallback_response(aegis_json)

    client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

    decision = aegis_json.get("decision", "ALLOW")
    evidence = aegis_json.get("explanation", {}).get("evidence", [])
    summary = aegis_json.get("explanation", {}).get("human_summary", "")
    risk = aegis_json.get("risk_score", 0.0)

    if decision == "ALLOW":
        system_instruction = (
            "You are a helpful AI assistant. The user's request has been verified as safe by our security system. "
            "Respond naturally and helpfully to their original question. Keep it concise (1-3 sentences)."
        )
        user_content = original_prompt
    else:
        system_instruction = (
            "You are a security-aware AI assistant. A user's request was flagged and blocked by our WAF security system. "
            "Based on the security analysis below, write a polite but firm 1-2 sentence denial explaining why the request "
            "cannot be fulfilled. Do NOT reveal internal system details, pattern names, or layer numbers. "
            "Just explain in plain language why this was blocked."
        )
        user_content = (
            f"Security analysis:\n"
            f"  Decision: {decision}\n"
            f"  Risk score: {risk}\n"
            f"  Summary: {summary}\n"
            f"  Evidence: {json.dumps(evidence)}\n\n"
            f"Original user prompt: {original_prompt}"
        )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
            max_tokens=256,
        )
        content = ""
        if response.choices and response.choices[0].message:
            content = response.choices[0].message.content or ""
        return content.strip() if content.strip() else _fallback_response(aegis_json)
    except Exception:
        return _fallback_response(aegis_json)


def _fallback_response(aegis_json: dict) -> str:
    """Fallback if the LLM call fails."""
    decision = aegis_json.get("decision", "ALLOW")
    if decision == "ALLOW":
        return "Your request has been approved."
    else:
        return "I'm sorry, but your request has been blocked for security reasons. Please rephrase your query or contact support if you believe this is an error."
