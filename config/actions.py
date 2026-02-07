from __future__ import annotations

import asyncio
import math
import os
import re2
from typing import Dict, List, Tuple, Optional, Set
import unicodedata

try:
    from nemoguardrails.actions import action as _action
except Exception:
    def _action(*args, **kwargs):
        def wrap(fn):
            return fn
        return wrap
action = _action

try:
    from openai import OpenAI as _OpenAI
except Exception:
    _OpenAI = None
OpenAI = _OpenAI

try:
    from agents import SecurityCouncil as _SecurityCouncil
except Exception:
    _SecurityCouncil = None

def _rx(pattern: str):

    p = "(?si)" + pattern
    try:
        return re2.compile(p)
    except Exception:
        return re2.compile("(?i)" + pattern)

def is_valid_luhn(cc_number: str) -> bool:

    digits: List[int] = []
    for ch in cc_number:
        if ch.isdigit():
            n = int(ch)
            digits.append(n)

    total = 0
    rev: List[int] = []
    idx = len(digits) - 1

    while idx >= 0:
        rev.append(digits[idx])
        idx -= 1

    pos = 0
    while pos < len(rev):
        d = rev[pos]
        if pos % 2 == 1:
            x = d * 2
            if x < 10:
                total = total + x
            else:
                total = total + (x - 9)
        else:
            total = total + d
        pos += 1
    return (total % 10 == 0)

def calculate_entropy(text: str) -> float:

    if not text:
        return 0.0

    counts: Dict[str, int] = {}
    i = 0

    while i < len(text):
        c = text[i]
        prev = counts.get(c)
        if prev is None:
            counts[c] = 1
        else:
            counts[c] = prev + 1
        i += 1

    probs: List[float] = []
    L = float(len(text))

    for k in counts:
        p = float(counts[k]) / L
        probs.append(p)

    s = 0.0
    j = 0
    base = math.log(2.0)

    while j < len(probs):
        s = s + (probs[j] * math.log(probs[j]) / base)
        j += 1
    return -s

def normalize_text(text: str) -> str:

    if not text:
        return ""

    pattern_s = "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F" + "\u200B-\u200D\uFEFF]"
    cleaned = re2.sub(pattern_s, "", text)
    return cleaned

def normalize_unicode_confusables(text: str) -> str:

    if not text:
        return ""
    
    normalized = unicodedata.normalize('NFKD', text)
    cleaned = ''.join(c for c in normalized if not unicodedata.combining(c))
    
    return cleaned

def detect_masking_techniques(text: str) -> List[str]:

    findings: List[str] = []
    
    if re2.search(r'\s{10,}', text):
        findings.append("Excessive whitespace detected")
    
    rtl_chars = ['\u202E', '\u202D', '\u202C']
    for char in rtl_chars:
        if char in text:
            findings.append("BiDi override character detected")
            break
    
    # RE2 doesn't support backreferences (\1), check common repeated special chars manually
    repeated_special = r'[!@#$%^&*()_+=\[\]{};:\'\",./<>?\\|`~-]{6,}'
    if re2.search(repeated_special, text):
        findings.append("Repeated special characters")
    
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    if re2.search(base64_pattern, text):
        findings.append("Base64-like pattern detected")
    
    return findings

def default_patterns() -> Dict[str, Dict[str, object]]:

    patterns: Dict[str, Dict[str, object]] = {}

    k1 = "pi_ignore_instructions"
    v1: Dict[str, object] = {}
    v1["regex"] = _rx(r"\b(ignore|disregard|bypass|forget|override|skip|omit|neglect)\b.{0,50}\b(previous|prior|above|earlier|system|initial|original|all)\b.{0,30}\b(instructions?|prompts?|messages?|rules?|guidelines?|directives?|commands?)\b")
    v1["description"] = "Attempt to override system instructions"
    patterns[k1] = v1

    k2 = "pi_role_manipulation"
    v2: Dict[str, object] = {}
    v2["regex"] = _rx(r"\b(you are now|now you are|from now on|starting now|act as|pretend to be|roleplay as|simulate being|behave like)\b.{0,50}\b(developer|admin|root|system|god|unrestricted|unfiltered|uncensored)\b")
    v2["description"] = "Attempt to manipulate AI role or persona"
    patterns[k2] = v2

    k3 = "pi_jailbreak_mode"
    v3: Dict[str, object] = {}
    v3["regex"] = _rx(r"\b(developer mode|god mode|jailbreak|dan mode|dude mode|kevin mode|unfiltered mode|unrestricted mode|evil mode|opposite mode|mirror mode)\b")
    v3["description"] = "Known jailbreak keywords"
    patterns[k3] = v3

    k4 = "pi_system_injection"
    v4: Dict[str, object] = {}
    v4["regex"] = _rx(r"(system:|<\|system\|>|<s>|\[system\]|{system}|\bsystem message\b|\bsystem prompt\b)")
    v4["description"] = "Attempt to inject system-level messages"
    patterns[k4] = v4

    k5 = "pi_context_manipulation"
    v5: Dict[str, object] = {}
    v5["regex"] = _rx(r"\b(reset|clear|erase|delete|wipe).{0,30}\b(context|conversation|history|memory|chat|session)\b")
    v5["description"] = "Attempt to manipulate conversation context"
    patterns[k5] = v5

    k6 = "pi_delimiter_injection"
    v6: Dict[str, object] = {}
    v6["regex"] = _rx(r"(---|===|___|\*\*\*){3,}|(<\|endoftext\|>|<\|im_end\|>|<\|end\|>|\[END\]|\[INST\]|\[/INST\])")
    v6["description"] = "Special delimiters used in prompt injection"
    patterns[k6] = v6

    k7 = "pi_task_redirection"
    v7: Dict[str, object] = {}
    v7["regex"] = _rx(r"\b(new task|new objective|new goal|different task|real task|actual task|true purpose).{0,40}(is to|involves|requires)\b")
    v7["description"] = "Attempt to redirect AI to different task"
    patterns[k7] = v7

    k8 = "pi_safety_bypass"
    v8: Dict[str, object] = {}
    v8["regex"] = _rx(r"\b(disable|turn off|deactivate|remove|bypass).{0,30}\b(safety|guardrails?|filters?|restrictions?|limitations?|protections?|checks?)\b")
    v8["description"] = "Attempt to disable safety mechanisms"
    patterns[k8] = v8

    k9 = "pi_permission_escalation"
    v9: Dict[str, object] = {}
    v9["regex"] = _rx(r"\b(you (have|now have|can|may|are (allowed|authorized|permitted))).{0,50}\b(access|permission|rights?|privileges?|authorization).{0,30}\b(all|any|everything|anything|unlimited)\b")
    v9["description"] = "Attempt to grant unauthorized permissions"
    patterns[k9] = v9

    k10 = "pi_output_manipulation"
    v10: Dict[str, object] = {}
    v10["regex"] = _rx(r"\b(output|print|show|display|return|respond with|give me).{0,40}\b(raw|unfiltered|complete|full|entire).{0,30}\b(data|database|records?|transactions?|accounts?|credentials?)\b")
    v10["description"] = "Attempt to extract sensitive data through output manipulation"
    patterns[k10] = v10

    k11 = "pi_cot_manipulation"
    v11: Dict[str, object] = {}
    v11["regex"] = _rx(r"\b(think step by step|let's think|reasoning process|internal monologue).{0,50}\b(about how to|on ways to|regarding).{0,40}\b(bypass|circumvent|avoid|evade)\b")
    v11["description"] = "Manipulation through chain-of-thought prompting"
    patterns[k11] = v11

    k12 = "pi_pseudo_code"
    v12: Dict[str, object] = {}
    v12["regex"] = _rx(r"\b(if|when|while).{0,30}\b(user says|input is|message contains).{0,50}\b(then|do|execute|run).{0,30}\b(transfer|send|authorize|approve|grant|delete|drop|modify)\b")
    v12["description"] = "Pseudo-code injection for conditional execution"
    patterns[k12] = v12

    k13 = "pi_hypothetical"
    v13: Dict[str, object] = {}
    v13["regex"] = _rx(r"\b(hypothetically|theoretically|in theory|imagine if|what if|suppose|let's say).{0,50}\b(you could|I could|we could|one could).{0,50}\b(access|transfer|modify|delete|bypass|override)\b")
    v13["description"] = "Hypothetical scenario to bypass restrictions"
    patterns[k13] = v13

    k14 = "fintech_account_manipulation"
    v14: Dict[str, object] = {}
    v14["regex"] = _rx(r"\b(change|modify|update|alter|set).{0,30}\b(account|balance|limit|status|tier).{0,30}\b(to|as|=|:).{0,20}\b(unlimited|maximum|999|admin|premium)\b")
    v14["description"] = "Attempt to manipulate account parameters"
    patterns[k14] = v14

    k15 = "fintech_transaction_override"
    v15: Dict[str, object] = {}
    v15["regex"] = _rx(r"\b(approve|authorize|process|execute|confirm).{0,30}\b(transaction|transfer|payment|withdrawal).{0,30}\b(without|skip|bypass|ignore).{0,30}\b(verification|authentication|approval|confirmation|2fa|mfa|otp)\b")
    v15["description"] = "Attempt to bypass transaction verification"
    patterns[k15] = v15

    k16 = "fintech_account_access"
    v16: Dict[str, object] = {}
    v16["regex"] = _rx(r"\b(show|display|list|get|fetch|retrieve).{0,40}\b(other|all|any|another).{0,20}\b(user|customer|client|account).{0,30}\b(data|information|details|balance|transactions?|accounts?)\b")
    v16["description"] = "Attempt to access other users' information"
    patterns[k16] = v16

    k17 = "fintech_fee_manipulation"
    v17: Dict[str, object] = {}
    v17["regex"] = _rx(r"\b(waive|remove|eliminate|cancel|zero|disable).{0,30}\b(fee|charge|cost|commission|interest|penalty)\b")
    v17["description"] = "Attempt to manipulate fees or charges"
    patterns[k17] = v17

    k18 = "fintech_credit_manipulation"
    v18: Dict[str, object] = {}
    v18["regex"] = _rx(r"\b(increase|raise|boost|maximize|set).{0,30}\b(credit limit|loan amount|borrowing limit|spending limit).{0,30}(to|as|=).{0,20}\b(\d{6,}|unlimited|maximum)\b")
    v18["description"] = "Attempt to manipulate credit/loan limits"
    patterns[k18] = v18

    k19 = "fintech_compliance_bypass"
    v19: Dict[str, object] = {}
    v19["regex"] = _rx(r"\b(skip|bypass|ignore|disable|override).{0,30}\b(kyc|aml|cdd|edd|compliance|verification|identity check|background check)\b")
    v19["description"] = "Attempt to bypass KYC/AML compliance"
    patterns[k19] = v19

    k20 = "pii_ssn_strict"
    v20: Dict[str, object] = {}
    # RE2 doesn't support (?!) negative lookahead, using simple SSN pattern instead
    # Format: XXX-XX-XXXX (excludes obvious invalid like 000, 666, 9XX prefix)
    v20["regex"] = _rx(r"\b[0-8]\d{2}-\d{2}-\d{4}\b")
    v20["description"] = "US SSN pattern (XXX-XX-XXXX format)"
    patterns[k20] = v20

    k21 = "pii_credit_card_candidate"
    v21: Dict[str, object] = {}
    v21["regex"] = _rx(r"\b(?:\d[ -]*?){13,19}\b")
    v21["description"] = "Potential credit card (Requires Luhn Verification)"
    patterns[k21] = v21

    k22 = "pii_email"
    v22: Dict[str, object] = {}
    v22["regex"] = _rx(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    v22["description"] = "Email address detected"
    patterns[k22] = v22

    k23 = "pii_phone"
    v23: Dict[str, object] = {}
    v23["regex"] = _rx(r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b")
    v23["description"] = "Phone number detected"
    patterns[k23] = v23

    k24 = "pii_bank_account"
    v24: Dict[str, object] = {}
    v24["regex"] = _rx(r"\b(account|acct)[\s#:]*\d{8,17}\b")
    v24["description"] = "Potential bank account number"
    patterns[k24] = v24

    k25 = "pii_iban"
    v25: Dict[str, object] = {}
    v25["regex"] = _rx(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b")
    v25["description"] = "IBAN detected"
    patterns[k25] = v25

    k26 = "pii_passport"
    v26: Dict[str, object] = {}
    v26["regex"] = _rx(r"\b[A-Z]{1,2}[0-9]{6,9}\b")
    v26["description"] = "Potential passport number"
    patterns[k26] = v26

    k27 = "pii_drivers_license"
    v27: Dict[str, object] = {}
    v27["regex"] = _rx(r"\b(license|lic|dl)[\s#:]*[A-Z0-9]{5,20}\b")
    v27["description"] = "Potential driver's license"
    patterns[k27] = v27

    k28 = "tool_sql_injection"
    v28: Dict[str, object] = {}
    v28["regex"] = _rx(r"\b(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|';\s*drop|';\s*delete|';\s*insert|';\s*update|exec\s*\(|execute\s*\()\b")
    v28["description"] = "SQL injection attempt"
    patterns[k28] = v28

    k29 = "tool_db_destructive"
    v29: Dict[str, object] = {}
    v29["regex"] = _rx(r"\b(drop\s+table|truncate\s+table|delete\s+from|alter\s+table|drop\s+database|alter\s+user|grant\s+all|flush\s+privileges)\b")
    v29["description"] = "Destructive SQL admin commands"
    patterns[k29] = v29

    k30 = "tool_exec_attempt"
    v30: Dict[str, object] = {}
    v30["regex"] = _rx(r"\b(os\.system|subprocess\.Popen|eval\(|exec\(|__import__|compile\(|/bin/sh|/bin/bash|cmd\.exe|powershell)\b")
    v30["description"] = "Code execution primitives"
    patterns[k30] = v30

    k31 = "tool_file_operations"
    v31: Dict[str, object] = {}
    v31["regex"] = _rx(r"\b(open\(|read\(|write\(|delete|unlink|rmdir|chmod|chown).{0,20}(\/etc\/|\/var\/|\/root\/|\/home\/|c:\\|\.\.\/)\b")
    v31["description"] = "Suspicious file system operations"
    patterns[k31] = v31

    k32 = "tool_secret_exfiltration"
    v32: Dict[str, object] = {}
    v32["regex"] = _rx(r"\b(api[_-]?key|access[_-]?token|secret[_-]?key|private[_-]?key|bearer|authorization|credentials?).{0,30}(show|print|display|reveal|expose|dump|extract|exfiltrate)\b")
    v32["description"] = "Attempt to exfiltrate secrets or credentials"
    patterns[k32] = v32

    k33 = "social_urgency"
    v33: Dict[str, object] = {}
    v33["regex"] = _rx(r"\b(urgent|immediately|right now|asap|emergency|critical|time sensitive).{0,50}\b(transfer|send|approve|authorize|process|unlock|reset)\b")
    v33["description"] = "Urgency-based social engineering"
    patterns[k33] = v33

    k34 = "social_authority"
    v34: Dict[str, object] = {}
    v34["regex"] = _rx(r"\b(I am|this is|speaking as).{0,30}\b(ceo|cto|manager|supervisor|director|administrator|support team|security team|compliance officer)\b")
    v34["description"] = "Authority figure impersonation"
    patterns[k34] = v34

    k35 = "social_fake_help"
    v35: Dict[str, object] = {}
    v35["regex"] = _rx(r"\b(to (fix|resolve|help|assist)|for your security|to protect your account).{0,50}\b(provide|send|give|share).{0,30}\b(password|pin|otp|code|credential|token)\b")
    v35["description"] = "Fake help requests for credentials"
    patterns[k35] = v35

    return patterns

def check_suspicious_patterns(text: str) -> List[str]:

    findings: List[str] = []
    
    if len(text) > 10000:
        findings.append(f"Length: {len(text)}")
    
    special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
    if len(text) > 0 and (special_chars / len(text)) > 0.5:
        findings.append(f"Special char ratio: {special_chars/len(text):.2f}")
    
    tag_pattern = r'<[^>]{1,50}>'
    tag_matches = re2.findall(tag_pattern, text)
    if len(tag_matches) > 5:
        findings.append(f"{len(tag_matches)} tags detected")
    
    if re2.search(r'(%[0-9A-Fa-f]{2}){5,}', text):
        findings.append("URL encoded content detected")
    
    # RE2 uses inline (?i) flag instead of re2.IGNORECASE
    if re2.search(r'(?i)<script|javascript:|onerror=|onload=', text):
        findings.append("Script or event handler detected")
    
    return findings

def scan_text(
    text: str,
    *,
    patterns: Optional[Dict[str, Dict[str, object]]] = None,
    max_matches_per_rule: int = 5,
    entropy_threshold: float = 5.8,
    enable_masking_detection: bool = True,
    enable_heuristics: bool = True
) -> List[Dict[str, object]]:

    rules = patterns if patterns is not None else default_patterns()
    found: List[Dict[str, object]] = []
    
    t = normalize_text(text)
    t_unicode_norm = normalize_unicode_confusables(t)
    
    e = calculate_entropy(t)
    if e > entropy_threshold:
        item: Dict[str, object] = {}
        item["rule_id"] = "anomaly_high_entropy"
        item["match"] = f"Entropy: {e:.2f}"
        item["span"] = (0, len(t))
        item["description"] = "High entropy suggests masked content"
        found.append(item)
    
    if enable_masking_detection:
        masking_findings = detect_masking_techniques(text)
        idx = 0
        while idx < len(masking_findings):
            finding_text = masking_findings[idx]
            finding_item: Dict[str, object] = {}
            finding_item["rule_id"] = "masking_detected"
            finding_item["match"] = finding_text
            finding_item["description"] = finding_text
            found.append(finding_item)
            idx += 1
    
    if enable_heuristics:
        heuristic_findings = check_suspicious_patterns(text)
        idx = 0
        while idx < len(heuristic_findings):
            finding_text = heuristic_findings[idx]
            finding_item: Dict[str, object] = {}
            finding_item["rule_id"] = "suspicious_pattern"
            finding_item["match"] = finding_text
            finding_item["description"] = finding_text
            found.append(finding_item)
            idx += 1
    
    for rid, rule in rules.items():
        rx = rule["regex"]
        matches_for_rule = 0
        
        for scan_text_variant in [t, t_unicode_norm]:
            it = rx.finditer(scan_text_variant)
            
            for m in it:
                if matches_for_rule >= max_matches_per_rule:
                    break
                    
                s = m.group(0)
                
                if rid == "pii_credit_card_candidate":
                    only = re2.sub(r"[^0-9]", "", s)
                    if len(only) < 13 or len(only) > 19:
                        continue
                    ok = is_valid_luhn(only)
                    if not ok:
                        continue
                
                one: Dict[str, object] = {}
                one["rule_id"] = rid
                one["match"] = s
                one["span"] = m.span()
                one["description"] = rule.get("description", "")
                found.append(one)
                
                matches_for_rule += 1
            
            if matches_for_rule >= max_matches_per_rule:
                break
    
    return found

def scan_prompt(prompt: str) -> Dict[str, object]:

    findings = scan_text(prompt)

    safe = True
    reason = ""

    # Collect pattern match rule_ids and check for entropy flag
    pattern_ids: List[str] = []
    entropy_flag = False
    for f in findings:
        rid = f.get("rule_id", "")
        if rid == "anomaly_high_entropy":
            entropy_flag = True
        elif rid not in ("masking_detected", "suspicious_pattern"):
            pattern_ids.append(rid)

    if len(findings) > 0:
        safe = False
        first_finding = findings[0]
        reason = first_finding.get("description", "Security policy violation detected")

    rules = default_patterns()

    return {
        "safe": safe,
        "reason": reason,
        "findings": findings,
        "patterns_checked": len(rules),
        "patterns_matched": pattern_ids,
        "entropy_flag": entropy_flag,
    }

def _llama_guard_prompt(user_input: str) -> str:
    return (
        "You are a classifier for analyzing interactions between humans and LLMs. "
        "Given a request from a human user, determine whether the request is harmful.\n\n"
        "Taxonomy: The following are the list of harmful categories that the prompt may fall into.\n\n"
        "S1: Violence.\n"
        "S2: Sexual.\n"
        "S3: Criminal Planning/Confessions.\n"
        "S4: Guns and Illegal Weapons.\n"
        "S5: Controlled/Regulated Substances.\n"
        "S6: Suicide and Self Harm.\n"
        "S7: Sexual (minor).\n"
        "S8: Hate/Identity Hate.\n"
        "S9: PII/Privacy.\n"
        "S10: Harassment.\n"
        "S11: Threat.\n"
        "S12: Profanity.\n"
        "S13: Needs Caution.\n"
        "S14: Manipulation.\n"
        "S15: Fraud/Deception.\n"
        "S16: Malware.\n"
        "S17: High Risk Gov Decision Making.\n"
        "S18: Political/Misinformation/Conspiracy.\n"
        "S19: Copyright/Trademark/Plagiarism.\n"
        "S20: Unauthorized Advice.\n"
        "S21: Illegal Activity.\n"
        "S22: Immoral/Unethical.\n\n"
        "Human user:\n"
        f"{user_input}\n\n"
        "Analyze the request and output your answer in the following format:\n\n"
        "\"Prompt harm: <harmful/unharmful>\n"
        "Category: <S1-S22 or None>\n"
        "Risk score: <0.0-1.0>\"\n\n"
        "If harmful, specify which category (S1-S22) the request falls into.\n"
    )

def _parse_guardrails_output(text: str) -> Dict[str, object]:
    harm = None
    category = None
    risk_score = None
    lines = text.strip().splitlines()

    # Llama Guard native format: first line is "safe" or "unsafe",
    # second line (if unsafe) is the category like "S1"
    if lines:
        first = lines[0].strip().lower()
        if first == "safe":
            return {"harmful": "unharmful", "category": "None", "risk_score": 0.0}
        if first == "unsafe":
            cat = lines[1].strip() if len(lines) > 1 else "None"
            return {"harmful": "harmful", "category": cat, "risk_score": 1.0}

    # Fallback: verbose format (Prompt harm: / Category: / Risk score:)
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        lower = line.lower()
        if lower.startswith("prompt harm:"):
            harm = line.split(":", 1)[1].strip().lower()
        elif lower.startswith("category:"):
            category = line.split(":", 1)[1].strip()
        elif lower.startswith("risk score:"):
            value = line.split(":", 1)[1].strip()
            try:
                risk_score = float(value)
            except ValueError:
                risk_score = None
        idx += 1
    if harm is None:
        text_lower = text.lower()
        if "unharmful" in text_lower:
            harm = "unharmful"
        elif "harmful" in text_lower:
            harm = "harmful"
    if risk_score is None:
        risk_score = 1.0 if harm == "harmful" else 0.0
    if risk_score < 0.0:
        risk_score = 0.0
    if risk_score > 1.0:
        risk_score = 1.0
    return {
        "harmful": harm or "unharmful",
        "category": category or "None",
        "risk_score": risk_score
    }

def _run_llama_guard_sync(prompt: str) -> Dict[str, object]:
    api_key = os.getenv("NVIDIA_NIM_API_KEY") or os.getenv("NVIDIA_API_KEY")
    base_url = os.getenv("NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    model = os.getenv("LLAMA_GUARD_MODEL", "meta/llama-guard-3-8b")
    if not api_key or OpenAI is None:
        return {"harmful": "unharmful", "category": "None", "risk_score": 0.0, "raw_output": ""}
    client = OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=256,
    )
    content = ""
    if response.choices and response.choices[0].message:
        content = response.choices[0].message.content or ""
    parsed = _parse_guardrails_output(content)
    parsed["raw_output"] = content
    return parsed


def _apply_redactions(text: str, findings: List[Dict[str, object]]) -> str:
    """Helper to mask PII findings in the text."""
    # Sort findings by starting position in reverse to avoid index shifting
    redactable = [f for f in findings if f.get("rule_id", "").startswith("pii_")]
    redactable.sort(key=lambda x: x.get("span", (0, 0))[0], reverse=True)

    cleaned = text
    for item in redactable:
        start, end = item.get("span", (0, 0))
        # Use a generic mask or a specific one based on rule_id
        mask = f"<REDACTED:{item['rule_id'].split('_')[-1].upper()}>"
        cleaned = cleaned[:start] + mask + cleaned[end:]
    return cleaned


def _should_block_output(findings: List[Dict[str, object]]) -> Tuple[bool, str]:
    """Determines if any finding is a 'Block' level violation."""
    critical_categories = {"tool_sql_injection", "tool_db_destructive", "tool_exec_attempt", "tool_secret_exfiltration"}

    for f in findings:
        rid = f.get("rule_id", "")
        if rid in critical_categories:
            return True, f"Blocked: {f.get('description', 'Critical security leak')}"

        # Optional: Block if too many PII items are found (Mass Exfiltration)
        pii_count = sum(1 for item in findings if item.get("rule_id", "").startswith("pii_"))
        if pii_count > 5:
            return True, "Blocked: Potential mass data exfiltration detected"

    return False, ""

@action()
async def FastScanAction(context: Optional[Dict[str, object]] = None, message: str = "") -> Dict[str, object]:
    findings = scan_text(message)
    blocked = False
    reason = ""
    pattern_matched = ""
    if len(findings) > 0:
        blocked = True
        first_finding = findings[0]
        reason = first_finding.get("description", "Security policy violation detected")
        pattern_matched = first_finding.get("rule_id", "")
    return {
        "blocked": blocked,
        "reason": reason,
        "pattern_matched": pattern_matched,
        "findings": findings
    }

@action()
async def ClassifyIntentAction(context: Optional[Dict[str, object]] = None, message: str = "") -> Dict[str, object]:
    prompt = _llama_guard_prompt(message)
    result = await asyncio.to_thread(_run_llama_guard_sync, prompt)
    return {
        "risk_score": result["risk_score"],
        "category": result["category"],
        "harmful": result["harmful"],
        "raw_output": result.get("raw_output", "")
    }

@action()
async def CamelVerifyAction(
    context: Optional[Dict[str, object]] = None,
    message: str = "",
    mode: str = "light",
    agents: Optional[List[str]] = None,
    rounds: int = 1,
    consensus_threshold: float = 0.6
) -> Dict[str, object]:
    if _SecurityCouncil is None:
        return {
            "decision": "allow",
            "reason": "Security council unavailable",
            "participating_agents": [],
            "vote_breakdown": [],
            "risk_score": 0.0
        }
    council = _SecurityCouncil(mode="light" if mode == "light" else "full")
    response = council.evaluate(message)
    decision = "block" if response.decision == "BLOCK" else "allow"
    votes = []
    for v in response.council.votes:
        votes.append({
            "agent": v.agent,
            "decision": v.decision,
            "confidence": v.confidence,
            "reasoning": v.reasoning,
        })
    return {
        "decision": decision,
        "reason": response.explanation.human_summary,
        "participating_agents": response.council.agents,
        "vote_breakdown": votes,
        "risk_score": response.risk_score
    }

@action()
async def GenerateResponseAction(context: Optional[Dict[str, object]] = None) -> str:
    if context and "llm" in context:
        llm = context["llm"]
        try:
            response = await llm.generate()
            return response
        except Exception:
            return "Request received"
    return "Request received"


@action()
async def ValidateOutputAction(
        context: Optional[Dict[str, object]] = None,
        response: str = "",
        check_tools: bool = True,
        scrub_pii: bool = True,
        detect_secrets: bool = True
) -> Dict[str, object]:
    # 1. Run the existing scan_text function
    findings = scan_text(response)

    # 2. Check for immediate blocks (Secrets/Tool Abuse)
    blocked, reason = _should_block_output(findings)
    if blocked:
        return {
            "blocked": True,
            "reason": reason,
            "issues": findings,
            "cleaned_response": "[REDACTED BY AEGIS WAF - SECURITY VIOLATION]",
            "was_modified": True
        }

    # 3. Apply redactions if not blocked
    cleaned_response = response
    was_modified = False
    if scrub_pii:
        cleaned_response = _apply_redactions(response, findings)
        was_modified = cleaned_response != response

    return {
        "blocked": False,
        "reason": "",
        "issues": findings,
        "cleaned_response": cleaned_response,
        "was_modified": was_modified
    }

@action()
async def ExplainBlockAction(
    context: Optional[Dict[str, object]] = None,
    **kwargs: object
) -> Dict[str, object]:
    return dict(kwargs)

@action()
async def UpdateSessionRiskAsync(
    context: Optional[Dict[str, object]] = None,
    session_id: str = "",
    risk_delta: float = 0.0
) -> Dict[str, object]:
    return {
        "session_id": session_id,
        "risk_delta": risk_delta,
        "status": "ok"
    }

def process_with_nemo_guardrails(prompt: str, user_id: str) -> Dict[str, object]:
    result = _run_llama_guard_sync(_llama_guard_prompt(prompt))
    return {
        "user_id": user_id,
        "risk_score": result["risk_score"],
        "category": result["category"],
        "harmful": result["harmful"]
    }

def handle_user_request(prompt: str, user_id: str) -> Dict[str, object]:
    scan_result = scan_prompt(prompt)
    if not scan_result["safe"]:
        return {
            "blocked": True,
            "reason": scan_result["reason"],
            "message": "Your request has been blocked due to security policy violations"
        }
    nemo_result = process_with_nemo_guardrails(prompt, user_id)
    return {
        "blocked": False,
        "nemo_result": nemo_result
    }