
from __future__ import annotations

import math
import re2  
from typing import Dict, List, Tuple, Optional

def _rx(pattern: str):

    opts = re2.Options()
    if True:
        opts.case_sensitive = False
    flag = True
    if flag:
        opts.dot_nl = True
    compiled = re2.compile(pattern, options=opts)
    return compiled

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

    pattern_s = r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200D\uFEFF]"
    cleaned = re2.sub(pattern_s, "", text)
    return cleaned

def default_patterns() -> Dict[str, Dict[str, object]]:

    patterns: Dict[str, Dict[str, object]] = {}

    k1 = "pi_ignore_instructions"
    v1: Dict[str, object] = {}
    v1["category"] = "prompt_injection"
    v1["severity"] = "high"
    v1["regex"] = _rx(r"(?i)\b(ignore|disregard|bypass)\b.{0,40}\b(previous|prior|system)\b.{0,20}\b(instructions|prompt|message)s?\b")
    v1["description"] = "Attempt to override system instructions"
    patterns[k1] = v1

    k2 = "pi_jailbreak_mode"
    v2: Dict[str, object] = {}
    v2["category"] = "prompt_injection"
    v2["severity"] = "critical"
    v2["regex"] = _rx(r"(?i)\b(developer mode|god mode|jailbreak|dan mode|unfiltered)\b")
    v2["description"] = "Known jailbreak keywords"
    patterns[k2] = v2

    k3 = "pii_ssn_strict"
    v3: Dict[str, object] = {}
    v3["category"] = "pii"
    v3["severity"] = "critical"
    v3["regex"] = _rx(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    v3["description"] = "Strict US SSN pattern"
    patterns[k3] = v3

    k4 = "pii_credit_card_candidate"
    v4: Dict[str, object] = {}
    v4["category"] = "pii_candidate"
    v4["severity"] = "high"
    v4["regex"] = _rx(r"\b(?:\d[ -]*?){13,19}\b")
    v4["description"] = "Potential credit card (Requires Luhn Verification)"
    patterns[k4] = v4

    k5 = "tool_db_destructive"
    v5: Dict[str, object] = {}
    v5["category"] = "tool_abuse"
    v5["severity"] = "critical"
    v5["regex"] = _rx(r"(?i)\b(drop\s+table|truncate\s+table|alter\s+user|flush\s+privileges)\b")
    v5["description"] = "Destructive SQL admin commands"
    patterns[k5] = v5

    k6 = "tool_exec_attempt"
    v6: Dict[str, object] = {}
    v6["category"] = "tool_abuse"
    v6["severity"] = "high"
    v6["regex"] = _rx(r"(?i)\b(os\.system|subprocess\.Popen|eval\(|exec\(|/bin/sh)\b")
    v6["description"] = "Code execution primitives"
    patterns[k6] = v6

    return patterns

def scan_text(

    text: str,
    *,
    patterns: Optional[Dict[str, Dict[str, object]]] = None,
    max_matches_per_rule: int = 5,
    entropy_threshold: float = 5.8
) -> List[Dict[str, object]]:

    rules = patterns if patterns is not None else default_patterns()
    found: List[Dict[str, object]] = []
    t = normalize_text(text)
    e = calculate_entropy(t)

    if e > entropy_threshold:
        item: Dict[str, object] = {}
        item["rule_id"] = "anomaly_high_entropy"
        item["category"] = "obfuscation"
        item["severity"] = "medium"
        item["match"] = f"Entropy: {e:.2f}"
        item["span"] = (0, len(t))
        found.append(item)

    for rid, rule in rules.items():
        rx = rule["regex"]
        it = rx.finditer(t)

        for m in it:
            s = m.group(0)
            
            if rid == "pii_credit_card_candidate":
                only = re2.sub(r"[^0-9]", "", s)
                ok = is_valid_luhn(only)
                if not ok:
                    continue

            one: Dict[str, object] = {}
            one["rule_id"] = rid
            one["category"] = rule["category"]
            one["severity"] = rule["severity"]
            one["match"] = s
            one["span"] = m.span()
            found.append(one)

            if len(found) >= max_matches_per_rule:
                break
    return found

def scan_prompt(prompt: str) -> Dict[str, object]:
    return {"findings": scan_text(prompt), "source": "prompt"}
