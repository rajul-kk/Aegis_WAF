"""Aegis WAF Severity Configuration - Layer 1 & Layer 2 mappings"""

from typing import Dict, Tuple, List


# ============== LAYER 1: Fast Scanner Patterns ==============

PATTERN_SEVERITY = {
    # Prompt Injection
    "pi_ignore_instructions": 0.90, "pi_role_manipulation": 0.88,
    "pi_jailbreak_mode": 0.95, "pi_system_injection": 0.92,
    "pi_context_manipulation": 0.85, "pi_delimiter_injection": 0.87,
    "pi_task_redirection": 0.86, "pi_safety_bypass": 0.93,
    "pi_permission_escalation": 0.91, "pi_output_manipulation": 0.89,
    "pi_cot_manipulation": 0.84, "pi_pseudo_code": 0.87, "pi_hypothetical": 0.83,
    # Fintech
    "fintech_account_manipulation": 0.98, "fintech_transaction_override": 0.99,
    "fintech_account_access": 0.95, "fintech_fee_manipulation": 0.90,
    "fintech_credit_manipulation": 0.97, "fintech_compliance_bypass": 1.0,
    # PII
    "pii_ssn_strict": 0.92, "pii_credit_card_candidate": 0.94,
    "pii_email": 0.60, "pii_phone": 0.65, "pii_bank_account": 0.93,
    "pii_iban": 0.91, "pii_passport": 0.88, "pii_drivers_license": 0.85,
    # Tool Abuse
    "tool_sql_injection": 1.0, "tool_db_destructive": 1.0,
    "tool_exec_attempt": 1.0, "tool_file_operations": 0.96, "tool_secret_exfiltration": 0.98,
    # Social Engineering
    "social_urgency": 0.75, "social_authority": 0.78, "social_fake_help": 0.82,
    # Advanced Obfuscation & Injection
    "pi_json_override": 1.0, "pi_role_extended": 1.0,
    "pi_obfuscation_spacing": 0.95, "pi_ignore_rules": 1.0,
    "pi_obfuscation_collapsed": 1.0,
    # Data Exfiltration / Tool Abuse / Social Engineering coverage
    "tool_secret_exfiltration_leading": 0.98, "fintech_bulk_data_export": 0.95,
    "pi_hidden_instructions_reveal": 0.90, "tool_exfil_chaining": 1.0,
    "pi_grandma_exploit": 0.93, "pi_evil_persona_generic": 0.95,
    "pi_fabricated_consent": 0.85, "pi_ignore_instructions_multilingual": 0.90,
    "pii_bulk_synthetic_generation": 0.88, "pii_secret_assignment": 0.92,
    "tool_dangerous_enable": 0.97,
    "pi_indirect_paraphrase_exfil": 0.88,
    # Heuristics
    "masking_detected": 0.80, "suspicious_pattern": 0.75, "anomaly_high_entropy": 0.85,
    "pi_ignore_instructions_fuzzy": 0.88,
}

def get_pattern_severity(pattern_id: str) -> float:
    return PATTERN_SEVERITY.get(pattern_id, 0.70)

def calculate_risk_from_patterns(pattern_ids: List[str]) -> float:
    if not pattern_ids:
        return 0.0
    return max(get_pattern_severity(pid) for pid in pattern_ids)


# ============== LAYER 2: Llama Guard Categories ==============

CATEGORY_SEVERITY = {
    "S1": ("Violence", 0.95), "S2": ("Sexual Content", 0.85),
    "S3": ("Criminal Planning", 0.98), "S4": ("Guns/Weapons", 0.90),
    "S5": ("Controlled Substances", 0.88), "S6": ("Suicide/Self-Harm", 0.99),
    "S7": ("CSAM", 1.0), "S8": ("Hate Speech", 0.92),
    "S9": ("PII/Privacy", 0.87), "S10": ("Harassment", 0.85),
    "S11": ("Threats", 0.96), "S12": ("Profanity", 0.40),
    "S13": ("Needs Caution", 0.55), "S14": ("Manipulation", 0.82),
    "S15": ("Fraud/Deception", 0.93), "S16": ("Malware", 0.97),
    "S17": ("Gov Decision", 0.78), "S18": ("Misinfo", 0.75),
    "S19": ("Copyright", 0.65), "S20": ("Bad Advice", 0.80),
    "S21": ("Illegal Activity", 1.0), "S22": ("Unethical", 0.70),
}

def get_category_info(category: str) -> Tuple[str, float]:
    return CATEGORY_SEVERITY.get(category, ("Unknown", 0.5))

def get_risk_score(category: str) -> float:
    return get_category_info(category)[1]

def get_category_name(category: str) -> str:
    return get_category_info(category)[0]


# ============== Adversarial Fatigue (session-level probing detection) ==============

def detect_adversarial_fatigue(
    risk_scores: List[float],
    threshold: float = 0.3,
    min_hits: int = 3,
    window: int = 5,
) -> bool:
    """Flags a session showing a pattern of repeated elevated-risk attempts
    (each individually resolved, e.g. via the council, but the pattern itself
    is a probing signal) rather than judging each prompt in isolation."""
    recent = risk_scores[-window:]
    hits = sum(1 for score in recent if score >= threshold)
    return hits >= min_hits
