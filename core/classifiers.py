"""Llama Guard Classifier with logprobs-based risk scoring"""

import sys
import os
_dir = os.path.dirname(__file__)
if _dir not in sys.path:
    sys.path.insert(0, _dir)
if os.path.join(_dir, '..') not in sys.path:
    sys.path.insert(0, os.path.join(_dir, '..'))

from typing import Optional

from config.actions import _llama_guard_prompt, _run_llama_guard_sync
from agents.schemas import RiskAssessment
from agents.preprocessor import preprocess_prompt
from severity import get_risk_score, get_category_name

# Zero-tolerance categories - always route to Full CAMEL
ZERO_TOLERANCE = {"S7", "S21", "S6", "S3"}  # CSAM, Illegal, Suicide, Criminal


class LlamaGuardClassifier:
    def __init__(self):
        pass

    def classify(self, prompt: str, preprocessed: Optional[str] = None) -> RiskAssessment:
        # Callers that already ran preprocess_prompt (e.g. the gateway, which
        # needs it for Layer 1 too) can pass the result through to avoid
        # decoding the same text twice.
        if preprocessed is None:
            preprocessed, _decodings = preprocess_prompt(prompt)

        # Use preprocessed text for Llama Guard analysis
        guard_prompt = _llama_guard_prompt(preprocessed)
        result = _run_llama_guard_sync(guard_prompt)
        
        category = result.get("category", "None")
        harmful = result.get("harmful", "unharmful")
        confidence = result.get("confidence", 0.85)
        
        if harmful == "harmful" and category != "None":
            category_name = get_category_name(category)
            severity = get_risk_score(category)
            
            # Hybrid risk calculation
            if category in ZERO_TOLERANCE or severity >= 0.99:
                # Force max risk for zero-tolerance categories
                risk_score = 1.0
            else:
                # Category severity acts as a floor so classifier confidence
                # can never under-rate an inherently high-severity category
                risk_score = max(confidence, severity)
        else:
            risk_score = 0.0
            category_name = None
        
        return RiskAssessment(
            score=risk_score,
            category=category_name,
            is_safe=(harmful == "unharmful"),
            raw_response=result.get("raw_output", "")
        )
