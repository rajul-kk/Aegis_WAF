"""
Dataset-Driven Test Suite for Aegis WAF
Reads from data/attack_dataset.csv and validates WAF decisions.
"""
import sys
import os
import csv
import time
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple

# Ensure we can import core modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from core.gateway import AegisGateway
    from agents.schemas import AegisResponse
except ImportError as e:
    print(f"Error importing core modules: {e}")
    sys.exit(1)

# Configuration
DATASET_PATH = os.path.join("data", "attack_dataset.csv")
LOG_FILE = "test_dataset_results.log"
ENABLE_FILE_LOGGING = True

# Colors for console output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(msg: str, color: str = ""):
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"
    print(f"{color}{formatted_msg}{Colors.ENDC}")
    if ENABLE_FILE_LOGGING:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")

def normalize_decision(decision: str) -> str:
    decision = decision.strip().upper()
    if "BLOCK" in decision:
        return "BLOCK"
    if "ALLOW" in decision:
        return "ALLOW"
    return decision

def run_dataset_tests():
    # clear log file
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"AEGIS WAF DATASET TEST REPORT - {datetime.now()}\n\n")

    log("Initializing Aegis Gateway...", Colors.HEADER)
    try:
        gateway = AegisGateway()
    except Exception as e:
        log(f"Failed to initialize gateway: {e}", Colors.RED)
        return

    if not os.path.exists(DATASET_PATH):
        log(f"Dataset not found at {DATASET_PATH}", Colors.RED)
        return

    log(f"Loading dataset from {DATASET_PATH}...", Colors.CYAN)
    
    cases = []
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases.append(row)

    total_tests = len(cases)
    passed_tests = 0
    start_time_all = time.time()
    
    results_by_category = {}

    log(f"Starting execution of {total_tests} test cases...", Colors.BOLD)

    for i, case in enumerate(cases):
        case_id = case.get("Case ID", f"Row-{i+1}")
        prompt = case.get("Prompt / Payload", "")
        expected = normalize_decision(case.get("Expected Decision", "BLOCK"))
        category = case.get("Category", "Unknown")
        description = case.get("Description / Notes", "")
        context = case.get("Context Content (retrieved_documents)", "")

        # Skip empty prompts
        if not prompt:
            continue

        log(f"\n[{i+1}/{total_tests}] Case {case_id}: {category}", Colors.BOLD)
        log(f"Prompt: {prompt[:80]}..." if len(prompt) > 80 else f"Prompt: {prompt}")

        try:
            # Gateway Processing (context simulates RAG/tool-output content
            # the prompt refers to, needed for Indirect Injection cases)
            response = gateway.process(prompt, session_id=f"test_ds_{case_id}", context=context)
            
            actual_decision = response.decision
            risk = response.risk_score
            pass_fail = (actual_decision == expected)
            
            # Special handling for allow_with_constraints
            if expected == "ALLOW" and actual_decision == "ALLOW":
                 pass_fail = True
            
            if pass_fail:
                passed_tests += 1
                result_color = Colors.GREEN
                log(f"PASS | Decision: {actual_decision} (Exp: {expected})", result_color)
            else:
                result_color = Colors.RED
                log(f"FAIL | Decision: {actual_decision} (Exp: {expected})", result_color)
            
            log(f"Risk: {risk:.4f} | Route: {response.route} | Patterns: {response.scan.patterns_matched}")
            
            # Update Category Stats
            if category not in results_by_category:
                results_by_category[category] = {"total": 0, "passed": 0}
            results_by_category[category]["total"] += 1
            if pass_fail:
                results_by_category[category]["passed"] += 1

        except Exception as e:
            log(f"ERROR processing case {case_id}: {e}", Colors.RED)

    total_time = time.time() - start_time_all
    
    log(f"\n{'='*50}", Colors.HEADER)
    log(f"DATASET TEST SUMMARY", Colors.BOLD)
    log(f"Total Tests: {total_tests}")
    log(f"Passed: {passed_tests}/{total_tests} ({passed_tests/total_tests*100:.1f}%)", Colors.GREEN if passed_tests == total_tests else Colors.YELLOW)
    log(f"Total Duration: {total_time:.2f}s")
    
    log(f"\n--- Category Breakdown ---", Colors.CYAN)
    for cat, stats in results_by_category.items():
        p = stats["passed"]
        t = stats["total"]
        pct = (p/t)*100 if t > 0 else 0
        log(f"{cat}: {p}/{t} ({pct:.1f}%)")

    log(f"{'='*50}", Colors.HEADER)
    log(f"Detailed logs saved to {LOG_FILE}", Colors.CYAN)

if __name__ == "__main__":
    run_dataset_tests()
