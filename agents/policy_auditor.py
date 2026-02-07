"""
Policy Auditor Agent - Compliance checking and policy enforcement.

Uses CAMEL-AI with NVIDIA NIM (Llama 3.3) as the backend.
"""
import os
from pathlib import Path
from typing import Optional

from openai import OpenAI
from dotenv import load_dotenv

from .schemas import AgentAnalysis

load_dotenv()
PROMPT_PATH = Path(__file__).parent / "prompts" / "policy_auditor.txt"
SYSTEM_PROMPT = PROMPT_PATH.read_text() if PROMPT_PATH.exists() else ""




class PolicyAuditor:
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or os.getenv("NVIDIA_API_KEY")
        self.base_url = base_url or os.getenv(
            "NVIDIA_BASE_URL", 
            "https://integrate.api.nvidia.com/v1"
        )
        self.model = model or os.getenv("LLAMA_MODEL", "meta/llama-3.3-70b-instruct")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )
        
        self.name = "policy_auditor"
    
    def audit(self, prompt: str, intent_analysis: Optional[AgentAnalysis] = None) -> AgentAnalysis:
        intent_context = ""
        if intent_analysis:
            intent_context = f"""
<intent_analyst_assessment>
Assessment: {intent_analysis.assessment}
Confidence: {intent_analysis.confidence}
Reasoning: {intent_analysis.reasoning}
Concerns: {', '.join(intent_analysis.concerns) if intent_analysis.concerns else 'None'}
</intent_analyst_assessment>

Consider the Intent Analyst's assessment but form your own independent judgment focused on policy compliance.
"""
        
        user_message = f"""Audit the following user prompt for policy compliance:

<prompt>
{prompt}
</prompt>
{intent_context}
Provide your analysis in the following format:
ASSESSMENT: [SAFE/UNSAFE/UNCERTAIN]
CONFIDENCE: [0.0-1.0]
REASONING: [Your detailed reasoning]
CONCERNS: [List any specific policy concerns, or "None" if compliant]
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
            max_tokens=1024,
        )
        
        content = response.choices[0].message.content
        return self._parse_response(content)
    
    def respond_to_analyst(self, prompt: str, analyst_analysis: AgentAnalysis) -> AgentAnalysis:
        user_message = f"""The Intent Analyst has updated their assessment.

<original_prompt>
{prompt}
</original_prompt>

<intent_analyst_assessment>
Assessment: {analyst_analysis.assessment}
Confidence: {analyst_analysis.confidence}
Reasoning: {analyst_analysis.reasoning}
Concerns: {', '.join(analyst_analysis.concerns) if analyst_analysis.concerns else 'None'}
</intent_analyst_assessment>

Consider their updated analysis and either:
1. Maintain your position with additional reasoning
2. Update your assessment based on their valid points
3. Challenge their assessment if you disagree

Provide your updated analysis in the following format:
ASSESSMENT: [SAFE/UNSAFE/UNCERTAIN]
CONFIDENCE: [0.0-1.0]
REASONING: [Your detailed reasoning, addressing the analyst's points]
CONCERNS: [List any specific policy concerns, or "None" if compliant]
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
            max_tokens=1024,
        )
        
        content = response.choices[0].message.content
        return self._parse_response(content)
    
    def _parse_response(self, content: str) -> AgentAnalysis:
        """Parse the model response into an AgentAnalysis object."""
        lines = content.strip().split("\n")
        
        assessment = "UNCERTAIN"
        confidence = 0.5
        reasoning = ""
        concerns = []
        
        current_section = None
        reasoning_lines = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("ASSESSMENT:"):
                value = line.replace("ASSESSMENT:", "").strip().upper()
                if value in ["SAFE", "UNSAFE", "UNCERTAIN"]:
                    assessment = value
                    
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = float(line.replace("CONFIDENCE:", "").strip())
                    confidence = max(0.0, min(1.0, confidence))
                except ValueError:
                    confidence = 0.5
                    
            elif line.startswith("REASONING:"):
                current_section = "reasoning"
                text = line.replace("REASONING:", "").strip()
                if text:
                    reasoning_lines.append(text)
                    
            elif line.startswith("CONCERNS:"):
                current_section = "concerns"
                text = line.replace("CONCERNS:", "").strip()
                if text and text.lower() != "none":
                    concerns.extend([c.strip() for c in text.split(",") if c.strip()])
                    
            elif current_section == "reasoning" and line:
                reasoning_lines.append(line)
                
            elif current_section == "concerns" and line and line.lower() != "none":
                concerns.extend([c.strip() for c in line.split(",") if c.strip()])
        
        reasoning = " ".join(reasoning_lines)
        
        return AgentAnalysis(
            agent_name=self.name,
            assessment=assessment,
            confidence=confidence,
            reasoning=reasoning or content,
            concerns=concerns,
        )
