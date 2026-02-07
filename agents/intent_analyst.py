"""
Intent Analyst Agent - Adversarial reasoning for detecting malicious intent.

Uses CAMEL-AI with NVIDIA NIM (Llama 3.3) as the backend.
"""
import os
from pathlib import Path
from typing import Optional

from openai import OpenAI
from dotenv import load_dotenv

from .schemas import AgentAnalysis

load_dotenv()
PROMPT_PATH = Path(__file__).parent / "prompts" / "intent_analyst.txt"
SYSTEM_PROMPT = PROMPT_PATH.read_text() if PROMPT_PATH.exists() else ""


class IntentAnalyst:
    
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
        
        self.name = "intent_analyst"
    
    def analyze(self, prompt: str) -> AgentAnalysis:
        user_message = f"""Analyze the following user prompt for potential malicious intent:

<prompt>
{prompt}
</prompt>

Provide your analysis in the following format:
ASSESSMENT: [SAFE/UNSAFE/UNCERTAIN]
CONFIDENCE: [0.0-1.0]
REASONING: [Your detailed reasoning]
CONCERNS: [List any specific concerns, or "None" if safe]
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
    
    def respond_to_auditor(self, prompt: str, auditor_analysis: AgentAnalysis) -> AgentAnalysis:
        """
        Respond to the Policy Auditor's analysis (debate turn).
        
        Args:
            prompt: Original user prompt.
            auditor_analysis: The Policy Auditor's assessment.
            
        Returns:
            Updated AgentAnalysis after considering auditor's points.
        """
        user_message = f"""The Policy Auditor has reviewed the prompt and provided their assessment.

<original_prompt>
{prompt}
</original_prompt>

<policy_auditor_assessment>
Assessment: {auditor_analysis.assessment}
Confidence: {auditor_analysis.confidence}
Reasoning: {auditor_analysis.reasoning}
Concerns: {', '.join(auditor_analysis.concerns) if auditor_analysis.concerns else 'None'}
</policy_auditor_assessment>

Consider their analysis and either:
1. Maintain your position with additional reasoning
2. Update your assessment based on their valid points
3. Challenge their assessment if you disagree

Provide your updated analysis in the following format:
ASSESSMENT: [SAFE/UNSAFE/UNCERTAIN]
CONFIDENCE: [0.0-1.0]
REASONING: [Your detailed reasoning, addressing the auditor's points]
CONCERNS: [List any specific concerns, or "None" if safe]
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
