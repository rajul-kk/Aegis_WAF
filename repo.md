sentinel-v/
├── config/                  # The "Brain" of the WAF 
│   ├── config.yml           # NeMo Guardrails model routing & rail activation
│   ├── main.co              # Colang 2.x flow logic (Tiered Routing)
│   └── actions.py           # Custom Python Actions (RuleScanner, SecretScrubber)
│
├── core/                    # Backend Logic & Integration
│   ├── __init__.py
│   ├── gateway.py           # Main entry point: prompt -> risk_score -> route
│   ├── classifiers.py       # Llama Guard 3 logic & logprob/risk calculation
│   └── main_llm.py          # Gemini 1.5 Flash client wrapper
│
├── agents/                  # CAMEL-AI Multi-Agent Society
│   ├── __init__.py
│   ├── security_council.py  # Orchestrates the "Debate" logic
│   ├── intent_analyst.py    # Role: Adversarial Reasoning Agent
│   └── policy_auditor.py    # Role: Compliance & Corporate Policy Agent
│
├── frontend/                # Streamlit Dashboard
│   ├── app.py               # Main UI script
│   ├── components/          # Reusable UI elements (RiskMeter, TraceView)
│   └── assets/              # Logos and architecture diagrams
│
├── tests/                   # The "Attack Bank"
│   ├── payloads/            # JSON/Text files with jailbreaks & injections
│   └── test_gateway.py      # Automated benchmark for latency & detection
│
├── .env                     # API Keys (NVIDIA, GOOGLE) - DO NOT COMMIT
├── .gitignore               # Ignores .env, __pycache__, and venv
├── requirements.txt         # Project dependencies
└── README.md                # Pitch, architecture diagram, and setup guide