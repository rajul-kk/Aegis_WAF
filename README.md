# Aegis WAF

Aegis is a multi-layer firewall for LLM applications, built to catch prompt injection, jailbreaks, and adversarial instructions in a fintech/trading context. It fast-tracks safe prompts and only spends deeper (and slower) AI reasoning on the ones that actually need it.

## Architecture

Requests move through four layers, escalating only as far as needed:

1. **Layer 0 — Preprocessor** (`agents/preprocessor.py`)
   Decodes common obfuscation — Base64, ROT13, hex, Morse code, leetspeak, reversed text, spaced-out letters, Cyrillic/Greek homoglyphs — before anything else looks at the text, so hidden attacks can't hide behind an encoding.

2. **Layer 1 — Fast Scanner** (`config/actions.py`)
   ~50 regex/heuristic patterns (prompt injection, fintech-specific abuse, PII, SQL/tool abuse, social engineering) plus fuzzy typo-matching for evasion attempts. Any match blocks immediately — no LLM call, no meaningful latency.

3. **Layer 2 — Llama Guard Classification** (`core/classifiers.py`)
   A single classifier call (Llama Guard 3, via NVIDIA NIM) scores the prompt 0.0–1.0. Routing: `< 0.30` → allow, `0.30–0.70` → full council, `0.70–0.99` → light council, `≥ 0.99` → immediate block.

4. **Layer 3 — Security Council** (`agents/security_council.py`)
   A multi-agent debate for ambiguous cases. **Light mode** runs `intent_analyst` → `policy_auditor` sequentially (a real debate turn). **Full mode** runs 5 agents in parallel — `intent_analyst`, `policy_auditor`, `adversarial_tester`, `context_analyzer`, `data_guardian` — with an early cutoff once 3 of 5 agree. The agents deliberately span two model families (Llama and Mixtral) rather than one, so a false consensus can't come from one model talking to itself five times.

Beyond the core pipeline:
- **Output validation** re-screens the LLM's response — a regex rescan or Llama Guard reclassification depending on the input's risk band, plus an unconditional check for exfiltration-shaped markdown links/images (the EchoLeak/CVE-2025-32711 pattern) regardless of how safe the input looked.
- **Adversarial fatigue tracking** — a session with repeated elevated-risk attempts gets escalated to the council even if the current prompt alone looks low-risk, instead of judging every prompt in isolation.
- **Session history** persists in Redis (`core/session_store.py`), shared across processes and surviving restarts; degrades gracefully to no-op if Redis is unavailable rather than failing the request.

## Project layout

```
core/           gateway, session store, severity scoring, Llama Guard classifier
agents/         preprocessor + the 5 council agents + orchestration
config/         Layer 1 regex patterns and scan heuristics
backend/        FastAPI REST + WebSocket API wrapping the gateway
web/            React Live Tester frontend (talks to backend/)
frontend/       Streamlit dashboard (separate, manually-run ops tool)
scripts/        standalone verification/benchmark scripts (not the pytest suite)
tests/          pytest suite
data/           benchmark CSV fixtures (attack + false-positive datasets)
docs/           design/reference notes (gitignored, local-only)
```

## Prerequisites

- Python 3.10+
- Node 18+ (only if running the React frontend)
- Redis (session persistence; the gateway degrades gracefully without it, just loses multi-turn context)
- An NVIDIA NIM API key (Llama Guard classification + all council agents)
- A Groq API key (only needed for `AegisGateway.chat()`'s answer generation; the WAF decision itself doesn't require it)

## Setup

```bash
git clone <this-repo>
cd Aegis_WAF
python -m venv venv
./venv/Scripts/activate      # Windows
# source venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
cp .env.example .env         # then fill in real API keys
```

## Running it

**Everything via Docker (backend + Redis + React, local/demo scope — no auth/TLS):**
```bash
docker compose up
```
Backend on `:8000`, React app on `:8080`.

**Or run pieces individually:**
```bash
# FastAPI backend (REST + WebSocket)
uvicorn backend.main:app --reload

# React Live Tester (in web/, proxies to the backend via Vite dev server)
cd web && npm install && npm run dev

# Streamlit ops dashboard (separate from the above, not containerized)
streamlit run frontend/app.py
```

**Tests and benchmarks:**
```bash
pytest tests/                      # unit/integration suite
python scripts/test_dataset.py     # 80-case attack dataset benchmark
```
Both benchmarks currently sit at 100% (80/80 attack cases, 18/18 false-positive cases). CI (`.github/workflows/test.yml`) runs the pytest suite and the attack benchmark against a real Redis service on every push/PR.

`scripts/` also has several other standalone verification scripts (`test_severity.py`, `test_failures.py`, `test_prompts.py`, etc.) used during development — run any of them directly with `python scripts/<name>.py` from the repo root.
