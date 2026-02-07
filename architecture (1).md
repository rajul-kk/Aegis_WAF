# AI WAF Architecture and Interfaces

## Summary
Build a latency-tiered AI WAF that prioritizes fast pass-through for safe prompts while escalating suspicious prompts to deeper AI reasoning.

Core design:
`Fast Scanner -> NeMo Risk Classifier -> Light/Full CAMEL Verification -> Explainability -> Adaptive Learning`.

Primary objective: minimize false positives and latency for legitimate prompts, while blocking prompt injection, jailbreak, and adversarial instructions with clear reasons.


## Decision-Complete Architecture

### Request Flow (Authoritative Behavior)
1. Ingest request with `request_id`, `session_id`, `user_prompt`, `tool_context`, and `policy_profile`.
2. Layer 1 Fast Scanner runs deterministic checks.
3. If Layer 1 hard-blocks, return `blocked` with reason codes and explanation.
4. Else Layer 2 NeMo-based classifier returns `risk_score` in `[0,1]`.
5. Routing:
   - `< 0.30`: Fast Track allow (skip CAMEL).
   - `0.30 - 0.70`: Light CAMEL verification.
   - `> 0.70`: Full CAMEL verification.
6. Layer 3 returns `allow`, `allow_with_constraints`, or `block`.
7. Layer 4 always produces structured explanation for non-allow decisions.
8. Layer 5 logs event and updates adaptive models/rules pipeline.

### Latency SLOs (p95)
- Layer 1: `<= 10 ms`
- Layer 2: `<= 60 ms`
- Low-risk total AI WAF overhead: `<= 80 ms`
- Medium-risk total overhead: `<= 350 ms`
- High-risk total overhead: `<= 900 ms`

### Blocking Policy Defaults
- Immediate block for explicit data exfiltration, credential theft, tool-abuse escalation, and policy override intent.
- `allow_with_constraints` for ambiguous medium-risk prompts (strip tool permissions, redact sensitive context, force safe system prompt).
- Human-readable block reason required for every blocked request.


## Tech Stack Recommendation

### Core Services
- API/Gateway: `FastAPI`, `Uvicorn`, `Pydantic v2`
- Async queue: `Redis` + `Redis Streams`
- Storage: `PostgreSQL` (audit logs, feedback, rule versions)
- Cache: `Redis` (hot rule cache, risk-score cache)
- Observability: `OpenTelemetry`, `Prometheus`, `Grafana`

### Layer 1 Fast Scanner
- Regex engine: `re2` via `pyre2`
- Optional acceleration: `Hyperscan` (`python-hyperscan`) for larger signature sets
- Heuristics: token/entropy checks, instruction-conflict checks, role override patterns, encoding/obfuscation detectors

### Layer 2 Intent Classifier (NeMo Guardrails)
- Framework: `NVIDIA NeMo Guardrails`
- Risk model: transformer classifier (`DeBERTa-v3` or `ModernBERT`) fine-tuned on jailbreak/prompt-injection corpora
- Calibration: `scikit-learn` isotonic calibration
- Policy rules: Colang flows + capability constraints

### Layer 3 CAMEL Verification
- Agent framework: `CAMEL-AI`
- Light CAMEL (medium risk):
  - Agents: `Intent Analyst`, `Policy Validator`
  - One reasoning round, strict timeout
- Full CAMEL (high risk):
  - Agents: `Intent Analyst`, `Policy Validator`, `Tool-Risk Auditor`, `Adversarial Simulator`, `Final Judge`
  - Two rounds + consensus
- Optional orchestration/tracing: `LangChain` callbacks or `LangSmith`

### Layer 4 Explainability Engine
- Structured taxonomy:
  - `prompt_injection`
  - `jailbreak_attempt`
  - `data_exfiltration`
  - `policy_violation`
  - `tool_abuse`
  - `obfuscation_attack`
- LLM explanation constrained by templates + reason codes

### Layer 3.5: Output Validator

Position: After CAMEL verification, before tool execution

**Purpose:** Validate AI-generated outputs BEFORE they execute tool calls or return to users.

**Components:**

1. **Tool Call Validator**
   - Whitelist of allowed tool names per policy profile
   - Parameter range validation (e.g., `limit <= 100`, no wildcards in delete)
   - Dangerous pattern detection (`DROP TABLE`, `rm -rf`, etc.)

2. **Response Content Scanner**
   - System prompt leakage detection
   - PII pattern matching (SSN, credit cards, emails in bulk)
   - Credential/secret pattern detection (API keys, tokens)
   - Instruction echo detection (repeating the attack prompt)

3. **Output Schema Enforcer**
   - Validate response matches expected JSON schema
   - Block malformed outputs that could exploit downstream systems

**Flow:**
- Input: AI-generated response or tool call
- Process: Run all three validators in parallel
- Output:
  - `allow`: Response passes through
  - `redact`: Response with sensitive content masked
  - `block`: Response blocked, return safe error

**Latency Target:** `<= 15ms` p95 (runs in parallel with response generation)

### Layer 5 Adaptive Feedback Loop
- Embeddings: `sentence-transformers`
- Novelty detection: `HDBSCAN` + centroid distance thresholds
- Auto-update pipeline:
  - Generate candidate regex/heuristics from clustered incidents
  - Shadow evaluate against benign holdout
  - Promote only when precision and false-positive guardrails pass
- Versioning: `MLflow` + DB version table

### Layer 6: Session Behaviour Monitor

Position: Runs continuously across session, parallel to per-request evaluation

**Purpose:** Detect multi-turn attacks, gradual privilege escalation, and anomalous session patterns.

**Components:**

1. **Session State Tracker**
   - Maintain per-session: request count, tool calls, topics, cumulative risk
   - Store in Redis with `session_id` key, TTL = session timeout

2. **Escalation Detector**
   - Track tool permissions requested across turns
   - Flag: benign -> sensitive -> admin tool progression
   - Example: `read_file -> write_file -> execute_command` = escalation

3. **Anomaly Scorer**
   - Request frequency anomaly (`> 10 requests/minute`)
   - Topic drift detector (embeddings cosine distance)
   - Cumulative risk threshold (sum of `risk_scores > 2.0`)

4. **Multi-Turn Attack Patterns**
   - "Warm-up" detector: N benign turns followed by attack
   - Fragmented injection: attack split across turns
   - Context poisoning: injecting malicious context in early turns

**Flow:**
- On each request: Update session state, run anomaly checks
- Flags:
  - `session_risk_elevated`: Add +0.2 to Layer 2 risk score
  - `session_blocked`: Block all further requests in session
  - `session_review`: Flag for human review

**Storage:**
- Redis: Real-time session state
- PostgreSQL: Completed session logs for ML training

**Latency Target:** `<= 5ms` (async, non-blocking check)

**Session State Schema:**
```json
{
  "session_id": "string",
  "request_count": "int",
  "cumulative_risk": "float",
  "tool_history": ["string"],
  "topic_embeddings": [["float"]],
  "first_request_at": "timestamp",
  "last_request_at": "timestamp",
  "flags": ["string"]
}
```

### Context Source Differentiation

**Purpose:** Handle indirect injection by tagging and differentiating input sources.

- Tag all inputs by source type: `user_direct`, `tool_output`, `rag_context`, `system`
- Apply stricter scrutiny to tool outputs and RAG context
- Patterns like "ignore previous" in tool outputs = high risk even if `user_direct` would be medium
- Different risk thresholds per source type


## Public APIs / Interfaces / Types

### `POST /v1/waf/evaluate`
Input:
- `request_id: string`
- `session_id: string`
- `prompt: string`
- `context: object`
- `requested_tools: string[]`
- `policy_profile: string`

Output:
- `decision: allow | allow_with_constraints | block`
- `risk_score: float`
- `route: fast_track | light_camel | full_camel`
- `reasons: string[]`
- `explanation: string`
- `sanitized_prompt: string | null`
- `allowed_tools: string[]`
- `latency_ms: object`

### `POST /v1/waf/feedback`
Input:
- `request_id: string`
- `label: false_positive | false_negative | correct_block | correct_allow`
- `analyst_notes: string`

Output:
- `feedback_status: string`
- `queued_for_adaptation: boolean`

### `GET /v1/waf/policy/version`
Output:
- `regex_version: string`
- `classifier_version: string`
- `camel_policy_version: string`
- `deployed_at: timestamp`


## Public APIs / Interfaces / Types (Additional)

### `POST /v1/waf/evaluate-output`

**Purpose:** Validate AI-generated outputs before execution.

Input:
- `request_id: string`
- `ai_response: string`
- `tool_calls: object[]`
- `policy_profile: string`

Output:
- `decision: allow | redact | block`
- `redacted_response: string | null`
- `blocked_tools: string[]`
- `reasons: string[]`


## Demo Dashboard Design

### Purpose
Visual interface for live demo showing real-time decisions, explanations, and metrics.

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  AI WAF Dashboard                              [Live] [Paused]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐  ┌─────────────────────────────┐  │
│  │   DECISION FEED         │  │   METRICS                   │  │
│  │                         │  │                             │  │
│  │ ● [ALLOW] "Help me..."  │  │  Requests: 247              │  │
│  │   12ms | fast_track     │  │  Blocked: 23 (9.3%)         │  │
│  │                         │  │  Constrained: 18 (7.3%)     │  │
│  │ ● [BLOCK] "Ignore..."   │  │                             │  │
│  │   340ms | full_camel    │  │  ┌─────────────────────┐    │  │
│  │   > Click to expand     │  │  │ Latency p95: 84ms   │    │  │
│  │                         │  │  │ ████████░░ 84/100   │    │  │
│  │ ● [CONSTRAIN] "Run..."  │  │  └─────────────────────┘    │  │
│  │   210ms | light_camel   │  │                             │  │
│  │                         │  │  Route Distribution:        │  │
│  └─────────────────────────┘  │  Fast Track:  ████████ 72%  │  │
│                               │  Light CAMEL: ███░░░░░ 19%  │  │
│  ┌─────────────────────────┐  │  Full CAMEL:  █░░░░░░░  9%  │  │
│  │   EXPLANATION PANEL     │  └─────────────────────────────┘  │
│  │                         │                                   │
│  │  Blocked Request #47    │  ┌─────────────────────────────┐  │
│  │  ─────────────────────  │  │   ATTACK BREAKDOWN          │  │
│  │                         │  │                             │  │
│  │  Prompt:                │  │   Prompt Injection: ████ 12 │  │
│  │  "Ignore all previous   │  │   Jailbreak:        ██░░  6 │  │
│  │   instructions and..."  │  │   Tool Abuse:       █░░░  3 │  │
│  │                         │  │   Obfuscation:      █░░░  2 │  │
│  │  Attack Type:           │  │                             │  │
│  │  prompt_injection       │  └─────────────────────────────┘  │
│  │                         │                                   │
│  │  Risk Score: 0.89       │                                   │
│  │  Route: full_camel      │                                   │
│  │                         │                                   │
│  │  Explanation:           │                                   │
│  │  "This prompt attempts  │                                   │
│  │   to override system    │                                   │
│  │   instructions using    │                                   │
│  │   a direct injection    │                                   │
│  │   pattern. The phrase   │                                   │
│  │   'ignore all previous' │                                   │
│  │   is a common attack."  │                                   │
│  │                         │                                   │
│  │  Safe Alternative:      │                                   │
│  │  "Can you explain how   │                                   │
│  │   system prompts work?" │                                   │
│  └─────────────────────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Dashboard Components

**1. Real-Time Monitor Panel (Decision Feed)**
- Live stream of requests: green (allow), yellow (constrained), red (block)
- Expandable cards showing full prompt, risk score, route taken, explanation
- WebSocket-powered real-time updates

**2. Analytics Panel (Metrics)**
- Pie chart: decision distribution (allow/constrain/block)
- Line chart: latency p50/p95/p99 over time
- Bar chart: attack type breakdown
- Request counter with percentage breakdowns

**3. Explanation Viewer**
- Plain-language explanation for each blocked request
- Attack taxonomy tag with visual badge
- Suggested safe reformulation
- Full request context on expand

### Tech Stack for Dashboard

```
Frontend:
- React + TypeScript
- TailwindCSS for styling
- Recharts for visualizations
- WebSocket for real-time feed

Backend Integration:
- WebSocket endpoint: ws://localhost:8000/ws/dashboard
- Pushes events: { type: 'decision', data: {...} }
- REST endpoint for historical queries: GET /v1/waf/decisions
```


## How We're Different

### Traditional WAF
- Regex-only pattern matching
- No AI understanding of context or intent
- High false positive rates on legitimate content
- No explanation for blocks

### Generic AI Guardrails
- Single threshold decision making
- No layered escalation
- Same latency for all requests
- Limited attack coverage

### This Solution: AI WAF
- **Tiered AI reasoning**: Fast deterministic checks + escalating AI verification
- **Adaptive learning**: Automatically learns from new attack patterns
- **Explainable decisions**: Every block includes human-readable reason
- **Latency-optimized**: 80ms for safe prompts, deeper analysis only when needed
- **Output validation**: Validates AI responses before execution (not just inputs)
- **Behaviour monitoring**: Detects multi-turn attacks and session anomalies


## Attack Taxonomy and Layer Coverage

| Attack Type | Layer 1 | Layer 2 | Layer 3 | Layer 3.5 | Layer 6 |
|-------------|---------|---------|---------|-----------|---------|
| Prompt Injection | Patterns | Intent | Verify | - | Multi-turn |
| Jailbreak | Keywords | Role detection | Consensus | - | Escalation |
| Data Exfiltration | Hard block | Intent | Verify | Response scan | - |
| Tool Abuse | Patterns | Risk score | Audit | Param validation | Progression |
| Obfuscation | Decode + scan | Embedding | Adversarial sim | - | - |
| Indirect Injection | - | Source tag | Full verify | - | Context poison |


## Latency Comparison

| Route | This Solution | Always Full Analysis |
|-------|--------------|---------------------|
| Benign prompt | ~80ms | ~1200ms+ |
| Medium risk | ~350ms | ~1200ms+ |
| High risk | ~900ms | ~1200ms+ |

**Savings:** 72% of requests (benign) process 15x faster than full analysis.


## Assumptions and Defaults
- English-first support for demo; multilingual expansion is next phase.
- Threshold defaults: `0.30` and `0.70` (configurable).
- CAMEL timeout default action: `allow_with_constraints`.
- Auto-promotion precision floor: `>= 0.98` on benign holdout.
- Demo corpus uses curated/synthetic attack data with no production PII.

