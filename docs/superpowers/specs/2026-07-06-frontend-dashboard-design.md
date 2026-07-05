# Aegis WAF frontend dashboard — design spec

## Context

`repo.md` has always pitched a Streamlit dashboard (`frontend/app.py`, `components/risk_meter.py`, `components/trace_view.py`), but all three files are one-line stubs — the entire frontend is missing. Right now the only way to exercise `AegisGateway` is through CLI test scripts and raw Python calls. This is the highest-leverage gap identified in a broader "what should we upgrade next" review: it's the difference between a working pipeline and a demonstrable product.

An older architecture doc (`architecture (1).md`) sketches a React + FastAPI + WebSocket dashboard. That predates the actual Streamlit stub scaffolding decision and would require building a server layer, a WebSocket channel, and a JS toolchain that don't exist today — disproportionate to what this project needs. This spec builds on the Streamlit direction the repo already committed to.

## Purpose

An interactive live tester: type or pick a prompt, submit it, and watch it flow through the real `AegisGateway`, seeing the full decision (route, risk score, latency breakdown, council votes, explanation) — not a monitoring dashboard over synthetic/replayed traffic, since no live production traffic exists yet.

## Scope

- **Interactive live tester** as the primary surface, calling `gateway.chat()` (not bare `.process()`) so the demo shows the whole loop — WAF decision *and* the actual LLM answer when allowed — not just a classification result.
- **Multi-turn sessions**: each browser session gets a `session_id`; a running conversation view means `context_analyzer` actually receives prior turns (the session-history work wired up earlier in this project has no test surface exercising it yet — this is that surface). A "New Session" button resets both the UI conversation list and the underlying `session_id`.
- **Curated example picker**: a dropdown pulling up to 2 representative rows per category from `data/attack_dataset.csv` and `data/false_positives.csv` (~24-30 entries total across both files' ~12 categories) so a demo doesn't depend on the presenter improvising attack prompts live. Falls back to a small hardcoded set (one example per major category) if those CSVs aren't present (they're gitignored, so a fresh clone won't have them).
- **Session Log tab**: a table view of the current session's turns (turn #, prompt, decision, risk, route, latency, timestamp) plus a few aggregate numbers (block rate, route distribution), computed from the same in-memory conversation list — not a new data source.
- **Architecture tab**: static reference content describing the 3-layer pipeline, for demo narration. No live calls.
- **Visual design**: styled against the tokens in `synaptiq-interface-remixed-DESIGN.md` — Inter for nav/brand, Newsreader for the conversational feed, JetBrains Mono for every piece of system output (decision chips, risk numbers, pattern names, reason codes, latency), emerald `#10B981` for ALLOW/primary, blue `#3B82F6` for actions, 16px card radius throughout.

## Out of scope

- The design file's "Motion" and "WebGL & Effects" sections (masked reveals, particles, ambient canvas movement) are not realistic in Streamlit, which is server-rendered Python, not a JS app. Color, typography, spacing, and radius tokens are applied faithfully; the motion/effects layer is not attempted.
- No persistence of the Session Log across a "New Session" reset — each session's log is independent, in-memory only, cleared on reset.
- No new backend/API layer — the dashboard imports and calls `AegisGateway` in-process, exactly like the existing test scripts do.

## Architecture & file layout

```
frontend/
  app.py                  — entry point: page config, CSS injection, tab routing,
                            st.session_state management (session_id, conversation, gateway)
  theme.py                — Synaptiq tokens as Python constants + a function that
                            injects the <style> block (via st.markdown, unsafe_allow_html)
  examples.py             — loads curated example prompts from data/*.csv with a
                            hardcoded fallback if those files are absent
  components/
    risk_meter.py         — render_risk_meter(risk_score, decision) -> HTML string
    trace_view.py         — render_trace(response_dict) -> HTML string (reason_code,
                            patterns_matched, decodings, council votes, latency breakdown)
```

`app.py` builds one `AegisGateway` instance via `st.cache_resource` (built once per server process, not re-created on every Streamlit rerun — consistent with the singleton-reuse pattern already used for `core/gateway.py`'s own council instances). `session_id` and the conversation list live in `st.session_state`, since Streamlit reruns the whole script on every interaction and would otherwise lose them.

`requirements.txt` needs `streamlit` added — it's installed locally but was never declared as a project dependency despite the stub files already existing.

## Data flow

**Live Tester tab**
1. Example picker (optional) populates the text input; free-typing also works.
2. On Send: append the user turn to `st.session_state.conversation`, call `gateway.chat(prompt, session_id=st.session_state.session_id, context=context_text)`.
3. Append the response as the assistant turn. The rerun renders the updated feed: each turn shows a decision chip + risk meter (`risk_meter.py`) and an expandable trace (`trace_view.py`).
4. "New Session" clears `st.session_state.conversation` and issues a fresh `session_id` (`uuid4`), so `core/gateway.py`'s module-level session-history store starts clean for that id too.

**Session Log tab**
Renders `st.session_state.conversation` as a table (`st.dataframe`) plus aggregate metrics (block rate, route distribution) computed from the same list.

**Architecture tab**
Static markdown content describing the pipeline. No data flow to design around.

## Error handling

- `AegisGateway`'s `enable_llm` is already gated on `GROQ_API_KEY` being set; `.chat()` already returns `"[LLM not configured...]"` when it's not. The dashboard surfaces that as a visible notice banner rather than a silent blank response.
- `gateway.chat()` calls are wrapped in try/except per turn — a downstream failure shows a friendly error banner in the feed for that turn instead of crashing the whole Streamlit session.
- `examples.py` falls back to a small hardcoded example list if `data/attack_dataset.csv` / `data/false_positives.csv` are missing, so the picker always has something to show.

## Testing

Two tiers, since Streamlit apps don't unit-test cleanly end-to-end:
1. **Pure-function tests** for the non-UI logic: `examples.py`'s CSV-present and fallback paths, and `risk_meter.py`/`trace_view.py`'s render functions (confirm they return HTML containing the expected decision/risk substrings — not full snapshot testing).
2. **Manual verification**: run `streamlit run frontend/app.py`, confirm it serves without server-side exceptions (via HTTP checks and log inspection, since no browser-automation tool is available in this environment), and walk the golden path (benign prompt, attack prompt, new session) before calling the feature done. Visual/layout correctness cannot be confirmed this way and won't be claimed as verified.
