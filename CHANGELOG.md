# Changelog

## 1.0.0

- Promoted Gemini to the administrative planning manager for proactive workflow analysis, test selection, and reviewable tool-improvement proposals. Generated code remains a draft and is not automatically applied.
- Added an explicit dual-opt-in full-evidence path: `LH_STORE_RAW_EVIDENCE=1` preserves raw Burp request/response messages locally at import, and `LH_GEMINI_SEND_RAW_EVIDENCE=1` allows selected raw evidence to be sent to the configured LLM. This can include test tokens/cookies and is disabled by default.
- Added prompt handling for raw request/response evidence, including Authorization/Cookie headers and response content, while instructing the model not to repeat secrets in its output.
- Added regression tests for raw-evidence opt-in and administrative manager prompts.
- Verification: 92 tests passed; compileall passed. No live Gemini API call or external target test was performed.


## 0.9.0

- Added passive, deterministic signal plugins for URL-shaped inputs, XML-looking input, and redirect behavior; labels remain candidates, not confirmed vulnerabilities.
- Added an opt-in external plugin loader that is disabled by default, catches module import failures, and avoids duplicate loading. External plugins are explicitly documented as trusted local code, not sandboxed.
- Added a deterministic synthetic signal fixture generator and `check-detection` / `list-signal-plugins` commands. Regression checks now account for both missing expected signals and unexpected signals, including a clean negative control.
- Added tests for plugin errors, repeated loads, disabled-by-default external loading, detector semantics, and non-persistent fixture analysis.
- Preserved Gemini multi-key credential availability, while explicitly stopping key rotation on HTTP 429 quota/rate-limit responses. No quota bypass behavior was added.
- Verification: 89 tests passed; 7/7 synthetic signal fixtures passed; compileall passed. No live Gemini API call or external target test was performed.


## 0.6.0 — evidence-ranked reasoning and lower-noise comparisons

- Expanded the deterministic workflow/ownership regression corpus from 6 to 12 labelled cases and added fixture-only precision/recall counts. These metrics are explicitly not real-world estimates.
- Reduced false positives by comparing identity-shaped response fields only when both captures appear to refer to the same object; unrelated resources no longer get compared as if they were the same record.
- Added explainable hypothesis priority scoring, with owner/principal mismatch on a same-object signal ranked above identity-field differences and status-only contrasts. Scores are labelled as triage priority, not exploit probability.
- Tightened the Gemini reasoning prompt: one discriminating low-risk test, no invented fields or IDs, explicit evidence-versus-confirmation distinction, and a stable compact JSON contract.
- Added `LH_MAX_PROMPT_CHARS` (default 12000) and deterministic lower-priority context trimming to control prompt size while preserving task instructions and output contract.
- Added a distinct quota exception and local provider circuit-breaker for Gemini HTTP 429, preventing repeated calls on every candidate. Quota responses do not trigger key rotation.
- Added regression tests for prompt bounds, quota classification, same-object comparison, ranked hypotheses, and expanded fixture metrics.
- Verification in the local development environment: 72 tests passed; 12/12 synthetic cases passed; 3/3 loopback lab checks passed; compileall passed. No live Gemini API call or external target test was performed.

## 0.4.0 — 2026-10-19

- Added Gemini Flash provider support with compact JSON responses.
- Added a maximum-ten-key Gemini availability pool; HTTP 429 stops key rotation instead of evading provider quotas.
- Added `LH_GEMINI_ONLY=1` to prevent fallback to other configured providers.
- Added chronological request ordering using Burp timestamps when available, with explicit fallback metadata when they are missing.
- Added explicit import labels for `attacker`, `victim`, and `unknown` exports. Role labels participate in deduplication so the same request captured in two test accounts remains separate evidence.
- Added `context_engine.py` to build a compact metadata-only endpoint/timeline model and extract structural JSON keys without retaining raw response bodies in the context graph.
- Added `context-report`; provider prompts now receive focused site context and only the latest five iterations, while complete history remains persisted locally.
- Shortened and clarified the model's output requirements to prioritize the next discriminating test and concise rationale.
- Added regression tests for role-aware chronology, compact context privacy, Gemini response parsing, and stopping key rotation on HTTP 429.
- Existing safety design remains: generated code is not executed and test actions are schema-validated.


## 0.3.0 — 2026-10-18

- Added an explainable context graph connecting related review candidates across endpoint families, parameter names, signals, and source traffic.
- Added adaptive prioritization based on evidence richness, relationships, and under-observed signal families.
- Added persistent local outcome memory for signals and test actions.
- Added `adaptive-report` and `improvement-plan` commands for transparent learning statistics and reviewable improvement proposals.
- Extended LLM context with related candidate metadata while explicitly treating graph relationships as hypotheses, not proof.
- Kept source-code self-modification disabled; improvement proposals are not auto-applied.
- Added regression tests for graph construction, outcome memory, and deterministic ranking.


## 0.2.0 — 2026-10-18

- Fixed source links for correlated candidates.
- Tightened LLM plan validation and added nested JSON/form scalar mutation (`set_body_param`).
- Made host/subdomain and non-default-port scope rules explicit.
- Aligned baseline and live response hashing; made local verdicts conservative.
- Added shared request caps, global pacing, cookie-jar isolation, and two-part opt-in for state-changing HTTP methods.
- Improved nested JSON secret/PII redaction while preserving long numeric identifiers; preserved safe cookie attributes for header analysis.
- Added provider fallback and resilient local budget recovery.
- Archived stale sessions and persisted inconclusive cases in a manual-review queue.
- Added missing Burp fixtures and localhost live integration tests.

## v0.5.0 — workflow inference and cross-role differential evidence

- Added `workflow_engine.py` to infer chronological, role-scoped endpoint transitions and summarize route-level role contrasts.
- Added conservative cross-role ownership-differential hypotheses using identity-shaped JSON fields and status changes. These remain unconfirmed until account identity and object ownership are independently verified.
- `analyze` now persists a permission-restricted `data/workflow_model.json` metadata graph.
- Added `workflow-report`, deterministic offline `benchmark`, and loopback-only HTTP `lab-benchmark` CLI commands.
- Added regression coverage for chronology, role-scoped transitions, cross-role differences, privacy of persisted graph metadata, and benchmark behavior.


## 0.7.0
- Added Gemini-led manager loop with a strict local-tool allowlist, persistent checkpoints, event log, and bounded decision count.
- Added reviewable self-improvement proposal artifacts; model-generated changes are not auto-applied.
- Added `agent` CLI with explicit live-test opt-in and local scope/budget enforcement through the existing executor.
- Added manager decision validation tests.
