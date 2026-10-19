# Architecture

1. **Import** — `logichunter.py` parses Burp XML using `defusedxml`, normalizes HTTP messages, redacts sensitive fields, applies the configured host allowlist, and deduplicates records.
2. **Analyze** — deterministic heuristics and same-endpoint correlations create review candidates. These are hypotheses, not findings.
3. **Plan** — `providers.py` sends a bounded, redacted context to a configured LLM provider. Providers only return JSON plans; they cannot reach the target.
4. **Guard** — `sessions.py` validates the plan schema, checks scope, applies action allowlists, enforces request caps and method restrictions, and performs the only target HTTP calls. It can change query parameters or existing JSON/form scalar fields; state-changing methods require a separate explicit opt-in.
5. **Verify** — local logic compares status and sanitized response evidence. It never uses the model's confidence as proof. IDOR-like differences remain ambiguous without ownership evidence.
6. **Context graph** — `adaptive.py` links candidates by normalized endpoint family, parameter names, overlapping signals, and shared source traffic. The graph stores metadata only; edges explain why cases are related but do not establish a common root cause.
7. **Adapt** — local verdicts update persistent outcome counts. Candidate priority adjusts toward richer evidence, related cases, under-observed signals, and unresolved patterns. `improvement-plan` suggests regression tests or heuristic reviews when repeated outcomes justify them.
8. **Persist** — session and learning files are written atomically with restrictive permissions where supported. Stale sessions are archived instead of destroyed.

## Trust boundaries

- Imported Burp data: untrusted, may contain secrets or prompt injection.
- LLM provider output: untrusted and schema-validated.
- Target HTTP traffic: disabled unless `--live` is supplied and the host is allowlisted.
- Credentials: environment-only overrides; do not commit them or put them into prompts.

## Provider selection

The local daily request counts are estimates, not authoritative provider quotas. Failed API attempts count against the local budget. If a provider fails, the loop tries the next provider with remaining budget. Set `DEEPSEEK_API_KEY`, `GROQ_API_KEY`, or `MISTRAL_API_KEY` only for providers you intend to use.


## Bounded self-improvement

The agent improves its *investigation strategy* from local outcomes and keeps a small, explainable record of why cases are connected. It does not fine-tune a model, learn from a target without evidence, or modify its own Python source automatically. Source changes must be made in an isolated working copy and pass the regression suite before promotion. This avoids turning a noisy result or prompt injection into a permanent code change.


## v0.4 chronological context

`context_engine.py` sorts imported requests using Burp timestamps when available and builds a bounded metadata-only site model: endpoint/method, parameter names, status distributions, response MIME/length signatures, explicit account-role labels, and a compact recent timeline. It does not store raw response bodies or cookie values in the context model. `context-report` prints a small summary. `providers.build_context_prompt` receives a focused compact view plus recent iterations; the complete session history remains stored locally for resume.

Account roles are explicit labels supplied at import time (`--role attacker|victim|unknown`). Export test accounts separately when attribution matters. Missing Burp timestamps fall back to import order and are marked `timestamp_source=import_order_fallback`; they must not be treated as authoritative capture time.

Gemini support uses `GEMINI_API_KEY` and optional numbered key variables. The key pool is for availability/invalid-key failover only. HTTP 429 stops key rotation rather than using multiple keys to evade provider quotas. `LH_GEMINI_ONLY=1` disables fallback to other LLM providers for a run.


## v0.5 workflow and ownership hypotheses

`workflow_engine.py` infers role-scoped transitions from chronological route events, highlights route-level status/length differences, and compares identity-shaped response fields across separately labelled exports. When the operator supplies a known `--principal-id`, it can flag a response owner field that matches the victim principal rather than the requesting attacker principal, provided the compared requests point to the same object. Evidence values are not copied into the report. All such results remain hypotheses; the tool does not independently authenticate the labels or know the application's intended public/private policy. `workflow-report` emits the graph and hypotheses. `benchmark` runs a deterministic synthetic regression fixture set, not a real-world performance evaluation.

## Gemini manager loop (v0.7.0)

`agent_manager.py` adds a checkpointed manager loop. Gemini emits one structured decision per step; the local runner validates the action against an allowlist and dispatches only typed local tools (status, workflow/context inspection, offline/loopback benchmarks, review queue, adaptive statistics, analysis, one bounded test batch, or a saved change/patch proposal). State is stored in `data/agent_state.json`; the append-only audit trail is `data/agent_events.jsonl`.

A manager run permits at most one test batch, capped at five candidates. Live HTTP verification requires the operator's explicit `--live` flag and continues through the existing executor's `allowed_hosts`, action validation, and request budgets. The manager cannot invoke arbitrary shell commands or arbitrary URLs. Proposed patches are stored as review artifacts and are never applied or executed by the model. A human should inspect and apply any change in a branch, then run the full regression suite.
