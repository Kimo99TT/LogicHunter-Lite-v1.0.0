# LogicHunter Lite v1.0.0 — Gemini administrative testing manager + full-evidence opt-in

LogicHunter Lite v0.7.0 is a **local-first, context-aware Burp traffic triage and verification harness**. It combines deterministic signals, optional LLM-generated test plans, a guarded HTTP executor, and evidence records. It is not a magic scanner and does not claim to discover every vulnerability class.

## What is included

- Safe Burp XML parsing with `defusedxml`.
- Request normalization, deduplication, and recursive secret redaction for JSON.
- Strict hostname scope rules: exact host by default; use `*.example.com` to allow subdomains explicitly.
- Deterministic signals for identity/resource parameters, auth response codes, server errors, error disclosure, admin/debug paths, CORS wildcard, missing headers, cookie flags, plus passive plugin signals for URL-shaped inputs, XML inputs, and redirect behavior.
- Correlation candidates for same-endpoint ID variations and similar responses with/without auth.
- Optional Gemini, DeepSeek, Groq, and Mistral planning with JSON validation and provider fallback.
- Chronological context model (`context_engine.py`) that summarizes endpoint patterns, parameter names, status distributions, and request order without storing raw response bodies in the context graph.
- Explicit per-export account-role labels (`attacker`, `victim`, `unknown`) and optional known principal IDs, enabling stronger owner-to-requester mismatch hypotheses without guessing from cookie values.
- Workflow inference (`workflow_engine.py`) for chronological role-scoped endpoint transitions, route-level contrasts, and cross-role owner-field checks.
- Offline synthetic signal regression checks (`python logichunter.py check-detection`) with expected and unexpected signal accounting; results are regression-only, not real-world accuracy estimates.
- Opt-in external passive signal plugins (`LH_ENABLE_EXTERNAL_PLUGINS=1`); importing external Python plugins executes local code, so only enable trusted files. Built-in plugins are always available.
- Offline 12-case workflow/ownership regression corpus with fixture-only precision/recall metrics (`python logichunter.py benchmark`), loopback-only HTTP lab benchmark (`python logichunter.py lab-benchmark`), and ranked workflow report (`python logichunter.py workflow-report`).
- Explainable hypothesis priority scores that explicitly represent triage priority, not exploit probability. Identity fields are compared only when captures appear to refer to the same object, reducing false positives from unrelated records.
- Bounded Gemini prompts (`LH_MAX_PROMPT_CHARS`, default 12000) that preserve decision rules and the JSON contract while trimming lower-priority context first.
- Persistent local provider circuit-breaker when Gemini returns HTTP 429, so each candidate does not repeatedly retry an exhausted quota; invalid-key fallback remains separate from quota handling.
- Compact context snapshots and short recent history to reduce repeated prompt tokens while preserving full local session history.
- Only four allowed test actions: `set_param`, `set_body_param`, `remove_cookie`, and a restricted `remove_header` set.
- Dry-run by default; `--live` is required for HTTP requests.
- Shared request budget and pacing, redirect suppression, non-default-port scope checks, and blocking of state-changing HTTP methods by default (with a separate two-part opt-in for approved lab tests).
- Localhost integration tests and a deliberately vulnerable local test application.
- Atomic session storage and archiving of stale sessions instead of silently deleting them.
- Explainable context graph connecting candidates by endpoint family, shared parameter names, shared traffic, and overlapping signals.
- Adaptive candidate prioritization based on evidence richness, related cases, and under-observed signal families.
- Local outcome memory across runs and a reviewable improvement-plan generator for repeated ambiguous/noisy signals.

## Install

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
cp config.example.yaml config.yaml
```

Edit `config.yaml` so `allowed_hosts` contains only hosts in your authorized scope. Subdomains require an explicit wildcard such as `*.example.com`; a bare `example.com` does not include subdomains. A non-default port must be explicitly listed, for example `127.0.0.1:9999`.

## Run tests

```bash
pytest -q
python -m compileall -q logichunter.py sessions.py providers.py context_engine.py workflow_engine.py adaptive.py vulnerable_app.py
```

The test suite includes an ephemeral localhost HTTP server. It does not send traffic to external systems.

## Basic workflow

```bash
python logichunter.py import-burp ./burp-export.xml --role unknown
# Export accounts separately; principal IDs are optional and must be known from the test setup:
# python logichunter.py import-burp ./attacker-export.xml --role attacker --principal-id attacker-1
# python logichunter.py import-burp ./victim-export.xml --role victim --principal-id victim-2
python logichunter.py analyze
python logichunter.py context-report
python logichunter.py workflow-report
python logichunter.py benchmark       # 12 labelled synthetic regression cases
python logichunter.py lab-benchmark  # loopback-only HTTP controls
python logichunter.py report
python logichunter.py test                 # dry-run only
python logichunter.py report-sessions
python logichunter.py report-review-queue
python logichunter.py adaptive-report
python logichunter.py improvement-plan
```

Live mode is opt-in and should only be used against targets you own or have explicit authorization to test:

```bash
python logichunter.py test --live --max-candidates 1 --rate-limit 1.0
```

Before using live mode, read [`docs/SECURITY.md`](docs/SECURITY.md).

## Optional LLM providers

Set only the API key for the provider you intend to use. Keys are read from environment variables and are not written into the project files. Gemini accepts `GEMINI_API_KEY` plus `GEMINI_API_KEY_1` through `GEMINI_API_KEY_10` (up to ten distinct keys are used). This pool is for credential availability/failover when a key is invalid or unavailable; **HTTP 429 quota/rate-limit responses stop Gemini key rotation**. Do not use multiple keys to bypass an exhausted quota; use the provider’s documented quota increase, wait for reset, or configure a separately permitted provider.

```bash
# Enter keys in your shell; do not commit them or paste them into chat.
read -rsp "Gemini API key: " GEMINI_API_KEY; echo; export GEMINI_API_KEY
export GEMINI_MODEL="gemini-2.5-flash"
# Optional additional keys for failover on invalid/unavailable keys:
# GEMINI_API_KEY_1 ... GEMINI_API_KEY_10
# To use Gemini only (no fallback to other configured providers):
export LH_GEMINI_ONLY=1
```

Model overrides: `GEMINI_MODEL`, `DEEPSEEK_MODEL`, `GROQ_MODEL`, `MISTRAL_MODEL`. The numbered Gemini key pool is capped at ten keys. A Gemini 429 quota/rate-limit response stops Gemini key rotation; keys must not be rotated to evade provider quotas. Local request budgets are estimates, not provider-authoritative quotas. Failed API attempts count against the local budget. If no API key is configured, the test loop stops without trying providers.

For a local lab only, live request credentials can be supplied through `LH_COOKIE` and `LH_AUTHORIZATION`. If the captured request body was redacted or omitted, set `LH_REQUEST_BODY` explicitly. These environment variables are never persisted by LogicHunter. Do not paste production credentials into prompts or source files. State-changing methods additionally require `LH_ALLOW_STATE_CHANGING=1` and `LH_CONFIRM_STATE_CHANGE=I_HAVE_AUTHORIZATION`; leave these unset for normal testing.

## Local lab demo

Terminal 1:

```bash
python vulnerable_app.py
```

It binds to `127.0.0.1:9999` and intentionally exposes insecure sample endpoints. It is for local testing only; do not expose it to a public network. The lab endpoints are intentionally simple and should not be treated as a complete benchmark.

## Important limitations

- A heuristic or AI plan is a hypothesis, not a finding.
- A status or response-body difference alone cannot prove IDOR; ownership and cross-account access need evidence.
- Authentication status changes are high-signal candidates, not automatic confirmation.
- Only GET, HEAD, and OPTIONS are sent by default. State-changing methods are blocked.
- The executor does not run arbitrary model-generated code or payloads.
- Adaptation learns outcome counts and prioritizes investigations; it does not rewrite Python source code automatically. Improvement proposals are advisory and must be implemented in an isolated branch with regression tests.
- The context graph stores candidate metadata only, not request/response bodies or secrets; graph links are investigation hints, not proof of a shared root cause.
- Coverage depends on captured traffic, supported request shapes, hypotheses, and verification quality.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SECURITY.md`](docs/SECURITY.md), and [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Workflow intelligence (v0.5.0)

After importing traffic and running `analyze`, LogicHunter also writes `data/workflow_model.json`. It models chronological endpoint transitions by the operator-supplied role label and highlights route-level differences between exports labelled `attacker` and `victim`.

```bash
python logichunter.py workflow-report
python logichunter.py benchmark       # 12 labelled synthetic regression cases
python logichunter.py lab-benchmark  # loopback-only HTTP controls
```

The workflow model stores route/method/status/parameter-name metadata, not response values. Optional `--principal-id` stores a known account/user identifier for evidence matching; never pass a password, cookie, API key, or session token as this value. Cross-role analysis inspects response previews in memory for identity-shaped JSON fields and emits **hypotheses only**. A role label does not authenticate the real user, and a response difference is not proof of IDOR. Verify account identity and resource ownership using a controlled lab or trusted application-side fixture before reporting a finding.

The offline benchmark is deterministic and useful as a regression gate for the implemented rules. It uses a tiny synthetic corpus and must not be described as a real-world detection-rate benchmark.


## Provider and prompt controls (v0.6.0)

Set `LH_MAX_PROMPT_CHARS` to bound prompt size (default 12000 characters). Invalid Gemini credentials may fall through to another configured key, but HTTP 429 stops key rotation and activates a local budget circuit-breaker. Multiple accounts must not be used to evade provider quotas.

## Gemini administrative manager agent (v1.0.0)

Gemini acts as the administrative planning manager: it chooses local tools, inspects workflow/context and adaptive outcomes, runs offline and loopback benchmarks, analyzes imported traffic, can start one guarded test batch per manager run (up to five candidates), and writes improvement proposals or draft unified diffs. Every decision and result is checkpointed in `data/agent_state.json` and `data/agent_events.jsonl`. It cannot auto-apply generated code or bypass the host allowlist/request executor.

```bash
# Manager mode: offline/local actions only unless --live is explicitly passed
python logichunter.py agent --max-steps 8

# Resume from the last checkpoint (default); start a fresh run instead:
python logichunter.py agent --max-steps 8 --no-resume

# Enable guarded live testing only for hosts in config.yaml allowed_hosts
python logichunter.py agent --max-steps 8 --live
```

Change proposals are saved under `data/agent_proposals/`; draft patches are saved there as `.patch` files. They are **not applied or executed automatically**. Review them in a branch and run the full test suite before applying. Gemini cannot run arbitrary shell commands, select arbitrary filesystem paths, or bypass the HTTP executor's host allowlist/request budgets. `--live` is an explicit opt-in; only test systems covered by written authorization should be added to `allowed_hosts`. Gemini API connectivity and quota must be verified in the operator's environment.



### Optional full raw HTTP evidence for Gemini

By default, imported requests are sanitized and raw HTTP messages are not stored. If your Burp export contains **dedicated test accounts** and you explicitly want Gemini to receive the full captured request/response (which may include `Authorization`, cookies, personal data, or other secrets), enable both flags:

```bash
# Set before importing Burp traffic, so raw messages are retained locally:
export LH_STORE_RAW_EVIDENCE=1
python logichunter.py import-burp ./test-account-export.xml --role attacker --principal-id test-account-a

# Set when running the analysis/manager to send stored raw evidence to Gemini:
export LH_GEMINI_SEND_RAW_EVIDENCE=1
export LH_GEMINI_ADMIN=1
python logichunter.py analyze
python logichunter.py test --max-candidates 1
# or: python logichunter.py agent --max-steps 8
```

**Important:** `LH_STORE_RAW_EVIDENCE=1` stores raw HTTP messages, including any credentials in the export, in `data/requests.jsonl`; file permissions are restricted where supported. `LH_GEMINI_SEND_RAW_EVIDENCE=1` transmits selected raw evidence to the configured external LLM provider. Only use this with test data you are authorized to share with that provider. The flags are independent: storing raw evidence does not send it to Gemini, and sending is ineffective if the import did not preserve raw evidence. When raw evidence sending is enabled, LogicHunter restricts the LLM provider for that test loop to Gemini so raw captures are not sent through a configured fallback provider. Turn both flags off when finished and remove raw test data if no longer needed. Gemini is an administrative planner, not an unrestricted shell/root process; proposed code changes remain reviewable patches and are not auto-applied.

## Passive signal plugins and synthetic regression

Built-in passive plugins flag URL-shaped values in URL-like parameters (`ssrf_input_candidate`), XML-looking input (`xml_input_candidate`), and redirect responses with redirect-like parameters (`redirect_behavior_candidate`). These are **triage indicators only**, not proof of SSRF, XXE, or open redirect. Run `python logichunter.py list-signal-plugins` to list registered detectors and `python logichunter.py check-detection` to run the synthetic regression corpus.

External plugins are disabled by default. To enable trusted Python files in `plugins/`, set `LH_ENABLE_EXTERNAL_PLUGINS=1`. A plugin must define `register_plugins(register_fn)`. Plugins execute as local Python code and are not sandboxed; never load untrusted plugin files.
