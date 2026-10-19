# Roadmap

## Implemented in this hardening pass

- Explicit wildcard scope semantics; exact hostname matching by default.
- Correlation candidates carry source request fingerprints.
- Strict LLM plan schema validation and bounded test values.
- Symmetric response-preview hashing.
- Nested JSON secret redaction and sensitive response-header redaction.
- Request-body preservation for analysis; environment-only credential/body overrides for live tests; safe mutation of existing JSON/form scalar fields, including nested GraphQL variables.
- Shared per-run request budget, bounded rate limiting, redirect suppression, and default blocking of state-changing methods with a separate two-part opt-in.
- Provider failover and attempted-call accounting.
- Session archival instead of destructive orphan cleanup.
- Persistent manual-review queue so inconclusive/high-signal cases are not silently discarded as rejected.
- Localhost integration tests for live response comparison and request-budget enforcement.

## Next steps before production use

1. Add account/record ownership fixtures so IDOR verification can distinguish public data from cross-account access.
2. Add deterministic response canonicalization for timestamps, CSRF values, and volatile fields without hiding security-relevant differences.
3. Add a durable job queue and crash-safe checkpoints for provider and request operations.
4. Add a permission model for explicitly approved state-changing tests, with a separate opt-in and audit log.
5. Add richer adapters for GraphQL and JSON API requests while retaining the same executor guard; current nested JSON variable mutation is intentionally limited to existing scalar fields.
6. Add a formal regression corpus for access control, authentication, session lifecycle, and business logic.
7. Run static analysis, dependency auditing, and test the package in clean Linux and Windows environments.

The project does not claim autonomous discovery of every vulnerability class. It is a guarded triage and verification harness; coverage depends on captured traffic, hypotheses, fixtures, and evidence quality.


## v0.5 implemented

- Role-scoped chronological workflow transitions and route-level cross-role comparisons.
- Optional known principal IDs for owner-to-requester mismatch hypotheses.
- Offline deterministic regression benchmark wired to `python logichunter.py benchmark`.
- Ephemeral loopback HTTP benchmark that checks a known vulnerable owner-mismatch fixture, a protected endpoint control, and a public endpoint control (`python logichunter.py lab-benchmark`).

## Remaining work that requires explicit data, not more autonomy

1. Add a curated, larger local lab corpus with authoritative principal-to-resource ownership maps and both positive/negative cases.
2. Add a lab-runner that exercises the HTTP executor against those fixtures and checks expected authorization invariants end-to-end.
3. Add richer workflow state extraction for GraphQL, CSRF, multi-step transactions, and asynchronous jobs, with per-adapter tests.
4. Measure precision/recall on held-out labelled cases before claiming general detection performance.


## v0.6.0 delivered

- Same-object gating for identity-field comparisons to reduce cross-record false positives.
- Explainable heuristic priority scores and 12-case synthetic regression metrics.
- Configurable prompt length budget and explicit evidence/uncertainty instructions.
- Quota-specific Gemini handling and persistent local circuit-breaker for HTTP 429.

## Next evidence-led priorities

1. Add a held-out corpus where expected access policies are written independently of the detector implementation.
2. Add nested JSON/GraphQL identity extraction fixtures and composite-resource-key matching.
3. Build a state-machine fixture format with preconditions, allowed principals, expected state transitions, and postconditions.
4. Add request/response canonicalization tests for volatile values without suppressing security-relevant fields.
5. Exercise provider adapters against mocked success, malformed JSON, invalid-key, transient 5xx, and quota responses; perform a separately authorized manual live API smoke test only after keys are configured locally.
