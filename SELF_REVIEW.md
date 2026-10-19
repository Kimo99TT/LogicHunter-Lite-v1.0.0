# Self-review: what is improved and what is still not solved

## Corrections made in this pass

- Correlation candidates now retain source request fingerprints, so the test loop can find the underlying request.
- The response hash comparison uses a preview length consistent with the stored baseline.
- One response difference no longer auto-confirms IDOR. Multiple differences remain a candidate until ownership is proven.
- A status change to 200 after an authentication-related mutation is treated as a high-signal candidate, not conclusive proof by itself.
- LLM plans have strict action, parameter, value-count, value-length, and confidence validation.
- Query and existing JSON/form body fields can be varied. Nested paths such as `variables.id` support common GraphQL request shapes.
- Provider failures fall through to the next configured provider; local attempt budgets count failed API attempts.
- Missing provider keys are detected before API attempts.
- Requests share a run-wide budget and rate limiter, and response cookies from one probe are not silently reused in the next.
- Subdomains and non-default ports require explicit allowlist entries.
- Unknown content types are omitted from persisted request bodies; nested secret/PII fields and sensitive headers are redacted.
- Cookie security attributes are retained after cookie values are redacted, so the analyzer can still inspect `Secure`, `HttpOnly`, and `SameSite`.
- Ambiguous cases go to a persistent manual-review queue rather than being silently marked rejected when the iteration cap is reached.
- Missing test fixtures were added, and the live-local regression suite now exercises the executor against an ephemeral localhost server.

## Deliberate limitations

- The tool does not autonomously write and execute arbitrary code. Model-generated actions stay within a reviewed, narrow executor interface. This reduces flexibility but prevents a model response from becoming arbitrary shell or network execution.
- It cannot prove IDOR from status, length, or hash changes alone. A credible proof needs a controlled two-account fixture, a known owner identity, and evidence that one account accessed another account's protected object.
- JSON body mutation only changes existing scalar fields; it does not synthesize missing fields, deeply restructure objects, or understand every GraphQL operation.
- State-changing methods are blocked unless two explicit environment flags are set. This reduces accidental writes but is not a substitute for authorization or a staging environment.
- The allowlist validates host and port syntax but does not pin DNS resolutions. For higher assurance, run through a controlled proxy or network namespace and consider DNS/IP pinning.
- Provider budgets are local estimates and cannot know the real remaining quota or billing state of an API account.
- The response parser stores previews rather than complete response bodies. This protects data and reduces cost, but may miss evidence beyond the preview boundary.
- No external target, paid API, or real bug-bounty program was tested in this pass.

## Verdict

This is a more reliable guarded triage harness, not a universal autonomous vulnerability hunter. Its strongest next improvement is a repeatable two-account lab with explicit ownership assertions, followed by regression cases for authorization, session lifecycle, and business-logic invariants. More autonomy without better evidence would mainly increase traffic and false positives, not necessarily real discoveries.


## v0.4.0 self-review

### Improvements delivered
- Added a compact chronological context model and explicit per-export account labels.
- Added Gemini integration, local request accounting, and focused prompts.
- Added regression tests for Gemini JSON parsing and stopping key rotation on quota/rate-limit responses.

### Known limitations that remain
- Account labels are supplied by the operator; the tool cannot reliably infer the real owner of an opaque session token. Mixed-account exports should be separated.
- The context model is structural and bounded; it does not semantically understand every application workflow or infer business rules from traffic alone.
- The executor still supports a narrow action vocabulary. This is deliberate: unrestricted model-generated code would make outcomes difficult to reproduce and could damage targets. New actions should be reviewed and tested in the local lab first.
- A 200/403 status or response-size difference is not proof of IDOR. Cross-account ownership evidence is still required.
- The Gemini API model name and account quota are external configuration; verify current availability in AI Studio. This project does not guarantee free quota or bypass 429 responses.
- The 58-test suite checks current behavior, not discovery rate on real bug-bounty programs. A controlled benchmark with known positive and negative cases is needed before claiming improved detection.

## v0.5.0 self-review — workflow intelligence

### Delivered
- Role-scoped chronological route transitions and route-level role contrasts.
- Conservative same-route comparison of status and identity-shaped JSON fields across separately labelled attacker/victim imports.
- Offline fixture benchmark wired into the CLI and test suite.
- Workflow graph persisted as metadata only; response identity values are not copied into the graph.

### Remaining gaps that are material, not cosmetic
- The engine cannot infer real principal identity from role labels. The operator must ensure exports actually correspond to distinct known accounts.
- Route transitions are only as complete as the captured traffic and do not establish causality or business rules.
- Identity-field differences and status changes remain review hypotheses. Reliable ownership proof requires an authoritative principal-to-account mapping and known resource owner in the lab; this version does not claim that proof.
- The six-case benchmark is a regression fixture suite, not an empirical vulnerability-detection benchmark. A larger curated corpus with expected policy, owner IDs, negative controls, and blinded evaluation is needed before quoting detection metrics.
- The workflow model currently summarizes endpoint-level transitions rather than full request-body state machines; CSRF, asynchronous flows, GraphQL semantics, and multi-step transaction invariants need explicit fixtures and reviewed adapters.


## v0.6.0 self-review — evidence quality and prompt control

### Delivered
- Identity-shaped response fields are compared only when captures appear to refer to the same object, reducing a clear false-positive pattern from comparing unrelated resources.
- Hypotheses receive a deterministic, explainable triage-priority score. This is not a calibrated probability and must not be reported as one.
- The regression suite now has 12 synthetic labelled cases and reports fixture precision/recall alongside raw counts. The observed 100% fixture metrics only describe this tiny synthetic set.
- Gemini prompts have a configurable character bound and prioritize decision rules/output schema over lower-value context.
- A Gemini 429 is represented as a quota-specific error and trips a local budget circuit-breaker, preventing repeated attempts across candidates. The key pool is not used to evade quota limits.

### Remaining evidence gaps
- No live Gemini request was made; model availability, response schema behavior, billing and quotas remain unverified in this environment.
- The fixture corpus is small and partly constructed around the detector's own rules, so it cannot support claims about real-world detection rate or superiority to commercial tools. A held-out corpus and independent expected outcomes are required.
- Cross-role labels and principal IDs still come from the operator. Same-object matching is heuristic and can be wrong when applications use composite identifiers, tenant scopes, or nested response shapes.
- The score is a triage ordering aid, not calibrated confidence. The current executor still uses a narrow reviewed action set, intentionally avoiding model-generated arbitrary code.
