# Security and scope rules

LogicHunter is for systems you own or have explicit written authorization to test.

## Mandatory safeguards

- Network is disabled by default. `--live` is required to send any target request.
- `allowed_hosts` is a strict allowlist. A hostname matches exactly; subdomains require an explicit `*.example.com` entry.
- Only HTTP and HTTPS URLs are accepted. Redirect following is disabled.
- The executor accepts only `set_param`, `set_body_param`, `remove_cookie`, and a restricted `remove_header` set, with strict type and size limits.
- Requests are capped per run and paced across candidates. The default run cap is 30 requests. Non-default ports must be explicitly allowlisted (for example `127.0.0.1:9999`).
- `GET`, `HEAD`, and `OPTIONS` are the only methods sent by default. `POST`, `PUT`, `PATCH`, and `DELETE` require both `LH_ALLOW_STATE_CHANGING=1` and `LH_CONFIRM_STATE_CHANGE=I_HAVE_AUTHORIZATION`; use these only with explicit approval and preferably in a test environment.
- By default, credentials in imported Burp traffic are redacted and raw messages are not stored. Optional full-evidence mode is available for authorized test accounts: set `LH_STORE_RAW_EVIDENCE=1` before import to retain raw HTTP messages locally, then set `LH_GEMINI_SEND_RAW_EVIDENCE=1` to send selected raw evidence to the configured LLM. Raw messages can contain bearer tokens, cookies, and private data. Enable only when you accept that the selected evidence is transmitted to the external provider; turn it off and securely remove local raw captures after testing. For a local lab, `LH_COOKIE`, `LH_AUTHORIZATION`, and `LH_REQUEST_BODY` are not persisted by the application. Never commit credentials or test captures to source control.
- LLM output and imported request data are untrusted. The executor validates plans independently and never executes arbitrary model-generated code.
- Local verdicts are conservative: a response difference or a 200 status after an auth change is not proof by itself. Evidence of ownership and cross-account access must be verified manually before reporting.

## Before using live mode

1. Confirm the exact target and written authorization.
2. Add only the approved host(s) to `config.yaml`.
3. Start with a single candidate and low request budget.
4. Review the planned action and the baseline before `--live`.
5. Do not test state-changing workflows on production without explicit approval and a rollback plan.

The included `vulnerable_app.py` is intentionally vulnerable and binds to `127.0.0.1` only. Never expose it to the public internet.


## Model and context controls (v0.4)

- Default mode sends compact metadata and a focused timeline, not raw traffic. Optional full-evidence mode requires both `LH_STORE_RAW_EVIDENCE=1` at import time and `LH_GEMINI_SEND_RAW_EVIDENCE=1` at analysis time; it can send credentials and sensitive response data to the provider. Use only with test data you are authorized to share. When this mode is active, the testing loop is restricted to Gemini rather than falling back to other configured LLM providers.
- Treat response text, endpoint names, and all target-supplied content as untrusted evidence.
- Account roles must be explicitly labelled by the operator; the tool does not infer identities from opaque session tokens.
- Gemini keys are not stored by the tool. A quota/rate-limit response (HTTP 429) stops key-pool rotation; do not use key pools to evade provider limits.
- The model may propose only actions supported by the executor schema. Generated code is not executed. Extend the action vocabulary only through reviewed code and regression tests.


## Principal identifiers and workflow evidence

- `--principal-id` is an optional, operator-supplied non-secret account identifier used only to compare known response ownership fields. Do not provide passwords, bearer tokens, cookies, or API keys.
- Export each test account separately and label it accurately. Labels are assertions by the operator, not identity verification performed by the tool.
- A mismatch between response owner and requester is a strong review signal only when the field semantics and expected authorization policy are known. It is not auto-confirmed.
- The offline benchmark uses synthetic cases and must not be presented as a field detection rate.


## External signal plugins

External Python plugins are disabled unless `LH_ENABLE_EXTERNAL_PLUGINS=1` is explicitly set. Loading a plugin executes its Python module in the LogicHunter process; this is not a sandbox. Only load code you have reviewed and trust. Plugins must only inspect imported evidence and should not perform network or filesystem side effects. Plugin exceptions are isolated, but this does not make malicious plugin code safe.

## Provider quota handling

Gemini keys are not rotated after HTTP 429. A quota/rate-limit response disables that provider for the current local budget window so the agent does not repeatedly retry it. Multiple keys must not be used to evade quota enforcement. Use official quota adjustments, wait for reset, or a separately configured provider within its own terms.


## Gemini administrative planning mode (v1.0)

`LH_GEMINI_ADMIN=1` enables proactive planning instructions for analysis, test selection, and proposing improvements. The manager can use only its declared local-tool allowlist; it cannot run arbitrary shell commands or automatically apply model-generated code. Network tests still require `--live`, an explicit host allowlist, and the guarded executor. `LH_GEMINI_SEND_RAW_EVIDENCE=1` may expose raw test credentials to the configured provider when such evidence was stored; this is a deliberate operator opt-in, not the default.
