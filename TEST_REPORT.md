# Test report — v0.5.0

Last verified in the build environment on 2026-10-19.

- Python compile check: passed for the project modules.
- Automated tests: **67 passed** (`python -m pytest -q`).
- Offline synthetic workflow benchmark: **6/6 fixture checks passed** (`python logichunter.py benchmark`).
- Loopback HTTP lab benchmark: **3/3 checks passed**, six requests to an ephemeral `127.0.0.1` server only (`python logichunter.py lab-benchmark`).
- CLI checks: `--help`, `workflow-report`, `benchmark`, and `lab-benchmark` exercised.
- No external targets or live Gemini API calls were used in this verification.

The six-case offline fixture pass rate and three loopback checks are regression results only. They are not estimates of real-world precision, recall, detection rate, or superiority over other tools. The secure private endpoint intentionally creates a role-difference hypothesis; the owner-mismatch signal is absent and no case is auto-confirmed.

## v0.9.0 verification addendum

- `pytest -q`: 89 passed.
- `python -m compileall -q .`: passed.
- `python logichunter.py check-detection`: 7/7 synthetic signal fixtures passed, with zero unexpected signals on the current fixture set.
- `python logichunter.py list-signal-plugins`: three built-in plugins listed; external plugins disabled by default.
- No live Gemini API call and no external target test was performed. Synthetic fixture results are not real-world detection-rate estimates.
