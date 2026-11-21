# Web security fixes — 2026-11-10

Baseline: `2e276d8d8fedd98b664748d924873867a9f2f928`.
Branch: `codex/fix-scan-isolation-and-evidence`.

## Result

Fixed browser-session data exposure on both API deployments and the copied
Gradio router; recursive email inspection; unsafe notification HTML; and ONNX
explanation provenance. Added hosted pytest checks with a fully pinned minimal
dependency environment. No remote deployment was performed.

Each browser now owns scan/active-document state, email history, quarantine and
audit. Foreign identifiers return 404. Secure partitioned cookies and origin
checks protect HTTPS writes; empty visitors cannot exhaust the session registry.

Nested multipart, forwarded and singlepart PDF mail is inspected without
flattening its MIME tree. Missing/unreadable candidates remain unavailable,
the UI says review is required, and a clean-email download is refused. Unknown
body charsets no longer crash warning insertion. Cleaned reviewed PDFs retain
more than 80% of bytes, the same page count and nonempty identical extracted text.

ONNX reports occlusion, PyTorch reports gradient-input attribution, and unknown
positions remain null. ONNX sparsity excludes unevaluated dimensions and states
its evaluated-input scope. Notification text is assigned with `textContent`.

## Verification

| Scope | Measured result |
| --- | --- |
| Focused application/security tests, existing `.venv`, Python 3.11.0 | 100 passed, 1 existing TestClient deprecation warning |
| Same focused tests, `.venv-windows-dev`, Python 3.11.16 with declared pypdf/Torch versions | 100 passed, same warning |
| Hosted security commands reproduced in a newly created environment | 6 passed; `pip check` passed |
| Source/content/synthetic security checks | 237/237 passed |
| Python comment and syntax audit | 402 files parsed, zero comments |
| Full suite before changes, existing `.venv` | 2023 passed, 240 failed, 25 skipped |
| Full suite after changes, same environment | 2065 passed, 240 failed, 25 skipped |

The full-suite XML comparison confirms the exact same 240 failing test IDs,
no missing original cases, no newly skipped cases and 42 additional passing
cases. **The full suite is still failing; this is not an all-green result.**
Historical failures include platform-specific LAB requirements, missing
dependencies and incompatible installed versions in the existing `.venv`.
They were not disabled, removed or converted to passing tests. No new model
accuracy or corpus-quality result is claimed. Overlapping focused/full test
counts above must not be added together.

Local detailed evidence (ignored, not committed):

- `artifacts/tmp/fix-20261110-focused.xml`
- `artifacts/tmp/fix-20261110-dev-focused.xml`
- `artifacts/tmp/ci-web-security-clean.xml`
- `artifacts/tmp/fix-20261110-full-final.xml`
- `artifacts/tmp/fix-20261110-full-final.log`
- `artifacts/tmp/fix-20261110-comparison.json`

## Remaining operational limits

REMnux SSH health checks timed out, so no LAB execution or deployment is claimed.
No raw malware or payload was retrieved, opened or detonated. Application tests
used only the two existing approved fixtures:

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `real_benign_document.pdf` | 324418 | `ef43e7f9e1c138d5d5279fe3c16e54c7d0a63c1a056f5008550872e31b4b0fa7` |
| `real_threat_document.pdf` | 324957 | `b260f9e53f0b8dabdc9ac81e93119e9b66766db88f8ece507596c7039cff9eca` |

Sessions are process-local: use one worker until shared state exists. Actual
Hugging Face iframe behavior was not tested on the remote service; browsers
that block embedded cookies need the direct Space URL. Hosted CI does not have
the ignored fixture/model binaries, so its six no-PDF tests do not substitute
for the local application integration suite. See
[the application contract](../../docs/web_security_and_validation.md) and
[BUG-010–013](../../docs/bugs/README.md) for boundaries and regression contracts.
