# Web sessions and application verification

## Browser data boundary

Both `malpdf.web.app` and the ONNX production router use server-issued opaque
browser cookies. A session owns its scan jobs, active selection, email results,
quarantine directory and audit history. Knowing another session's scan ID or
quarantined filename grants no access; lookups return 404. Caller-supplied
`X-MalPDF-Client-ID` headers are not an identity source.

The route class carries this boundary when `production/app.py` copies routes
into Gradio. A standalone-app-only middleware would miss that deployment path.
The design follows the [FastAPI route customization API](https://fastapi.tiangolo.com/how-to/custom-request-and-route/).

HTTPS cookies are `HttpOnly; Secure; SameSite=None; Partitioned`; local HTTP uses
`HttpOnly; SameSite=Lax`. Partitioning supports a Space embedded in Hugging Face
on browsers that support partitioned cookies. Browsers that block all embedded
cookies must open the direct Space URL. Foreign-origin writes and cross-site
write requests are refused with 403, including when the browser possesses a
session cookie. Private responses use `Cache-Control: no-store`.

Session state is held in one process. Run one Uvicorn worker; multiple workers
or replicas need shared session/job storage before they can preserve a browser's
state. Idle sessions expire after eight hours and process restart clears the
registry. This is browser-session isolation, not a user-account or login system.

The registry holds at most 128 sessions. It may discard completely empty,
inactive sessions at capacity; sessions with jobs, audit, email or in-flight
requests are retained, and capacity exhaustion returns 503. Health probes create
no sessions. Empty page visits create no quarantine files or directories.
Expired session files are not reassigned to new sessions; automatic deletion of
quarantined files is outside this change.

## Email and XAI contracts

Cloud chat uses only the server-side `VILAO_API_KEY` secret. No key is served in
HTML. Cloud mode requires a session-owned scan, bounds questions to 2000
characters, refuses redirects, and limits provider calls to six per session per
minute. When no replacement credential is configured, the UI uses its existing
fallback; the old publicly embedded credential must be revoked/rotated. See
[BUG-014](bugs/BUG-014-browser-cloud-api-credential.md).

Email inspection recursively preserves the MIME tree and handles a PDF at the
root, nested multipart PDFs and forwarded `message/rfc822` messages. Empty or
unreadable PDF candidates are `UNAVAILABLE` and hold the email for review rather
than marking it clean. Existing inspection headers are replaced. Email rendering
and download actions keep that review status explicit.

ONNX explanations use `xai_method=occlusion`; PyTorch uses
`xai_method=gradient_input`. `cross_attention_matrix_status` distinguishes
`measured_occlusion_saliency`, `measured_gradient_saliency` and `unavailable`.
`xai_coverage` reports evaluated and total node/feature counts. ONNX evaluates
at most 24 graph nodes and 16 tabular features; unevaluated node saliency is
`null`, and unevaluated tabular features are excluded from ranked attributions.
Prediction parity does not establish explanation parity.
Sparsity is scoped to evaluated input attributions, excluding unknown positions
from its dimensionality rather than treating them as measured zero effects.

## Verification scopes

Hosted CI preserves the existing content/source/security checks and adds actual
pytest execution on Windows and Linux for session-registry boundaries and
notification rendering in Chrome. Its minimal dependency set is pinned in
`configs/ci-web-security-requirements.txt`; installation accepts wheels only.
These tests need no PDFs, model binaries, malware corpus or credentials.

Full application checks additionally require the approved on-disk files
`real_benign_document.pdf` and `real_threat_document.pdf` in `tests/fixtures/`
(or `MALPDF_REVIEWED_FIXTURES`) and the trained PyTorch/ONNX models. These ignored
binary inputs are not committed or substituted with generated blank PDFs.
The hosted no-PDF gate is not a claim that those integration tests ran there.

With approved local assets, run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_browser_sessions.py tests/test_web_session_isolation.py tests/test_mail_gateway_mime.py tests/test_mail_gateway.py tests/test_cdr_disarm.py tests/test_web_app.py tests/test_onnx_production.py tests/test_web_notifications.py tests/test_xai_provenance.py tests/test_runtime_evidence.py -q
.\.venv\Scripts\python.exe -m pytest tests/ -q --junitxml=artifacts/tmp/application-full.xml
```

Chrome/Chromium is required for the notification test. `MALPDF_TEST_BROWSER` may
point to its executable. The test uses an isolated headless profile and checks
both literal display of an untrusted subject and absence of script execution.

Full-suite results retain their environment, failure IDs and skipped cases.
A Windows LAB-only failure is not converted into a passing or disabled test;
missing dependencies and historical failures are reported separately from new
regressions. Real-corpus processing still belongs to the approved LAB workflow.
