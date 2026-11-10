# BUG-015 — Cloud reasoning consumes the final-answer budget

Recorded: 2026-11-10. Status: FIXED IN SOURCE, live verification pending.
Severity: MEDIUM. Category: CLOUD_PROVIDER_INTEGRATION.
Affected: `src/malpdf/web/cloud_chat.py`, web chat template.

## Symptoms and reproduction

On the deployed Space, a greeting (`hello`) after scanning the approved,
controlled threat fixture intermittently returned HTTP 503
`cloud_ai_unavailable`. The browser displayed a generic readiness warning and
the deterministic fallback. Other requests using the same credential succeeded.
The issue was reproduced through both live HTTP and the real browser.

Only reviewed on-disk fixtures were used. No raw malware corpus was involved.
Diagnostic artifacts under ignored `artifacts/tmp/hf-deploy-20261110/` contain
status, timing and token counts, never credentials or private reasoning text.

## Root cause — five whys

1. The UI fell back because the backend returned no final answer.
2. The provider's successful HTTP response had `content=null` and
   `finish_reason=length`.
3. All 650 completion tokens were consumed by internal reasoning.
4. The output cap had been sized for a non-reasoning answer; MiniMax M3.1 Flash
   always reasons and shares the cap between reasoning and final content.
5. The adapter collapsed empty output, timeout and provider errors into the same
   unavailable result, and existing tests did not exercise reasoning exhaustion.

One direct reproduction with 650 tokens returned no final content in 7.063 s.
At 2048 tokens, a completed response took 13.273 s, exceeding the old 12 s
timeout. Another completed 2048-token request with low effort took 13.959 s and
used 2024 completion tokens. These individual observations do not establish a
latency distribution or prove that low effort is faster.

The model's [official text-generation guide](https://platform.minimax.io/docs/guides/text-generation)
documents always-on reasoning, supported low effort and a 4096-token example.
Disabling reasoning is unsupported for this model.

## Resolution

Use 4096 output tokens, supported `reasoning_effort=low`, and a bounded 40 s
transport timeout. Preserve final-content-only rendering, no redirects, response
size limits, session ownership and the existing six-requests-per-minute limit.
No retries or fabricated greeting are used to hide provider failures.

Classify output exhaustion, timeouts, upstream rate limits, rejected credentials
and invalid provider responses with safe error codes. Never return provider
error bodies or reasoning. Reject truncated final content instead of presenting
it as complete. The browser explains the failure and labels each displayed
answer with its actual source: Cloud AI, browser AI or deterministic fallback.

## Anti-regression invariants and tests

- Reasoning and final text share a sufficient explicit output budget.
- A length-limited response is a failure even when it contains partial text.
- Provider timeouts and capacity failures remain distinct from missing secrets.
- Credentials and reasoning never appear in API responses, logs or browser HTML.
- `tests/test_cloud_chat_adapter.py` uses actual dev/ONNX APIs and reviewed PDFs;
  only the external HTTP transport is doubled. No live key is used in tests.
- `tests/test_cloud_chat_security.py` preserves cross-session isolation,
  missing-secret behavior, input bounds and absence of browser credentials.

Live deployment results will be recorded after the new runtime is verified.
