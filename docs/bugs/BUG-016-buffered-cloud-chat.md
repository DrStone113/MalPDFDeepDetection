# BUG-016 — Cloud answer waits for the entire provider response

Recorded: 2026-11-10. Status: RESOLVED; verified on the live Space and browser.
Severity: MEDIUM. Category: CLOUD_CHAT_LATENCY.
Affected: cloud adapter, dev/ONNX chat routes, browser chat renderer.

## Symptoms and root cause

The user must wait for the whole Cloud AI answer before seeing any text.

1. The browser waits for `response.json()` before rendering.
2. The backend returns one complete JSON answer.
3. The adapter sends `stream=false` and reads the entire provider response.
4. The existing local AI incremental rendering path is not used by Cloud AI.
5. Previous tests covered successful complete answers but not incremental output.

This is a transport/rendering behavior, separate from BUG-015's reasoning budget.

## Resolution and invariants

The existing endpoint accepts opt-in `stream=true` for cloud mode. Its final
content is relayed as UTF-8 SSE deltas, then an explicit successful `done` event.
The browser renders each delta while generation continues. No buffered answer
is split into simulated typing, and no private reasoning is displayed.

The JSON route remains compatible with existing callers. Streaming preserves
ownership checks, secrets on the server, no redirects, bounded reads, output
limits and rate limits. Premature EOF, exhausted output or network errors never
count as successful completion. Partial text remains visibly incomplete; errors
before any text can use the labeled deterministic fallback. The provider
connection is closed on terminal paths and downstream send failures.

Protocol and bounds are documented in `docs/web_security_and_validation.md`.
The model's [official guide](https://platform.minimax.io/docs/guides/text-generation)
supports opt-in streaming and separates reasoning from final content. SSE event
framing follows [MDN's event format](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events#event_stream_format).
Provider reasoning can still precede the first visible answer token.

## Regression verification

- RED: ten API cases fail against the old buffered route; the client parser test
  fails because no incremental decoder exists.
- GREEN: 107 focused adapter, stream, client-decoder, credential and ownership
  cases pass with approved on-disk PDFs. Only external provider HTTP transport
  is doubled; no fake runtime endpoints, generated blank PDFs or real keys.
- The server produces its first content delta before reading the completion
  frame. Closing the generator or failing the downstream send closes upstream.
- Client tests feed a real Web `ReadableStream` one byte at a time, including
  split Vietnamese UTF-8, and observe text before sending completion. They also
  verify explicit errors, premature EOF and reader cancellation.
- Inverting the new length-exhaustion branch makes both dev/ONNX regression
  cases fail; the original source is restored afterward.
- Whole Windows suite: 2148 passed, the same 240 failed IDs as the recorded
  pre-cloud baseline, 25 skipped. No new failed IDs or skipped cases. The 83
  additional passing cases since that older baseline include the intervening
  credential, adapter and proxy work; they are not all from this streaming change.
- Source commit `2c8af7d`; live Space revision
  `87b44aa3f3105a3aba3b2c07ff971dbc687c0e7f`, confirmed RUNNING by the Hub API.
  Only four runtime files were copied from Windows; models and SDK are unchanged.
- Live approved benign fixture: HTTP 200, 139 final deltas, successful completion.
  Its first/last deltas arrived close together; this request alone would not
  establish visibly incremental delivery.
- Live approved controlled threat fixture: HTTP 200, 396 deltas, first visible
  content at 46.468 s and completion at 57.078 s (10.610 s between them). Both
  HTTP smoke-test jobs were removed. These samples are not latency guarantees.
- Real browser with the same controlled fixture and a separate detailed question:
  observed Cloud AI text at 462 characters while state was `streaming` and the
  send button remained disabled. Later samples showed 3502 and 4672 characters
  before completion at 5260 characters; the send button then re-enabled.
  Initial text was observed at 20.319 s and completion at 43.215 s. The provider
  can pause between deltas; continuous fixed-rate typing is not promised.
- No browser console errors were captured. A screenshot saved while text was
  incomplete shows the `Đang trả lời…` source label. The browser test record
  remains available for review; no raw/unreviewed PDFs or real malware were used.
- Commit checks: 237 passed; repository content gate passed; no Python comments
  introduced. REMnux SSH health returned Python 3.12.3. This web-only change does
  not require or trigger a LAB extraction job.

Ignored evidence under `artifacts/tmp/hf-deploy-20261110/`:
`cloud-stream-tests.xml`, `cloud-stream-full.xml`,
`cloud-stream-baseline-comparison.json`, `cloud-stream-mutation.txt`,
`cloud-stream-live-verification.json`, `cloud-streaming-browser-observation.json`,
`cloud-streaming-browser-partial.png`, `cloud-streaming-browser-final.png`.
