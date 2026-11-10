# BUG-016 — Cloud answer waits for the entire provider response

Recorded: 2026-11-10. Status: FIXED IN SOURCE; deployment verification pending.
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
- Whole-suite and deployed/browser evidence will be recorded after verification.
