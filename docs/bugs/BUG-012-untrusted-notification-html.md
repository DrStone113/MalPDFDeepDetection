# BUG-012 — Untrusted notification messages executed as HTML

Status: RESOLVED. Severity: HIGH. Category: WEB_XSS.
Recorded: 2026-11-10.

## Symptoms and root cause — five whys

A subject containing an SVG event handler executed in the actual `showToast`
function in isolated Chrome. The harmless reproduction only set a DOM attribute.

1. Notification messages were interpolated directly into `innerHTML`.
2. Messages could contain filenames, email subjects or server errors.
3. Those strings retained sender/uploader-controlled metadata.
4. Escaping elsewhere in the page did not protect this sink.
5. UI tests checked markup presence rather than browser execution.

## Resolution and anti-regression invariants

The toast template now contains a static message element populated with
`textContent`. All callers receive the same literal-text handling.

- HTML-like subjects remain visible and create no executable elements.
- `test_web_notifications.py` runs the real function in isolated Chrome and
  verifies literal display and absence of the harmless execution marker.
- The browser run is bounded and makes no external request.

The test creates no PDF substitutes and adds no Python comments.
