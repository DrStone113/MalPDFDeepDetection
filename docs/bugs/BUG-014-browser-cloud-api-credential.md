# BUG-014 — Cloud provider credential embedded in browser JavaScript

Status: MITIGATED in source; old credential revocation/rotation requires its
owner. Severity: HIGH. Category: SECRET_EXPOSURE. Recorded: 2026-11-10.

## Symptoms and root cause — five whys

Deployment reconciliation found a provider credential literal in the existing
public Space's HTML. Its value is intentionally omitted from all reports/tests.

1. Cloud requests were sent directly from browser JavaScript.
2. The Authorization value was built from an inline credential.
3. Anyone loading the page could receive that credential.
4. Environment-backed server configuration was absent.
5. Tests checked AI behavior without rejecting credential literals in HTML.

## Mitigation and limits

The browser now calls the existing session-scoped `/api/ai/chat` endpoint with
`mode=cloud`. The server uses only the `VILAO_API_KEY` environment secret, fixes
the provider endpoint/model, refuses redirects, bounds question/response sizes
and time, and limits each active browser session to six cloud calls per minute.
The grounded context is rebuilt from that session's own scan result.

The exposed old credential is never reused, copied to Secrets or tested against
the provider. No Space secret was configured during this deployment. Without a
new key, cloud requests return 503 and the UI uses its existing fallback. The
owner must revoke/rotate the old provider key and put a replacement into Space
Secrets as `VILAO_API_KEY`; it must never be pasted into code or chat.

Old public Git history may still contain the exposed value. Removing the current
literal does not make that old credential safe, and history was not force-pushed.

## Anti-regression invariants

- No provider credentials or browser-side Authorization construction in HTML.
- Foreign scan IDs never grant cloud access to another session's document.
- Unconfigured cloud mode fails explicitly; deterministic mode remains usable.
- Oversized questions fail before any provider request.
- Tests: `test_cloud_chat_security.py`, `test_web_notifications.py`.

Only approved PDF fixtures are used in API tests; no live provider request or
new AI-quality result is claimed without replacement credentials.
