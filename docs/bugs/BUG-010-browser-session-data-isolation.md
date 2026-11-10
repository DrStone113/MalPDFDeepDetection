# BUG-010 — Browser sessions exposed each other's documents

Status: RESOLVED in source; remote deployment not performed. Severity: HIGH.
Category: WEB_DATA_ISOLATION. Recorded: 2026-11-10.

## Symptoms and root cause — five whys

Two independent browsers could read the same active scan, details, original
previews, email, quarantine and audit history, or mutate a known foreign ID.

1. API lookups used one process-wide store.
2. The active document and email dictionaries were also global.
3. Quarantine files had no browser ownership boundary.
4. Random IDs were treated as separation although listing exposed those IDs.
5. Tests exercised only one browser, without foreign-ID denial assertions.

The Gradio entrypoint copies route objects: standalone-only middleware would
leave that deployment path unprotected. String-prefix path checks also accepted
a sibling directory sharing the allowed directory's prefix.

## Resolution and anti-regression invariants

`web/sessions.py` binds a server-owned opaque session around each route,
including copied routes and threadpool calls. Each session owns stores and a
quarantine directory; resolved quarantine files must be immediate children.
HTTPS cookies are HttpOnly, Secure and Partitioned; foreign-origin writes are
refused. Empty sessions can be replaced at capacity, while occupied/in-flight
sessions are retained. Empty page visits create no quarantine directories.

- Foreign scan, email and quarantine IDs never grant access.
- A valid cookie restores only its own session; fabricated cookies select none.
- Copied-router deployments retain the same boundary.
- Regression: `test_web_session_isolation.py`, `test_browser_sessions.py`.

Session state remains process-local: run one worker. No account login,
distributed persistence or automatic quarantine deletion is introduced. See
[the contract and limits](../web_security_and_validation.md).
