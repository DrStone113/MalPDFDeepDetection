# BUG-011 — Nested and singlepart PDF emails bypassed inspection

Status: RESOLVED. Severity: HIGH. Category: MIME_INSPECTION.
Recorded: 2026-11-10.

## Symptoms and root cause — five whys

The same reviewed fixture was detected in flat multipart mail but left intact
in nested/singlepart mail marked `CLEAN`/`PASSED` with zero inspected files.

1. Only direct children of a multipart root were inspected.
2. Nested containers were treated as non-PDF content.
3. Singlepart roots never entered the loop.
4. Missing PDF payloads passed through without an unavailable result.
5. The original regression covered only flat multipart mail.

## Resolution and anti-regression invariants

The gateway recursively replaces PDF leaves while preserving MIME containers,
forwarded envelopes and non-PDF content. Empty/unreadable candidates are held
for review. Existing inspection headers are replaced, traversal is bounded,
quarantine filenames use hashes, and warning bodies have matching encodings.
The APIs and UI preserve `HELD_FOR_REVIEW` instead of advertising held mail as
clean; a clean-email download is refused until every PDF candidate is classified.
Unknown text charsets fall back to UTF-8 when inserting the warning banner.

- All supported MIME depths and a PDF root are inspected.
- Empty or unknown payloads are never converted to benign verdicts.
- Every cleaned fixture retains >80% bytes, page count and nonempty exact text.
- Headers, multipart structure and non-PDF content survive replacement.
- Regression: `test_mail_gateway_mime.py`, existing `test_mail_gateway.py`.

Only approved on-disk fixtures are used; no real malware detonation or
new-corpus effectiveness measurement is implied.
