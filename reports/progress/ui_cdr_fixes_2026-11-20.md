# UI assessment and PDF cleaning fixes — 2026-11-20

Fixed the fragmented assessment badges and the indirect-scalar `objgen` crash in CDR. Existing uncommitted UI and web-test changes were preserved. No topology, corpus or model changes were made.

## Verification

- Regression first reproduced the exact integer AttributeError, then passed with the container filter.
- `.venv-windows-dev/Scripts/python.exe -m pytest tests/test_cdr_disarm.py tests/test_web_app.py -q`: **22 passed**, one Starlette/httpx deprecation warning.
- Full `pytest tests/ -q`: **2140 passed, 183 failed, 33 skipped**, one warning, 210 seconds. The suite is not green. Observed failures include unsupported Windows `fork`, Linux-only extraction isolation, missing `/sys/class/net` and unavailable executables. Not all 183 failures were independently diagnosed or baseline-compared in this task.
- Actual Chromium upload/scan/CDR flow using reviewed fixtures: HTTP 200 for cleaning; before/after previews rendered; no JavaScript page errors. Assessment badges verified as single inline-flex, nowrap boxes at 1365, 768 and 320 px.
- `git diff --check`: passed. Repository content guard: passed, 2491 tracked index files checked against HEAD (not a blanket assertion about untracked files).
- UI design detector emitted warnings about existing page styling/markup outside this one-line badge fix; no page redesign was attempted.
- REMnux SSH health check timed out. No remote deployment or LAB tests performed.
- The exact PDF shown in the user's screenshot was not available for a retest. The regression uses a reviewed content-bearing fixture with indirect scalar objects, preserving xref offsets; size, pages, extracted text and content/resources are asserted.

## Local evidence

- `artifacts/ui-cdr-pytest-20261120.log`
- `artifacts/ui-cdr-browser-20261120.log`
- `artifacts/verify-ui-cdr.cjs`
- `artifacts/ui-assessment-fixed.png`
- `artifacts/ui-cdr-fixed.png`
- `docs/bugs/BUG-014-cdr-indirect-scalars-and-assessment-badges.md`
