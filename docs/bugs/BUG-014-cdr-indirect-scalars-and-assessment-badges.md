# BUG-014: CDR indirect scalar crash and fragmented assessment badges

Date: 2026-11-20. Status: RESOLVED for the focused regressions.
Category: CDR_BINARY_MUTATION / UI_LAYOUT. Severity: HIGH (CDR), LOW (UI).

## Symptoms and root cause

1. Cleaning a PDF failed with `AttributeError: 'int' object has no attribute 'objgen'`.
2. `_active_keys` read `objgen` while building its initial work list.
3. `pdf.objects` can contain indirect scalar values exposed as native Python integers or booleans.
4. The container type check happened only later, when consuming that list.
5. Existing fixtures did not exercise an indirect numeric object in the serialized object table.

The assessment table separately rendered severity text in a plain inline span. In narrow columns, its background and border fragmented across wrapped lines.

## Resolution and invariants

- Filter initial traversal entries to Dictionary, Stream and Array before reading `objgen`. Scalars contain no child keys. Preserve the existing cycle detection, traversal limits and post-save verification.
- Use `inline-flex items-center whitespace-nowrap` on severity badges. Retain the table's horizontal scrolling and existing severity labels/colors.
- Do not catch and hide traversal exceptions or replace the original PDF with a new document.

## Regression contract

`tests/test_cdr_disarm.py::test_cdr_handles_indirect_scalars_in_object_table` modifies the reviewed, content-bearing benign fixture. Equal-length replacements turn indirect string markers into numeric/boolean PDF objects without invalidating xref offsets. The test reproduced the exact AttributeError before the fix.

After cleaning, assert more than 80% size retention, identical page count and nonempty identical extracted text, unchanged content/resources, retained scalar values and removed nested JavaScript trigger.

Browser verification uses the existing reviewed threat fixture through the actual upload/scan UI. Check all severity badges at widths 1365, 768 and 320, then click CDR and check the successful response and rendered result. No production demo endpoint or fabricated result was added.

## Verification scope

- Focused CDR/web tests: 22 passed (one dependency deprecation warning).
- Chromium: badges remain single boxes at all three widths; CDR returned HTTP 200; no JavaScript page errors.
- Exact user PDF was not supplied or opened. REMnux SSH timed out; remote verification unavailable.
- Full-suite results and broader limitations are recorded in the dated progress report.
