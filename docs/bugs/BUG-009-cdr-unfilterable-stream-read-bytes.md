# BUG-009: CDR Disarm Failure on PDFs with Unfilterable Image Streams (`/DCTDecode` / `/JPXDecode`) and Deep Indirect Chains

## 1. Metadata
- **Bug ID:** `BUG-009`
- **Category:** `CDR_BINARY_MUTATION`
- **Severity:** `HIGH`
- **Status:** `RESOLVED`
- **Regression Test:** `tests/test_cdr_disarm.py::test_cdr_handles_unfilterable_dctdecode_image_streams_in_resources`

## 2. Symptom & Traceback
When running in-place CDR disarm (`POST /api/disarm/{scan_id}`) on a multi-page academic report (`BAO_CAO_THS2025-78_v3_Clean_20...pdf`, 83 pages, 2.67 MB) containing embedded JPEG logo images (`/Filter /DCTDecode`) inside `/Resources/XObject`, `PDFDisarmer.sanitize_bytes` raised:
```text
  File "src/malpdf/cdr/engine.py", line 31, in snapshot
    items["decoded_sha256"] = hashlib.sha256(value.read_bytes()).hexdigest()
pikepdf._core.PdfError: stream <_io.BytesIO ...> (object 1093,0, offset 84873): read_bytes called on unfilterable stream
```

## 3. Root Cause (5 Whys)
1. **Why did `/api/disarm` return `Disarm failed`?**
   `PDFDisarmer.sanitize_bytes` raised an unhandled `pikepdf.PdfError` inside `_preserved_document_state(pdf)`.
2. **Why did `_preserved_document_state(pdf)` raise `pikepdf.PdfError`?**
   `snapshot()` called `value.read_bytes()` unconditionally on every `pikepdf.Stream` reachable from `/Contents` and `/Resources`.
3. **Why did `value.read_bytes()` fail on `object 1093,0`?**
   In `pikepdf` (QPDF), `stream.read_bytes()` attempts to decode stream filters; for lossy image filters such as `/DCTDecode` (JPEG) or `/JPXDecode` (JPEG2000) inside `/Resources/XObject`, QPDF treats the stream as unfilterable for generic byte decompression and requires `value.read_raw_bytes()`.
4. **Why was `_preserved_document_state` also slow on 83-page documents?**
   Shared indirect objects (`identity != (0, 0)`) in `/Resources` (fonts, color spaces, XObjects) were not memoized across pages, causing the same indirect objects to be recursively traversed and hashed 83 times.
5. **Why could `_active_keys` also fail on long indirect chains (e.g., 83-page `/Outlines` `/Next` chains)?**
   `_active_keys` incremented `depth + 1` on indirect object hops even though `seen` already prevents revisiting any indirect object (`objgen != (0, 0)`).

## 4. Fix & Anti-Regression Invariants
1. **Unfilterable Stream Fallback & Memoization (`src/malpdf/cdr/engine.py`):**
   - In `_preserved_document_state`, wrap `value.read_bytes()` with a fallback to `value.read_raw_bytes()` so `/DCTDecode` / `/JPXDecode` XObject streams are cryptographically hashed by their raw bytes without raising `pikepdf.PdfError`.
   - Memoize `identity = value.objgen` (`identity != (0, 0)`) per document snapshot and skip parent back-references (`/Parent`, `/P`) so shared resources across multi-page documents are snapshotted in $O(N)$ time.
2. **Inline-Only Depth Bound in `_active_keys` (`src/malpdf/cdr/engine.py`):**
   - Reset `next_depth = 0` when traversing into an indirect object (`objgen != (0, 0)`, which is guarded by `seen`), and increment `depth + 1` strictly for inline direct objects (`objgen == (0, 0)`).
3. **Single-Pass Offset Indexing (`src/malpdf/scanner/ingestion.py`):**
   - Pre-index `(obj_num, generation) -> offset_pos` once per document in `_extract_graph_and_scripts` instead of running `re.search` per node across multi-megabyte PDFs.

