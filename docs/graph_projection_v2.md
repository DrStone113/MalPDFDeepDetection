# Graph Projection & Feature Contract v2 (`pdf-graph-projection-v2`)

Authoritative specification for additive Graph Projection v2 (`src/malpdf/extraction/graph_projection_v2.py`), Quality Gate v2 (`src/malpdf/extraction/quality_gate.py`), and fail-closed sanitized Graph Export v2 (`scripts/lab/export_graphs_v2.py`).

## 1. Motivation & Blockers Resolved

`BUG-007B2` and `BUG-007B3` proved that the legacy 19D graph projection (`numeric_export.py` / `extract_hetero_graphs.py`) failed Tier 3 representation checks on two independent axes:

1. **Inline Scalar Saturation & Security-Sensitive Truncation (`security_sensitive_truncation_bounded`):**
   - `evidence_v9.py` emits inline scalar values and anonymous sub-dictionaries (`/Count 1`, `/MediaBox` numbers, `/Resources` / `/XObject` containers) as `kind = "pdf_object"` with `object_number = null`.
   - Under `v1` first-seen order (`node_cap = 200`), inline `pdf_object` records consumed `93.17%` of eligible slots in capped PDFs, dropping security-sensitive nodes (`action`, `script`, `annotation`, `filespec`, `stream`) in `400 / 1,452` (`27.55%`) documents.
   - Simultaneously, `v1` dropped structural container records (`array`, `form`, `field`) without contracting directed edges across them, severing `pages -> [/Kids array] -> page`, `page -> [/Resources -> /XObject] -> stream`, and `catalog -> [/AcroForm -> /Fields -> field] -> action`.

2. **Missing Semantic Node Size & Provenance Integrity (`v2_provenance_size_contract_verified`):**
   - `record.details.size_bytes` was `null` on `100%` (`163,991 / 163,991`) of projected semantic nodes because `size_bytes` exists only on the non-projected `document` record.
   - Using `projected_json_storage_bytes` as an object size feature or imputing `null -> 0` without indicator masks is strictly prohibited.

## 2. Priority Node Selection (`node_cap = 200` Preserved)

`project_graph_bundle_v2` keeps `MAX_NODES = 200` unchanged while eliminating inline scalar saturation:

1. **Inline `pdf_object` Exclusion:**
   - Any record with `kind == "pdf_object"` and `not (type(object_number) is int and object_number > 0)` is excluded from consuming `node_cap` (`excluded_inline_pdf_objects`), while remaining eligible as an intermediate structural container for edge contraction.
   - Dict-valued inline `pdf_object` fallback activates only if a bundle has zero semantic or indirect candidates.
2. **Deterministic Priority Tiers:**
   - **Tier 0 (Root & Security-Sensitive):** `catalog`, `pages`, `action`, `script`, `annotation`, `filespec`, `stream`
   - **Tier 1 (Document Structure):** `page`
   - **Tier 2 (Indirect Objects):** indirect `pdf_object` (`object_number > 0`)
3. **Order Preservation:**
   - Candidates are ranked by `(priority_tier, bundle_record_position)`, capped at `node_cap = 200`, and re-sorted by `bundle_record_position` for canonical node indexing.

## 3. Bounded Container-Transparent Edge Contraction

1. Only edges with `status != "unresolved"` participate in graph topology.
2. Direct edges `(u, v)` between retained nodes are emitted first (`direct_kept_edges`).
3. From each retained node `u`, `project_graph_bundle_v2` performs a bounded BFS (`MAX_CONTAINER_HOPS = 8`) exclusively through unretained observed container records (`array`, `form`, `field`, `pdf_object`, `embedded_stream`, `xfa_packet`).
4. Traversal terminates immediately upon reaching any retained node `v != u` (never shortcutting *through* a retained node such as `pages -> page -> stream`) and emits deduplicated typed edges `(u, v, EDGE_TYPES.get((type_u, type_v), 7))` (`contracted_container_edges`).

## 4. Provenance-Backed Sizes & Injective 23D Node Feature Schema

JSON projections preserve `null` (`None`) whenever a physical size is unavailable:
- `verified_physical_span_bytes`: `int | null` from `forensic_object_declaration` (`[byte_start, byte_end)` matched strictly on `pypdf` non-repaired `(object_number, generation, byte_offset_start)`), paired with `verified_physical_span_reasons`.
- `stream_raw_payload_bytes`: `int | null` from `StreamObject.details.raw_bytes`.
- `projected_json_storage_bytes_used`: strictly `false`.

Each retained node receives a finite `23D` feature vector (`NODE_FEATURE_DIM_V2 = 23`) compatible with `PDFTransGraph(node_in_dim=23)`:

| Feature Index | Name | Encoding | Missing (`null`) vs Zero (`0` bytes) |
| --- | --- | --- | --- |
| `0` | `log1p_verified_physical_span` | `log1p(span)` if measured else `0.0` | `null -> [0.0, 0.0]`, `0B -> [0.0, 1.0]` |
| `1` | `has_verified_physical_span_mask` | `1.0` if measured else `0.0` | Injective indicator mask |
| `2` | `log1p_stream_raw_payload` | `log1p(raw_bytes)` if known else `0.0` | `null -> [0.0, 0.0]`, `0B -> [0.0, 1.0]` |
| `3` | `has_stream_raw_payload_mask` | `1.0` if known else `0.0` | Injective indicator mask |
| `4` | `is_indirect` | `1.0` if `object_number > 0` else `0.0` | Exact structural flag |
| `5` | `is_synthetic_repaired` | `1.0` if `is_synthetic_repaired` else `0.0` | Exact backend repair flag |
| `6` | `is_orphan` | `1.0` if `in_degree == 0` and `type != catalog` else `0.0` | Post-contraction topology flag |
| `7..22` | `rwse_step_1..16` | 16-step random-walk return probability | Bounded `[0.0, 1.0]` |

## 5. Fail-Closed Export Gate (`scripts/lab/export_graphs_v2.py`)

- Evaluates the full Protocol G cohort under `GATE_CONTRACT_VERSION_V2 = "pdf-extraction-quality-gate-v2"`.
- Refuses export (`ValueError("quality_gate_not_ready_for_export")`) unless all 8 gate checks pass (`cohort_gate_verdict == "ready_for_locked_export"`).
- Never inserts placeholder zero-nodes for unavailable documents; exports non-empty validated `23D` graphs to `hetero_graphs_v2.jsonl.gz` (verified by `index_measured_graphs_v2`), full-cohort static features to `tabular_features_v2.jsonl.gz`, and explicit unavailable dispositions to `unavailable_document_ledger.json`.

