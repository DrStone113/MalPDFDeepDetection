# Extraction Quality Gate Specification (`pdf-extraction-quality-gate-v1`)

Authoritative specification for **BUG-007B3** ([BUG-007B](bugs/BUG-007B-recovery-and-truncation-analysis.md)), enforced by [`src/malpdf/extraction/quality_gate.py`](../src/malpdf/extraction/quality_gate.py) and [`scripts/lab/evaluate_extraction_quality_gate.py`](../scripts/lab/evaluate_extraction_quality_gate.py).

## 1. Scope & Non-Goals

- **Saved-Bundle Evaluation Only (`raw_pdf_processing = false`):** Evaluates verified `private_bundles/*.json` artifacts on REMnux against a pinned `expected_index.json` without opening raw PDFs, mutating existing bundles, changing `node_cap = 200`, modifying parser adapters, or running model training (`training_executed = false`).
- **Fail-Closed Before Export/Training:** No numeric graph export or GNN training pipeline may declare `legacy_19d_model_input_ready = true` or `training_unlocked = true` unless the cohort achieves `cohort_gate_verdict == "ready_for_locked_export"`.
- **Read-Only Virtual Overlay Support:** Supports comparing the immutable baseline job (`dfafd888f7a9...`) against a read-only virtual overlay of diagnostic replay (`6f9cc944ed98...`) while keeping `baseline_bundles_modified = false`.

## 2. Closed Sample Disposition Taxonomy (`SAMPLE_DISPOSITIONS`)

Every planned sample in the `Protocol G` cohort receives exactly one mutually exclusive `sample_disposition`:

| Disposition | Category | `gnn_message_passing_eligible` | `tabular_features_valid` | `evaluation_handling` | Meaning |
| --- | --- | --- | --- | --- | --- |
| `usable_complete_projection` | Usable | `true` | `true` | `graph_and_tabular` | Uncapped non-empty projected graph (`<= node_cap`) with `complete` / `bounded_complete` / `observed` status. |
| `usable_degraded_partial_or_timeout` | Usable | `true` | `true` | `graph_and_tabular` | Uncapped non-empty projected graph preserved from primary checkpoint despite secondary stage `partial` / `timeout`. |
| `usable_degraded_capped_benign_loss` | Usable | `true` | `true` | `graph_and_tabular` | Truncated at `node_cap`, dropping only generic `pdf_object`/`catalog`/`pages`/`page` nodes (`security_sensitive_dropped_cap == 0`). |
| `usable_degraded_capped_security_loss` | Usable | `true` | `true` | `graph_and_tabular` | Truncated at `node_cap` and dropping >= 1 security-sensitive node (`action`, `script`, `annotation`, `filespec`, `stream`). |
| `unavailable_projection_filtered` | Unavailable | `false` | `true` | `abstention_or_tabular_only_no_placeholder_graph` | Valid bundle with `parser_object` records outside the 9 projected kinds (`index 141` class). |
| `unavailable_timeout_no_graph` | Unavailable | `false` | `true` | `abstention_or_tabular_only_no_placeholder_graph` | Worker hit `wall_timeout` before emitting any eligible projected graph node (`[292, 407, 749]` class). |
| `unavailable_worker_failure` | Unavailable | `false` | `true` | `abstention_or_tabular_only_no_placeholder_graph` | Unresolved `worker_error` / admission failure with empty projected graph. |
| `unavailable_unclassified_empty` | Unavailable | `false` | `true` | `abstention_or_tabular_only_no_placeholder_graph` | Empty projected graph without verified projection-filter, timeout, or worker-failure classification. |
| `rejected_unverified_cleanup` | Rejected | `false` | `false` | `fail_closed_abort_evaluation` | `coverage_report.worker.worker_cleanup_complete` is not `true`. |
| `rejected_missing_or_corrupt` | Rejected | `false` | `false` | `fail_closed_abort_evaluation` | Missing bundle, SHA-256 mismatch, invalid JSON/schema, structural graph corruption, or invalid `feature_store` contract. |

## 3. Unavailable-Document Policy (`UNAVAILABLE_DOCUMENT_POLICY`)

1. **Preserve Full `Protocol G` Denominator:** `planned_denominator == evaluation_denominator_preserved` (`1,452` across `train = 870`, `validation = 291`, `test = 291` under seed `42`). Silent sample dropping from `validation` or `test` denominators is strictly prohibited (`eval_denominator_shrinkage_allowed = false`).
2. **Forbid Synthetic Placeholder Zero-Nodes:** Empty-graph documents (`kept_nodes_after_cap == 0`) must never receive fabricated dummy/zero nodes (`placeholder_zero_nodes_allowed = false`, `placeholder_nodes_inserted = false`).
3. **Partition-Specific Handling of Verified Unavailable Graphs:**
   - `train`: Excluded from GNN message-passing minibatches (`gnn_message_passing_eligible = false`), retained in the cohort manifest and audited static `feature_store`.
   - `validation` & `test`: Retained in the full split denominator via explicit abstention or verified tabular-static fallback (`abstention_or_tabular_only_no_placeholder_graph`), provided `unavailable_worker_failure == 0`, `rejected == 0`, and `unavailable_ratio <= 0.01` (`1.0%`).
4. **No Artificial Requirement for 1,452 Non-Empty Graphs:** Documents whose parser/projection contracts legitimately yield `0` projected nodes (such as `index 141` `unavailable_projection_filtered` or bounded primary-parse `wall_timeout` samples `[292, 407, 749]`) are recorded transparently in `unavailable_document_ledger` rather than coerced into artificial graphs.

## 4. Node-Size & Feature Provenance Policy (`NODE_SIZE_AND_FEATURE_PROVENANCE_POLICY`)

1. **Missing Values Stay `null`:** Missing node sizes remain `None`/`null` in JSON and provenance schemas; silent `null -> 0` imputation is forbidden (`null_to_zero_imputation_allowed = false`).
2. **JSON Serialization Bytes Forbidden as PDF Object Size:** `projected_json_storage_bytes` measures UTF-8 JSON footprint only (`is_model_feature_producer = false`) and must never be substituted for PDF object byte length.
3. **Legacy 19D Readiness Gate:** `legacy_19d_ready` requires `legacy_sizes_null == 0` and `legacy_sizes_known == kept_nodes_after_cap`. Because `normalize.py` v1 writes `details.size_bytes` only on non-projected `document` records, `legacy_19d_ready` evaluates to `false` across all `v1` projected graphs, preventing unverified zero-filled 19D exports.
4. **Verified v2 Size Producers:** Future v2 graph feature contracts must source physical sizes exclusively from `verified_physical_declaration_span_bytes` (top-level original byte spans) and `stream_raw_payload_bytes` (`details.raw_bytes` on `stream` nodes) with explicit availability masks for inline/repaired/`/ObjStm` objects.
5. **Cleanup & Tabular Contract Enforcement:** Every accepted sample must satisfy `worker_cleanup_complete is True` and pass `ObservationStatus` invariants on `feature_store` (`observed` / `absent_within_scope` non-null; `not_run` / `timeout` / `unsupported` / `decode_error` strictly `null`).

## 5. Cohort Gate Checks & Ordered Verdicts (`protocol-g-quality-policy-v1`)

| # | Check Identifier | Pass Condition | Tier |
| --- | --- | --- | --- |
| 1 | `cohort_denominator_complete` | `observed_present_valid == expected_planned` and `rejected_missing_or_corrupt == 0` | Tier 1 — Integrity |
| 2 | `worker_cleanup_verified` | `rejected_unverified_cleanup == 0` across all planned samples | Tier 1 — Integrity |
| 3 | `graph_structural_validity` | `0` samples with structural graph issues (`audit_bundle` clean) | Tier 1 — Integrity |
| 4 | `tabular_static_feature_store_integrity` | `0` samples with invalid `feature_store` `ObservationStatus` contracts | Tier 1 — Integrity |
| 5 | `unresolved_worker_failures_cleared` | `unavailable_worker_failure == 0` | Tier 2 — Recovery |
| 6 | `evaluation_partition_coverage` | Every present `validation`/`test` split has `rejected == 0`, `worker_failures == 0`, `unclassified == 0`, and `unavailable_ratio <= 0.01` | Tier 2 — Recovery |
| 7 | `legacy_19d_semantic_size_populated` | Across all GNN-eligible graphs, `legacy_sizes_null_total == 0` and `legacy_sizes_known_total == retained_nodes_total` | Tier 3 — Representation |
| 8 | `security_sensitive_truncation_bounded` | `usable_degraded_capped_security_loss / planned <= 0.05` (`5.0%`) | Tier 3 — Representation |

Ordered cohort verdict resolution:
1. If any Tier 1 check fails → **`rejected_integrity_failure`**
2. Else if any Tier 2 check fails → **`blocked_unresolved_extraction_failures`**
3. Else if any Tier 3 check fails → **`hold_pending_v2_projection_and_size_contract`**
4. Else (all 8 checks pass) → **`ready_for_locked_export`** (`legacy_19d_model_input_ready = true`, `training_unlocked = true`)

## 6. Sanitized Artifact Layout

- **REMnux Output Directory:** `/home/remnux/malpdf-extraction-quality-gates/run_<UTC>_<job12>/`
- **Windows Experiment Record:** `reports/experiments/pdf_extraction_quality_gate/run_<UTC>_<job12>/`
- **Exported Files:** `locked_methodology.json`, `cases.jsonl`, optional `replay_overlay_cases.jsonl`, `summary.json`, `report.md`, `manifest.json` (plus retrieval `verification.json` and `local_manifest.json` on Windows DEV). No raw PDF bytes, strings, paths, or `details` payloads are ever emitted.

