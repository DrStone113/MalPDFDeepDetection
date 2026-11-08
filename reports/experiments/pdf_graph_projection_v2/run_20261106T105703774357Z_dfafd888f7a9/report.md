# Graph Projection v2 — Extraction Quality Gate Evaluation

Contract: `pdf-extraction-quality-gate-v2` | Policy: `protocol-g-quality-policy-v1` | Node cap: `200`

## 1. Baseline Cohort Verdict

- Baseline verdict: **`blocked_unresolved_extraction_failures`** (`6 / 8` checks passed).
- Planned / Preserved evaluation denominator: `1452` / `1452` (`placeholder_nodes_inserted=false`).
- GNN message-passing eligible: `1377` | Tabular static valid: `1452` | Unavailable empty projections: `75` | Rejected: `0`.
- Model readiness flags: `v2_graph_model_input_ready=False`, `legacy_19d_model_input_ready=False`, `training_unlocked=False`, `training_executed=False`, `raw_pdf_processing=False`.

## 2. Baseline Gate Checks (8-Point Contract)

| Gate Check | Passed | Summary |
| --- | --- | --- |
| `cohort_denominator_complete` | `True` | `observed_present_valid=1452`, `expected_planned=1452`, `rejected_missing_or_corrupt=0` |
| `worker_cleanup_verified` | `True` | `rejected_unverified_cleanup=0` |
| `graph_structural_validity` | `True` | `samples_with_structural_issues=0` |
| `tabular_static_feature_store_integrity` | `True` | `samples_with_invalid_tabular_features=0` |
| `unresolved_worker_failures_cleared` | `False` | `unavailable_worker_failure_samples=70` |
| `evaluation_partition_coverage` | `False` | `max_eval_unavailable_ratio=0.01`, `splits={'validation': {'planned': 291, 'unavailable': 18, 'unavailable_ratio': 0.061856, 'worker_failures': 17, 'rejected': 0, 'passed': False}, 'test': {'planned': 291, 'unavailable': 12, 'unavailable_ratio': 0.041237, 'worker_failures': 12, 'rejected': 0, 'passed': False}}` |
| `v2_provenance_size_contract_verified` | `True` | `gnn_eligible_samples=1377`, `v2_provenance_ready_samples=1377`, `retained_nodes_total=40575`, `verified_physical_spans_known_total=6486`, `verified_physical_spans_null_total=34089`, `stream_raw_payloads_known_total=8865`, `stream_raw_payloads_null_total=31710`, `projected_json_storage_bytes_used=False`, `null_to_zero_imputation_violations=0` |
| `security_sensitive_truncation_bounded` | `True` | `samples_losing_security_sensitive_nodes=0`, `observed_ratio=0.0`, `max_allowed_ratio=0.05` |

## 3. Stratified Dispositions by Split and Label

| Partition | Planned | Eval Denominator | GNN Eligible | Tabular Valid | Unavailable Empty | Rejected | `v2_provenance_graph_ready` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `train` | 870 | 870 | 825 | 870 | 45 | 0 | 825 |
| `validation` | 291 | 291 | 273 | 291 | 18 | 0 | 273 |
| `test` | 291 | 291 | 279 | 291 | 12 | 0 | 279 |
| `label=0` | 652 | 652 | 618 | 652 | 34 | 0 | 618 |
| `label=1` | 800 | 800 | 759 | 800 | 41 | 0 | 759 |

## 4. Unavailable-Document Ledger (Baseline)

- Total unavailable empty-graph documents: `75`.
- `unavailable_projection_filtered` indices: `[141]`.
- `unavailable_timeout_no_graph` indices: `[126, 292, 496, 749]`.
- `unavailable_worker_failure` count: `70`.
- Evaluation abstention / tabular-fallback indices: `validation=[141, 245, 297, 305, 317, 337, 367, 375, 415, 445, 475, 485, 495, 505, 515, 535, 565, 755]`, `test=[295, 355, 377, 397, 417, 555, 615, 635, 655, 685, 715, 765]`.

## 5. Read-Only Virtual Post-B1 Quality Gate (Baseline Bundles Unmodified)

- Replay job: `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575` (`scope=read_only_virtual_comparison_baseline_bundles_unmodified`).
- Verdict transition: **`blocked_unresolved_extraction_failures` -> `ready_for_locked_export`** (`8 / 8` checks passed).
- Checks cleared by B1: `['unresolved_worker_failures_cleared', 'evaluation_partition_coverage']`.
- Remaining failed checks blocking `ready_for_locked_export`: `[]`.
- Virtual post-B1 GNN eligible: `1448` / `1452` (`unavailable_empty_projection=4`, `rejected=0`).
- Virtual post-B1 unavailable ledger: `projection_filtered=[141]`, `timeout_no_graph=[292, 407, 749]`, `worker_failure=[]`.
- Virtual post-B1 evaluation abstention / tabular-fallback indices: `validation=[141]`, `test=[]`.

### Virtual Post-B1 Gate Checks

| Gate Check | Passed | Summary |
| --- | --- | --- |
| `cohort_denominator_complete` | `True` | `observed_present_valid=1452`, `expected_planned=1452`, `rejected_missing_or_corrupt=0` |
| `worker_cleanup_verified` | `True` | `rejected_unverified_cleanup=0` |
| `graph_structural_validity` | `True` | `samples_with_structural_issues=0` |
| `tabular_static_feature_store_integrity` | `True` | `samples_with_invalid_tabular_features=0` |
| `unresolved_worker_failures_cleared` | `True` | `unavailable_worker_failure_samples=0` |
| `evaluation_partition_coverage` | `True` | `max_eval_unavailable_ratio=0.01`, `splits={'validation': {'planned': 291, 'unavailable': 1, 'unavailable_ratio': 0.003436, 'worker_failures': 0, 'rejected': 0, 'passed': True}, 'test': {'planned': 291, 'unavailable': 0, 'unavailable_ratio': 0.0, 'worker_failures': 0, 'rejected': 0, 'passed': True}}` |
| `v2_provenance_size_contract_verified` | `True` | `gnn_eligible_samples=1448`, `v2_provenance_ready_samples=1448`, `retained_nodes_total=42306`, `verified_physical_spans_known_total=6879`, `verified_physical_spans_null_total=35427`, `stream_raw_payloads_known_total=9275`, `stream_raw_payloads_null_total=33031`, `projected_json_storage_bytes_used=False`, `null_to_zero_imputation_violations=0` |
| `security_sensitive_truncation_bounded` | `True` | `samples_losing_security_sensitive_nodes=0`, `observed_ratio=0.0`, `max_allowed_ratio=0.05` |
