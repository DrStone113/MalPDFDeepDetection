# Graph Projection v2 — Extraction Quality Gate Evaluation

Contract: `pdf-extraction-quality-gate-v2` | Policy: `protocol-g-quality-policy-v1` | Node cap: `200`

## 1. Baseline Cohort Verdict

- Baseline verdict: **`ready_for_locked_export`** (`8 / 8` checks passed).
- Planned / Preserved evaluation denominator: `1452` / `1452` (`placeholder_nodes_inserted=false`).
- GNN message-passing eligible: `1446` | Tabular static valid: `1452` | Unavailable empty projections: `6` | Rejected: `0`.
- Model readiness flags: `v2_graph_model_input_ready=True`, `legacy_19d_model_input_ready=False`, `training_unlocked=True`, `training_executed=False`, `raw_pdf_processing=False`.

## 2. Baseline Gate Checks (8-Point Contract)

| Gate Check | Passed | Summary |
| --- | --- | --- |
| `cohort_denominator_complete` | `True` | `observed_present_valid=1452`, `expected_planned=1452`, `rejected_missing_or_corrupt=0` |
| `worker_cleanup_verified` | `True` | `rejected_unverified_cleanup=0` |
| `graph_structural_validity` | `True` | `samples_with_structural_issues=0` |
| `tabular_static_feature_store_integrity` | `True` | `samples_with_invalid_tabular_features=0` |
| `unresolved_worker_failures_cleared` | `True` | `unavailable_worker_failure_samples=0` |
| `evaluation_partition_coverage` | `True` | `max_eval_unavailable_ratio=0.01`, `splits={'validation': {'planned': 291, 'unavailable': 2, 'unavailable_ratio': 0.006873, 'worker_failures': 0, 'rejected': 0, 'passed': True}, 'test': {'planned': 291, 'unavailable': 0, 'unavailable_ratio': 0.0, 'worker_failures': 0, 'rejected': 0, 'passed': True}}` |
| `v2_provenance_size_contract_verified` | `True` | `gnn_eligible_samples=1446`, `v2_provenance_ready_samples=1446`, `retained_nodes_total=42308`, `verified_physical_spans_known_total=7741`, `verified_physical_spans_null_total=34567`, `stream_raw_payloads_known_total=9285`, `stream_raw_payloads_null_total=33023`, `projected_json_storage_bytes_used=False`, `null_to_zero_imputation_violations=0` |
| `security_sensitive_truncation_bounded` | `True` | `samples_losing_security_sensitive_nodes=0`, `observed_ratio=0.0`, `max_allowed_ratio=0.05` |

## 3. Stratified Dispositions by Split and Label

| Partition | Planned | Eval Denominator | GNN Eligible | Tabular Valid | Unavailable Empty | Rejected | `v2_provenance_graph_ready` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `train` | 870 | 870 | 866 | 870 | 4 | 0 | 866 |
| `validation` | 291 | 291 | 289 | 291 | 2 | 0 | 289 |
| `test` | 291 | 291 | 291 | 291 | 0 | 0 | 291 |
| `label=0` | 652 | 652 | 648 | 652 | 4 | 0 | 648 |
| `label=1` | 800 | 800 | 798 | 800 | 2 | 0 | 798 |

## 4. Unavailable-Document Ledger (Baseline)

- Total unavailable empty-graph documents: `6`.
- `unavailable_projection_filtered` indices: `[141]`.
- `unavailable_timeout_no_graph` indices: `[3, 11, 292, 407, 749]`.
- `unavailable_worker_failure` count: `0`.
- Evaluation abstention / tabular-fallback indices: `validation=[3, 141]`, `test=[]`.
