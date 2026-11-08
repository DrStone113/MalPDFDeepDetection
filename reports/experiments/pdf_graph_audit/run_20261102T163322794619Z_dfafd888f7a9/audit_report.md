# Audit PDF Extractor and graph quality

## Result and scope

Audited 1452/1452 saved JSON bundles. Existing projection has 1377 graphs and 75 empty projections. Input availability: `{"present": 1452}`. No raw PDF was read, parsed, executed, copied or queued by this audit. Classifier training/evaluation was not run. `model_input_ready=false`.

## Missing projection classifications

| Evidence family | Cases |
| --- | ---: |
| `projection_filter` | 1 |
| `timeout` | 4 |
| `worker_error_unspecified` | 70 |

Cause status for the missing-projection cohort: `{"confirmed": 1, "unresolved": 74}`. Confirmed means a specific represented-view mechanism is supported; it does not certify a whole PDF as corrupt, harmless, or intrinsically ungraphable. Generic `worker_admission_failed` remains unresolved because the source catches OSError/ValueError across the profile call. A timeout confirms a recorded timeout, not its underlying root cause. Parser errors alone cannot prove PDF corruption. This audit does not certify legitimately empty PDFs without a verified completed relevant scope.

| Index | Parser candidates | Observed objects with projection | Objects with any projection | Classification |
| --- | ---: | ---: | ---: | --- |
| 126 | 0 | 0 | 0 | `timeout` |
| 141 | 16 | 13 | 13 | `projection_filter` |
| 496 | 0 | 0 | 0 | `timeout` |
| 749 | 433 | 0 | 0 | `timeout` |

Inventory candidates and failed reads are not successful graph nodes. Multigraph edges, separate backend observations, shared references and cycles are retained. The old nine-kind projection excludes parser/forensic inventory records; available evidence is not silently promoted into a replacement model graph.

## Measurements

The projection retains at most 200 eligible nodes. 465 samples excluded additional eligible nodes by this cap. Node and edge exclusions are counted separately by kind, observation status, cap and retained endpoint membership. Structural issue totals: `{"dangling_edges": 0, "duplicate_edge_ids": 0, "duplicate_node_ids": 0, "invalid_attributes": 0}`.

`original_object_span_bytes` is the verified half-open original-byte interval from the indirect object header through the end of `endobj`. It requires a raw-forensic observed top-level declaration, matching record/producer boundaries and object identity. Measured declarations: 8619; other evidence records retain null with an explicit reason. Direct semantic nodes, decoded object-stream members and unverified spans do not inherit another object's byte length. Overlapping spans are not summed into document coverage.

These measurements apply only to their own raw-forensic declaration records. They do not backfill the legacy semantic projection: 171055 retained projection nodes still have unknown legacy size_bytes attributes. No object-number-only or cross-backend join is used.

`node_record_storage_bytes` and graph wire storage count canonical JSON UTF-8 bytes (sorted keys, compact separators, ensure_ascii=false, finite numbers, no newline). Graph wire data consists of nodes/edges only. These are serialization costs, not original PDF size, RSS, or proposed model predictors. Source bundle file bytes are recorded separately.

Distributions use min/median/nearest-rank p95/max with known and null counts. `feature_dim=null` because this audit does not materialize a feature tensor. Legacy target dimension 19 is metadata only. No null-to-zero conversion or placeholder node is performed.

## Source execution map

Runner selection/hash pins → isolation/admission → disposable worker and append-only IPC checkpoints → legacy pypdf/MuPDF graph → native pypdf/QPDF/MuPDF inventory → original-byte forensic evidence → normalization → full evidence graph versus nine-kind projection/export.

The graph fallback already exists and is distinct from native inventory. QPDF inventory is not proof that a QPDF semantic graph was built. Backend graph status and native-view status are reported separately. The profile parent restores saved primary/checkpoint evidence on known worker failures; the orchestrator's outer generic exception path can replace profile diagnostics with worker_admission_failed. The legacy graph builder reads details.size_bytes with a zero fallback; the current numeric projection keeps unknown sizes null. This audit changes none of those producer paths.

## Proposed work order, not implemented

1. Preserve bounded error enums, originating stage and verified checkpoints through admission/IPC/profile failures. Investigate the unresolved generic worker errors before changing parser behavior.
2. Review evidence excluded by projection, beginning with samples with observed native objects. Define a separate versioned graph view before extending node kinds or merging backends; retain backend/revision provenance.
3. Reuse verified saved spans for applicable physical declarations. Define producers for still-missing model attributes; do not substitute JSON storage length for PDF object length.
4. Reproduce supported parser/fallback failures on safe fixtures. Propose offline diagnostic runs only for cases whose next_action requires new information; preserve the 1452 denominator and labels/splits.
5. Validate the complete cohort and an explicit unavailable-document policy before a later training-readiness decision. No demand for 1452 nonempty graphs is imposed.

The proposed diagnostic candidate indices are in metrics.json and cases.jsonl. The indices are a proposal, not an armed or queued job. Any future real-PDF parser run retains the operator `lab run` gate. Original bundles and historical experiments remain unchanged.
