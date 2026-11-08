# BUG-007B2 — Graph Truncation & Node-Size Provenance Audit

Contract: `pdf-graph-truncation-audit-v1` | Quality view: `pdf-extraction-quality-v1` | Node cap: `200`

## 1. Cohort Overview

- Planned / Audited: `1452` / `1452` (`raw_pdf_processing=false`, `model_input_ready=false`).
- Non-empty projected graphs: `1377` (`uncapped=912`, `capped=465`).
- Empty projected graphs: `75` (`projection_filter_confirmed=[141]`).

## 2. Stratified Summary by Split and Label

| Partition | Planned | Non-empty | Empty | Capped (`>200`) | Valid under v1 contract |
| --- | ---: | ---: | ---: | ---: | ---: |
| `train` | 870 | 825 | 45 | 329 | 825 |
| `validation` | 291 | 273 | 18 | 87 | 273 |
| `test` | 291 | 279 | 12 | 49 | 279 |
| `label=0` | 652 | 618 | 34 | 212 | 618 |
| `label=1` | 800 | 759 | 41 | 253 | 759 |

## 3. Capped Cohort (`excluded_nodes_cap > 0`)

- Capped sample count: `465`.
- Dropped nodes by cap total: `274506` (median `495.0`, p95 `1353`, max `1425`).
- Dropped eligible edges by cap total: `90991` (`one_endpoint_capped=9352`, `both_endpoints_capped=81639`); non-eligible endpoint edges kept separate: `647885`.
- Samples dropping security-sensitive nodes (`action`/`script`/`annotation`/`filespec`/`stream`): `373` (`5658` nodes).
- Structural distortion on retained nodes: newly isolated `16`, newly orphaned `32`, disconnected from `catalog` `377`, retained WCC fragmentation gain `25`.

## 4. Node-Size Producers & Provenance Across Retained Nodes

| Size Definition | Known | Null (`None`) | Total Bytes | Model Feature Producer |
| --- | ---: | ---: | ---: | --- |
| `legacy_semantic_size_bytes` | 0 | 171055 | 0 | `True` |
| `verified_physical_declaration_span_bytes` | 5900 | 165155 | 24607946 | `True` |
| `stream_raw_payload_bytes` | 4445 | 166610 | 73584157 | `True` |
| `projected_json_storage_bytes` | 171055 | 0 | 160703249 | `False` |

## 5. Read-Only Virtual Post-B1 Overlay (Baseline Unmodified)

- Replay job: `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575`.
- Virtual post-B1 non-empty projected graphs: `1448` / `1452` (`uncapped=959`, `capped=489`, `empty=4`).
