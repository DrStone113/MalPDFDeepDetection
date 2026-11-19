# Bulk extraction recovery — 2026-11-19

The old bulk writer and its two children were stopped after verifying their process identities. All eight checkpoint markers and 40 output files retained their SHA-256 values. The old job and claim files also retained their hashes. The selection has 41,727 documents. The original 4,000 tabular identities match the pinned manifests and still partition into 3,903 graphs and 97 unavailable records.

All 60 original `rejected_unverified_cleanup` records had zero features and `fail_closed_abort_evaluation`. They were in chunk 7. Chunks 0–6 had zero such records.

## Candidate verification

- Source: `9297f9572528da96a44b87b4e63b0d09a19d7e6c`.
- The IPC reader drains through one complete frame or a nonblocking read boundary. Empty EOF preserves the worker exit classification. A malformed frame preserves verified checkpoints. The quality gate verifies finite and well-formed evidence without serializing the full evidence twice.
- Windows DEV, `.venv-windows-dev`: focused suite 102 passed and 12 Linux-only skips. Full baseline `ee646d7`: 2,101 passed, 187 failed, 23 skipped. Full candidate: 2,119 passed, 183 failed, 33 skipped. The set of failed or errored test identities `(file, classname, name)` introduced by the candidate was empty. `check_local.py` passed with 237/237 synthetic checks and `dirty=false`. Repository content and whitespace checks passed.
- REMnux: the scoped lifecycle, extraction, and runner suites yielded 387 passed and one skip. The skipped planning artifact lies outside the release allowlist. The Linux worker test used a reviewed benign fixture and a 256-FD process limit.
- Deployment checks and installs passed for the gateway, then the runner. Windows verified the live gateway policy `0ad21f0a09d7017502d9b9101f3186d0a8971a7ed927c9d6189047366e73341f`. Installed `lab_jobs.py` and `lab_runner.py` matched the sealed release and live policy. The deployed gateway passed 409 syntax and 6 synthetic checks. Firewall stayed `phase2_locked`, with NAT down.

## Operator handoff

- At handoff, the only selectable offline `pdf-static-bulk` job was `0f747ed1359440a57f02c3da52ccce1efc8cf3c117fc5328dbbb3e5e07620ae1`. It used the pinned 41,727-entry selection `5b6134576e836c5d9f8d8f41a80e3e471806944a4cef6643bca6952a9e8ae3b1`. Post-queue verification confirmed that all eight checkpoints, 40 artifacts, and the original job and claim retained their hashes.
- At handoff, the pilot cohort was locked from the eight original chunks. It contained 64 graph, 16 node-cap, 16 other unavailable, 16 large, and 16 worker/cleanup cases.
- A passing pilot allows adoption of chunks 0–6, covering 3,500 samples. The candidate then rebuilds chunk 7 and processes the remaining chunks, for 38,227 samples total. Publishing the rebuilt chunk preserves the original in `.chunk_00007.replaced-e5e6ca989c5dd20724c7b47ad34e887f2cc1f4277478e5eec155a73e074696d2`. Unexplained pilot differences block corpus processing. If a session stops at its time budget, run `lab run` again under the same offline conditions.

## First offline pilot

The runner recorded an attested offline session and compared all 128 pilot records. The result was 112 exact matches, 13 lifecycle recoveries with verified cleanup and result preservation, and three unexplained differences. The pilot exported 108 graphs. The console displayed `worker_failed` because the runner maps the pilot mismatch to a generic failure reason. The attempt recorded `cleanup_verified=true` and the candidate is no longer pending.

| Index | Changed field | Baseline | Candidate |
| --- | --- | ---: | ---: |
| 5 | `excluded_feature_count` | 118 | 112 |
| 509 | `excluded_feature_count` | 367 | 361 |
| 3486 | `excluded_feature_count` | 124 | 118 |

The exported feature records, graphs, metadata, and Markov bytes matched for those three identities. The pilot report SHA-256 is `141bc95ff0c9e89b880410064bbfc27cc948d3ca41939c637d5e68bb003d05e2`. Pilot bulk-pipeline time was 227.674 s. The observed peak RSS sum of the process tree was 1,793,310,720 bytes. The historical measurements cover a different workload and do not establish a speed or memory improvement on the pilot.

A benign-fixture probe with a 2,048-byte parser-inventory cap and two synthetic clocks reproduced a six-count change while all 296 exported features matched. The inventory cap returns the last retained snapshot, whose backend list depends on checkpoint timing. A backend contributes six records outside the projection allowlist. The saved corpus artifacts do not contain the detailed inventories needed to establish which excluded records account for the three actual differences.

The corpus run stayed behind the pilot gate. A readback confirmed that all eight original checkpoint hashes, all 40 artifact hashes, and the original job and claim hashes still match. No new corpus chunk was committed.

## Parser inventory candidate staged

- Release `b5f4f00ee0538dd9c157f467f87287794d46a57e` checks parser-inventory byte limits at each accepted change and coalesces only the IPC snapshots. The pilot reports eligible historical counter differences as `bounded_inventory_excluded_count` with both values. All other unexplained differences still block bulk. [BUG-013](../../docs/bugs/BUG-013-parser-inventory-checkpoint-jitter.md)
- Windows `.venv-windows-dev`: 2,138 passed, 183 failed, 33 skipped in the full suite. The failing test identity set matched `9297f95` and introduced zero failures relative to `ee646d7`. `check_local.py` passed 237/237 synthetic checks. The reviewed benign fixture matched the previous noncoalesced inventory at 250 cap thresholds.
- REMnux: 185 related tests passed with the file descriptor limit set to 256. The planning-artifact test was skipped because the release allowlist excludes that artifact. Gateway and runner install checks passed, the installed helper hashes matched the sealed release and active gateway policy, and the live gateway passed 409 syntax and 6 synthetic checks.
- The only pending job is `980050531188875ca4fc7a1b5d5d53b188b6e532f68bc55fd26f0cbad698f7db`. Its 128-sample pilot is identical to the first job's selection. The first job's terminal result and pilot report are preserved. After staging, all eight original checkpoint hashes and all 40 artifact hashes still matched. Firewall remained `phase2_locked` with NAT down.
- The candidate awaits `lab run` in the offline REMnux console. A passing pilot allows adoption of chunks 0–6 and a rebuild from chunk 7.

[Recovery plan](../../plans/bulk-extractor-recovery/plan.md)
