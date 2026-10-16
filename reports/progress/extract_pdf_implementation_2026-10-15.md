# Extract-pdf foundation implementation — 2026-10-15

Status: first static implementation increment and metadata-only job prepared;
the six-stage research roadmap is **not complete**. No real PDF was processed.

The authorization covers source changes, benign synthetic tests, saved metadata
inspection and preparation of an offline static CIC Train/Validation job.
Rendering, JavaScript execution/emulation, Reader and CAPE remain outside scope.
See [implementation, contracts and remaining work](../../docs/pdf_extraction.md)
and [plan checklist](../../plans/extract-pdf/implementation.md).

Implemented: linked evidence/feature/coverage stores and JSON Schemas, explicit
observation states, immutable primary checkpoints, bounded original-byte layout
profiling, v9 graph/per-script AST exports, inert action/event plans, API/CLI and
guarded metadata preparation/execution commands. Existing parser workers, byte
caps, checkpoint transport and seed42 group-aware selection are reused. No model
was loaded/fitted/evaluated and no Test identity was selected.

## Saved preparation

Run: `run_20261015T064943254953Z_7d02abdb85da`.
Generating revision: `7d02abdb85da108b64c92b51dfe10ddb02858cd3`, dirty worktree
recorded; previous local edits preserved. Preparation is permitted on dirty code
for review; actual execution requires a clean committed worktree matching the
sealed source/environment fingerprint.

- [Preparation summary](../experiments/pdf_extraction_prepare/run_20261015T064943254953Z_7d02abdb85da/run_summary.json)
- [Manifest provenance and checks](../experiments/pdf_extraction_prepare/run_20261015T064943254953Z_7d02abdb85da/preparation_checks.json)
- [Locked preparation methodology](../experiments/pdf_extraction_prepare/run_20261015T064943254953Z_7d02abdb85da/locked_methodology.json)

Selection: 32 Train and 32 previously exposed Validation records, 16 of each
class in each partition; saved Protocol G seed42 partitions unchanged. Complete
manifest metadata was checked for file/related/equivalent-group partition
integrity; Test was excluded from the selected diagnostic. Related CIC configs
agree on the three pinned manifest contracts. No PDF path was opened or hashed
during preparation/checking.

The checks report records full paths and SHA-256 for:

| Manifest | SHA-256 |
| --- | --- |
| `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/split_manifest.csv` | `e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643` |
| `data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv` | `d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b` |
| `data/processed/cic_normalization/run_20261003T104918756555Z_3b68d36a5705/normalization_manifest.csv` | `c4dc77f00849518ee56dc34d0f0cc7daf0c92b3ce9fd1e93fd63d053caf8570f` |

The private per-sample lock stays ignored under
`artifacts/tmp/maintenance/pdf_extraction_prepare/<run>/job_lock.json`.
It contains source/package fingerprints and selected source identities; those
identities are not copied into this aggregate report.

## Verification

Existing root `.venv/`: Python 3.11.17; dependencies are unchanged. The existing
environment was preserved and reused. Fresh installation/environment validation
was not performed in this task.

`pytest tests/`: **1038 passed**, 2 existing single-label sklearn warnings,
121.86 seconds. This includes 38 new extraction/job tests. The full suite ran
outside the tool sandbox with disk-backed temporary fixtures and bounded BLAS
threads, following the repository's documented multiprocessing test procedure.
`python -m pip check`, `git diff --check`, ignore coverage, unchanged unrelated
file hashes and append-only research-log prefix checks passed.

Private maintenance evidence is grouped under
`artifacts/tmp/maintenance/extract_pdf/`: `current.json`, `pytest.log`,
`prepare.log`, `checks.json` and `local_lab_state.json`. There are no new
top-level artifact directories, source-tree copies or artifact virtualenvs.

The current tool workspace has uid1000, an active SSH session and two connected
NICs. No agent socket or known credential files/environment values were detected
by the bounded presence check; this does not prove absence of all credentials.
The SSH alias `lubuntu` is not configured in this tool environment, so no second
remote checkout was verified or modified. The current repository path and HEAD
were verified with Git. Network state was not modified.

## Console handoff

Metadata-only recheck:

```bash
.venv/bin/python scripts/22_extract_pdf.py check --prepared-run run_20261015T064943254953Z_7d02abdb85da
```

After review/commit, verify offline isolation at the VMware console and follow
[the guarded execution procedure](../../docs/pdf_extraction.md#reproducible-offline-cic-job).
If runtime sources, configuration or package versions change, prepare a new job
against the same locked split. Do not reuse or delete the consumed v9 Final
claim. No new extraction claim was created in this maintenance task.

The historic 21 partial Validation PDFs remain untested by this increment.
QPDF, full filter/recursive decoding, Arlington, full historical object coverage,
abstract interpretation, media/visual processing, dynamic execution and release
packaging remain open. There is no measured detector or whole-format coverage
gain. Label=1 means malicious; F1/MCC/ECE/Brier are N/A because no model/partition
evaluation was performed. The retained ECE convention is ten equal-width
malicious-probability bins, with p=1 in the final bin.
