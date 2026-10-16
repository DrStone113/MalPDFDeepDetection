# Research status and development evidence

This page preserves the research updates previously published in the project README. Results and test counts below describe their recorded historical revisions; they are not new measurements. See the [documentation index](README.md) for workflows and the [append-only research log](../reports/research_log.md) for dated provenance.

- [Current research status](#current-research-status)
- [Static evidence and inference speed](#static-evidence-and-inference-speed)
- [Static model development on Kaggle](#static-model-development-on-kaggle)

## Current research status

The first offline `extract-pdf` run completed on 2026-10-16 with all64 locked
Train/Validation records at commit `ba64a514ae5afe86b06e054f527cc066133d8afd`.
Its statuses are56 resource_limit,3 decode_error,2 partial,1 unsupported,
1 encrypted and1 observed; Test and model evaluation were excluded. A saved-JSON
audit verifies all64 original identities/labels/partitions and root checkpoints,
including **21/21 historical Validation partials**: original primary values and
the173-field projection exactly match the saved v9 baseline, including nulls.
Seven child checkpoints are kept separate. This satisfies preservation for
that locked cohort, while broader extraction coverage remains incomplete.
See [the post-run review](../reports/progress/extract_pdf_postrun_2026-10-16.md)
for the immutable source run, audit, reason counts and remaining limits.

The next Arlington code increment indexes cached raw dictionaries once per
document and retains duplicate values, context/source ownership and unknown
results. It changes no rule/model/resource limit and has synthetic/reference
verification only; the completed real run used the preceding code. The consumed
job/claim stays immutable, and the updated code has not been run on real PDFs.

The next predicate increment adds current-field BitClear/BitSet/BitsClear/
BitsSet under a32-bit bound and corrects Contains for typed scalar or array
operands. All four bit functions occur in the locked model (174 call sites,
not174 newly validated rules). Missing reference/type context, unsupported
predicates and invalid model arguments remain unknown. Synthetic verification
and six real-model fixtures are separate from future real-PDF acceptance.

On 2026-10-15, the first [extract-pdf implementation increment](pdf_extraction.md)
adds linked evidence/feature/coverage stores, bounded lexical profiling, inert
event planning and metadata-only preparation of the existing CIC Train/Validation
diagnostic. Synthetic validation and preparation are separate from real-PDF
acceptance: at that increment the historic21 partial files had not been rerun; no new detector
quality or whole-format extraction coverage is established. The broader QPDF,
Arlington, native-media, visual and dynamic roadmap remains open.
The next code increment adds bounded general stream filters and predictors,
with optional parent-verified raw/intermediate/prefix retention. It consumes only
v9's remaining byte allowance and preserves the original primary measurements.
See [the supported codecs and remaining limits](pdf_extraction.md#additive-stream-decoding).
Bounded recursion now follows verified complete decoded artifacts into PDF/ZIP,
ObjStm syntax, XML and inert JS ASTs. Child identities/features and every source
lineage remain separate; shared limits and partial checkpoints stay explicit.
Font/image/media decoders and full forensic coverage remain open. See
[recursive-artifact scope](pdf_extraction.md#bounded-recursive-artifacts).
The next increment adds original-byte QPDF/MuPDF/pypdf xref inventories and a
conservative merger preserving generation/key/value/stream disagreements. It
records QPDF offsets only after byte-header checks, keeps MuPDF generations
unknown, and preserves original model measurements. The declared dependency
and fresh Python3.11 environment are verified with synthetic fixtures; no new
real-PDF or detector result follows. See [native inventory scope](pdf_extraction.md#independent-native-object-inventories).
The raw forensic increment adds an independent byte lexer/object grammar,
traditional/binary/hybrid xrefs, scoped `/Prev` history, ObjStm syntax and static
reference IR with synthetic missing targets. It preserves physical duplicates,
length/boundary uncertainty, unlisted-member evidence and partial checkpoints;
revision ordinals require footer/prefix proof. Native/code/model measurements
remain separate. See [raw grammar and limitations](pdf_extraction.md#original-byte-grammar-xrefs-and-static-reference-ir).

The Arlington increment locks the user-selected public model at
`b7d880b7a3d3c8f505c025f17763397475e90503`: 610 TSV files and3976 rows, with
LICENSE/NOTICE and every checksum verified against that Git tree. Bounded rules
use cached raw IR, preserve unknown keys and original values, and keep unknown
predicates/context separate from failures or passes. Real-reference verification
uses generated benign fixtures only. Complete conformance, real-PDF acceptance
and detector gains remain unverified. See [the catalog and rule scope](pdf_extraction.md#locked-arlington-catalog-and-static-rules).
The [Arlington maintenance report](../reports/progress/extract_pdf_arlington_2026-10-15.md)
records the exact reference, final synthetic verification, manifest locks and checks.

The static script increment reuses existing JavaScript/XFA ASTs for lexical
alpha normalization, finite scalar data-flow transfers, conservative branch
joins/loop widening and source-linked call candidates. Original model/syntax
measurements remain unchanged; unknown effects, uninvoked functions, repaired
lineage and excluded calls stay explicit. No JS runtime/emulator, eval body or
host API is executed. These synthetic guarantees do not establish complete
script behavior or real-PDF coverage. See [the static script contract](pdf_extraction.md#static-script-semantics-from-existing-asts).
The [static JS/XFA progress report](../reports/progress/extract_pdf_js_semantics_2026-10-16.md)
records the saved synthetic bundles, final checks and unchanged Train/Validation lock.

The byte-image increment maps original bytes, confirmed object spans, completed
decoded streams/ObjStm members and admitted artifacts to lossless grayscale PNG
tiles. It records exact source namespaces/offsets, padding masks, resource caps
and separate encoded/transported/persisted coverage. The pass reuses admitted
buffers, preserves primary/v8/v9 and float32 Markov measurements, and performs no
page rendering or media decoding. Independent pixel/offset checks use generated
benign fixtures only. See [the byte-raster contract](pdf_extraction.md#lossless-byte-images-with-source-offsets)
and [its maintenance report](../reports/progress/extract_pdf_byte_images_2026-10-16.md).
Real-PDF and historic21-partial acceptance remain unverified.

The metadata-export increment adds `malpdf export` and library APIs for six
typed JSONL/Parquet tables, lossless original JSON records and NetworkX node-link
graphs. Optional Torch COO indices retain isolated nodes and edge multiplicity.
Null/status/scope/provenance, duplicate/failure occurrences and cross-run keys
are preserved; no model transforms, source-PDF reads or reference following occur.
Arrow round trips, actual NetworkX and tensor layouts are checked with synthetic
bundles. Native PyG/DGL and real-corpus scale/quality remain unverified. See
[the export contract](pdf_extraction.md#existing-bundle-tabular-and-graph-exports)
and [the export progress report](../reports/progress/extract_pdf_exports_2026-10-16.md).

The contract increment independently validates the three public JSON Schemas
against Draft 2020-12 and saved benign pipeline metadata. It fixes rejected
legitimate backend version/scope/Arlington/graph fields while retaining closed
core shapes, and adds missing runtime count/type/completion/JSON-safety checks.
The old schemas produced26 coverage errors across four synthetic bundles; the
updated schemas and runtime accept all12 store instances without changing source
metadata. The independent validator is a pinned dev dependency and uses an
offline registry. See [the schema contract](pdf_extraction.md#schema-conformance-and-runtime-invariants)
and [the contract progress report](../reports/progress/extract_pdf_contracts_2026-10-16.md).
These metadata checks do not establish real-PDF or detector coverage.

The static SDK increment implements all three requested extension contracts:
parser inventories, budgeted decoder routes and transactional feature batches.
Explicit Python registries pin source/configuration and preserve backend scope,
source links, repaired lineage and completed contributions after interruption.
Synthetic worker tests check imports under CPU/RAM limits, nested custom filter
dispatch and unchanged primary measurements. Plugins remain disabled in the
locked CIC job. See [the SDK contract](contributing_plugins.md) and
[its maintenance report](../reports/progress/extract_pdf_plugins_2026-10-16.md).
Corpus acceptance and the remaining dynamic/container/community release remain open.

The event-planning increment reuses exported graph/raw IR for owner-specific
document/page/annotation/field actions, declared XFA/name-tree scripts and raw
bookmark/link/form candidates. It preserves source IDs, repaired provenance,
unresolved destinations/selectors and a shared bounded traversal/output ledger.
No PDF/blob read, parse/decode or runtime operation is added by planning; the
original primary/code/v8 measurements remain separate. See the
[event-plan contract](trigger_plans.md) and
[synthetic maintenance report](../reports/progress/extract_pdf_triggers_2026-10-16.md).
Real-PDF and Reader/event feasibility remain unverified.

The [Vietnamese progress report for October 11, 2026](../reports/progress/progress_report_2026-10-11.html)
is a self-contained offline HTML document with presentation and print modes. It
summarizes the RIT training protocol, completed Kaggle Vision and FT runs,
optimization methods, stacking/calibration, retrospective CIC ablations, and
the sequence of static-extraction attempts, explaining each change, its measured
result and its limits. It uses plain Vietnamese in a student reporting voice,
explains key terms, and distinguishes the RIT CSV and CIC from the additional
PDFs acquired from Zenodo, Contagio and CVE-T4PDF for Vision training. Metrics
and effective training settings link to saved evidence.

Completed, versioned evidence covers the local RIT-PDFMal-2026 audit; paper-aligned Protocol P; feature-vector-disjoint Protocol G; a five-seed descriptive P/G comparison; paper-aligned XGBoost CV10; TreeSHAP; a fixed deep-learning comparison; safe static extraction and a static deployment artifact. Dynamic work is offline report-schema/routing infrastructure only; the isolated CAPEv2 laboratory is a design, not a live sandbox evaluation. The consolidated thesis package is under `reports/thesis/`.

RIT is available locally as CSV only. The authors report malicious samples from
VirusTotal during 2017–2025 and benign samples collected by their crawler
([dataset source](https://github.com/Mo-Alani/RIT-PDFMal-2026)). CIC PDFs support
future extractor development; RIT CSV cannot supply new JS/AST or byte features.

Rebuild its lightweight tables from committed reports only (no data loading, PDF access, model fitting, or benchmark rerun):

```powershell
.venv\Scripts\python.exe scripts\build_thesis_evidence.py
```

See `reports/thesis/thesis_evidence_index.md` for source provenance and `reports/thesis/limitations.md` before interpreting any result.

## Static evidence and inference speed

The October 2026 P0/P1 maintenance separates unknown structural/AST totals from
observed partial evidence. JSON diagnostics use `static-diagnostics-v3` and code
inspection uses `pdf-code-inspection-v7`: bounded PDFDocEncoding/Unicode text
decoding, action traversal priority, and explicit partial xref recovery alongside
ASCIIHex/ASCII85/Flate filters. Failed/incomplete PDF parsing refuses
deployment inference even when all numeric model inputs happen to be present.
Canonical 41-feature RIT measurements, source-defined sentinels, model artifacts
and locked partitions keep their established definitions.
See [the metadata audit, feature groups and offline commands](../reports/analysis/static_p0_p1.md).
This maintenance uses benign synthetic fixtures and reads dataset metadata only.

V7 extracts declared JavaScript from bounded XFA XML streams and ordered packet
arrays through the same inert AST worker. XML encoding/escapes and object/packet
provenance are retained; FormCalc is counted separately. DTDs, references,
malformed XML and exhausted budgets remain explicit partial evidence. The completed
locked offline job also recorded the existing P0/P1/P2 observed-evidence ablation
inside its original run, without another PDF pass or source-cleanliness bypass.
See [scope and verification](../reports/analysis/cic_static_xfa.md). Synthetic
coverage is verified. The v7 console run on the same 64 files completed on October 10:
recall and parser coverage stayed unchanged; strict C1 false positives fell
from 3/5 to 2/5 classified benign files. The P0/P1/P2 fallback hard-label counts
were unchanged. This small development result does not establish a general
accuracy gain. See [the measured v7 result](../reports/analysis/cic_static_offline.md#completed-v7-xfa-paired-measurement).

The `development/v8.0` candidate adds a separate `pdf-evidence-v8` LAB view:
read-only MuPDF recovery, object/action/attachment evidence, backend conflicts,
primary-result checkpoints, and a fixed C1 model with explicit abstention and
Train-only missingness handling. V7 remains the baseline. The final same64 offline
measurement completed on October 11 at 01:22:10 Asia/Ho_Chi_Minh, but release
acceptance is blocked. Complete analysis stayed at 23/64; 15 former parser errors
became partial results. C1 coverage fell from 11/32 to 9/32, with TP3/6 and FP2/3
among classified files. Three overlay worker errors changed the legacy fit/evaluation
cohorts, so the P0/P1/P2 changes do not establish a model improvement. The subsequent
backend/checkpoint repair passed 817 dataset-free tests; it has no new CIC measurement.
See [measured results, diagnosis and remaining limits](../reports/analysis/cic_static_v8.md).

The `development/v9.0` implementation adds `analysis_v9` (`pdf-evidence-v9`):
immutable observations, verified action/script/XFA/attachment relationships,
per-script AST summaries, parent-held raw streams and additive worker checkpoints.
C1 uses the original v8 RF173 artifact, its saved Train31 preprocessing and
threshold0.5; P0/P1/P2 use the original v7 artifacts. There is no retraining,
calibration, feature addition or threshold selection. Partial positives require
verified model inputs and an eligible linked evidence chain. Incomplete negatives
remain Inconclusive. Conflicts and caps are checked against model and graph
dependencies; ambiguous conflicts still abstain.

V9 code validation and real-PDF acceptance are separate. The console launcher
`scripts/20_launch_cic_v9.py` offers **Integration** (Enter) for exactly the three
historic AttributeError inputs and **Final** for the sealed same64 diagnostic.
Integration must pass before final preparation; its aggregate reports must be
reviewed and committed to restore the clean-worktree requirement. A campaign-wide
atomic claim permits one final attempt across all prepared jobs. Failed or
interrupted claims remain intact. The v8 shortcut continues reading its saved
outcome. Real PDFs remain restricted to the disconnected non-root VMware console
with the selected shared-folder/clipboard/drag-drop procedure. See
[V9 contracts, checks and console handoff](../reports/analysis/cic_static_v9.md).
The corrected three-file console integration passed 3/3, with primary features
unchanged and source hashes/worker cleanup verified. Its partial results retain
localized failures and checkpoints within the existing 2MiB metadata budget.
The matching fresh Python3.11 CPU validation passed 987 dataset-free tests with
two retained sklearn warnings; dependency, source-integrity, diff and ignore
checks passed. Detector-quality metrics were measured in the
[completed Final attempt](../reports/experiments/cic_v9_final/run_20261011T045223500000Z_ff3f5b65d376/run_summary.json).
It recorded all 64 cold and 64 warm profiles, with source identity and worker
cleanup verified. The v9 overlay has 22 complete and 42 partial results, with no
worker-unavailable files. C1 still classifies 9/32 development files (28.1%):
TP3/6 and FP2/3 among classified files, with 23 abstentions. All 32 C1 decisions
match v8; this does not establish an accuracy or coverage gain.
The [saved-metadata acceptance review](../reports/experiments/cic_v9_final_review/run_20261011T050628599657Z_ff3f5b65d376/review_evidence.json)
explains the six P1/P2 input changes across the three recovered-xref files and
preserves probability/hard-label parity on unchanged inputs. It records individual
private explanations for all 21 old partials. Acceptance remains blocked by graph
caps and ambiguous dependency scopes; one Train graph became partial while its
primary measurements stayed complete. The Final campaign claim is consumed;
reopening the launcher reads the saved outcome. See
[measured results and remaining limits](../reports/analysis/cic_static_v9.md#completed-final-measurement).

Static inspection now reads one size-capped, stable byte snapshot.
`malpdf.inference.StaticScanSession` reuses a verified frozen XGBoost deployment
model and predicts compatible rows in bounded batches, with optional TreeSHAP.
`malpdf code-inspect /explicit/local/sample.pdf` adds redacted JavaScript AST
evidence from literal/Flate/ASCIIHex/ASCII85 streams in a disposable resource-limited process;
unsupported/failed analysis recommends referral. It never executes JavaScript.
Use `malpdf scan /explicit/local/sample.pdf --json --no-explanation
--code-inspection` for combined output. This does not change v3/v4 models or labels.
See [design and limitations](../reports/analysis/static_acceleration_design.md).
`scripts/14_benchmark_static.py` measures synthetic ingestion/inference timings
from clean committed code without touching external datasets or Test partitions.
`scripts/16_benchmark_cic_static.py prepare` locks a small CIC Train/dev subset
from saved manifests without reading PDFs. Its `run` action requires the offline
console LAB, records every parser/AST failure and times the actual pipeline.
Profile v2 separates inference gate/refusal time from actual `predict_proba`,
which is null when no model call occurs. `prepare --baseline-run <profile_id>`
locks the same64 inputs/configuration and writes a paired status comparison.
For the original Windows estimator at
`artifacts/models/xgboost__G-drop3constant.joblib`, add that path as
`prepare --model-file ...`. Preparation checks its binary 38-feature contract,
fixed configuration and native-JSON probability parity, then pins a private
snapshot and source checksum without fitting. This supplied Protocol G model
has its own identity; it does not replace the full-RIT deployment manifest.
See [offline job and measurement limits](../reports/analysis/cic_static_offline.md).

The completed v6/v7 Lubuntu measurements used **Chạy CIC offline** on the Desktop
after the selected disconnected console LAB procedure. The shortcut invokes a
locked job through the existing guarded CLI, accepts Enter to start or `q` to
cancel, and keeps the terminal open after completion or failure.
The [first v8 invocation](../reports/experiments/cic_static_profile/run_20261010T172942216671Z_2d744ec19f24/run_summary.json)
failed before PDF access because available RAM did not meet the isolated parser
budget. Its claim and reports remain intact. Parser admission now runs before
claiming and again after model loading; repeated launches display the saved status
and report instead of starting another attempt. The shortcut's
[replacement v8 job](../reports/experiments/cic_static_prepare/run_20261010T181103978407Z_d5cb3d5309e1/run_summary.json)
has now [completed its measurement](../reports/experiments/cic_static_profile/run_20261010T181946430830Z_3c5f90ef33fb/run_summary.json).
Reopening the shortcut or using `scripts/18_launch_cic_offline.py --check` reads that
saved outcome without starting another job. See
[current launcher status and RAM preparation](../reports/analysis/cic_static_v8.md#limits-and-final-execution).
Its VM-specific desktop entry is versioned
in `configs/cic_offline_launcher.desktop`; the thin entry point is
`scripts/18_launch_cic_offline.py`. This shortcut does not change network settings.

The fixed CPU study `scripts/17_train_cic_static.py` compares the supplied frozen
RIT model against one XGBoost candidate fit on the saved CIC Train partition
using the controlled cached feature table. Its 40 predictors retain measured
`script_ratio` and `ObfuscationCount`; dropping them creates cross-partition
feature-equivalent groups. The three exclusions must be zero constants on
Train, and all Test identities are discarded before numeric conversion.
Threshold0.5 and the established XGBoost configuration are fixed before fitting.
Numeric Validation classification and missing-row denominators are reported
separately from PDF parser coverage. This does not replace deployment artifacts
or establish independent Test accuracy. See
[the accuracy diagnosis](../reports/analysis/cic_static_accuracy.md).
The completed fixed candidate reduced false positives but lost malicious recall
on the 291 previously exposed CIC Validation rows; it remains a development
artifact. The frozen model stays in use. The completed same-64 offline v5
profile increased files with observed AST evidence from 11 to 20, retaining
partial status for recovered/incomplete analysis. Complete/partial/parser-error
counts remain 23/23/18; the small RF pilot's recall/FPR are unchanged from the
earlier run. No full-pipeline classification improvement is established.
See [the measured v5 result](../reports/analysis/cic_static_offline.md#completed-v5-paired-measurement).
Prepared jobs must match their locked extractor fingerprints.

The saved-profile ablation found no hard-label gain from observed AST on the
first64 cohort: P0 and P1 detected12/16 malicious development files and falsely
flagged13/16 benign files. Additional parser flags reduced false positives by
one, with MCC0. All32 development inputs were eligible for the experimental
fallback; this is not complete parser coverage or a deployable improvement.
The negative evidence is retained and no candidate is promoted.

Code-inspection v6 addresses the specific missing-`startxref` case with one
fixed, in-memory reconstruction retry through the existing bounded pypdf
worker. Original bytes/hash/raw counts stay unchanged; strict failure remains
visible and recovered evidence stays partial, with unknown totals. Existing
markers and resource failures are not replaced/retried by this path. The
completed same64 v6 run recovered partial structure on14 additional files,
including AcroForm/XFA/embedded-file evidence. JS/AST file counts stayed25/20;
whole-file status, strict classifier coverage and recall/FPR were unchanged.
See [the measured v6 result](../reports/analysis/cic_static_offline.md#completed-v6-paired-measurement).
Completed jobs are historical evidence; later source changes require a newly
prepared fingerprint before another offline invocation.

The separately locked saved-profile ablation reuses that completed v5 LAB
evidence without reopening PDFs:

```bash
.venv/bin/python scripts/17_train_cic_static.py --config configs/cic_profile_accuracy.yaml
```

The matched study of the completed v6 evidence uses
`--config configs/cic_profile_accuracy_v6.yaml`. A separate fixed RF200 baseline
on all870 cached CIC Train rows uses `--config configs/cic_static_rf_accuracy.yaml`.
Both reuse the same entry point, fixed threshold0.5 and saved splits, without
reopening PDFs or evaluating Test. Their experimental candidates stay in LAB.
Both studies completed without promotion. The larger RF candidate's recall fell
to23.75% while reducing FPR to25.95% on291 cached development rows. On32 v6
development rows, additional observed structure/AST kept12/16 TP but increased
FP from13/16 to14/16. These exposed development results do not establish a
full-PDF accuracy gain. See [the preserved outcomes](../reports/analysis/cic_static_accuracy.md).

Three fixed RF variants share the same eligible 32 Train and 32 development
rows: canonical RIT41 measurements, additional complete/observed structure and
AST evidence, then additional parser-status flags. Unknown totals stay null;
observed values are explicitly named lower bounds. Median imputation and
missing indicators fit on Train only. An experimental raw-feature fallback
retains parser-error rows whose bounded byte snapshot and raw measurements
were verified; missing input still refuses classification. This study does not
change the production gate. All failures stay in coverage denominators and
status-stratum results. Fixed threshold 0.5, no tuning or Test access, and
separate LAB-only model identities prevent replacing the supplied RIT model.
Previously exposed, balanced development evidence requires larger and fresh
offline confirmation before any deployment or full-pipeline accuracy claim.

## Static model development on Kaggle

`scripts/15_train_static_development.py launch --root /path/to/data-workspace` starts a private, internet-disabled Kaggle GPU study from a clean committed code worktree, using the existing authorized v4 numeric dataset. No dataset is uploaded. `collect --root /path/to/data-workspace --launch-run <run_id>` imports checksum-verified numeric evidence after completion; checkpoints remain in private Kaggle Output to save Codespace disk space.

The separately locked retrospective study compares uniform training with cohort/class/group-balanced training over the existing five Train folds. XGBoost, LightGBM, CatBoost and Random Forest run on Kaggle CPU; FT-Transformer uses CUDA FP16 AMP, preloaded tensors and persistent pinned DataLoaders. All 40 measured security features and metadata missing flags remain. Preprocessing fits only on each Train fitting fold. The existing four Validation roles separately control early stopping, meta fitting, Platt fitting and MCC/Youden selection. Selection maximizes macro-cohort Validation MCC with recorded tie-breakers. CIC's base-selection role contains only one equivalence group; this limitation is reported explicitly.

This is a five-branch static ablation; the existing Vision model and previously evaluated Test sets remain unchanged. Test rows are excluded before preprocessing, fitting, weighting and inference. Validation results are development diagnostics, requiring future independent-cohort confirmation, and do not establish new Test accuracy. Historical runs are retained; launch, import, metrics and checks append to the research log.

The completed 50-fit Kaggle study did not improve CIC discrimination: Accuracy stayed 53.125% on the 64-row Validation selection subset, and MCC remained near zero. Cohort balancing improved CIC calibration but worsened source calibration. The candidate has not replaced the deployed model. See the [immutable development summary](../reports/experiments/static_development_summary/run_20261004T154256846017Z_e9ae2aee5365/summary.md).

For the paired byte-profile study, pass `--configuration configs/static_markov_development.yaml` to the same launch command. It attaches both existing authorized private numeric datasets without uploading additional sample data. Two variants use identical saved Train folds and new group-diverse roles within the existing Validation partition: the original 40 structural features and those same features plus 33 fixed Markov descriptors. Original split and role files remain immutable. Each Validation role has at least ten groups and both classes per cohort; large indivisible groups can still prevent equal row or class counts. FT checkpoint loss gives each cohort equal total weight and equal weight to groups within a cohort, so large equivalence groups cannot dominate stopping. Meta fitting, Platt fitting, and Youden/MCC selection remain on disjoint Validation roles. No Test matrices, inference, or metrics are used.

The Markov descriptors measure sparsity, conditional entropy and transitions between byte-value bands. They preserve float32 probabilities and require no fitted transform. Two bounded CPU processes read only verified Train/Validation NPY members directly from the existing numeric inputs, without expanding caches to disk or reading PDFs. FT inputs are preloaded into RAM and use the existing CUDA AMP training budget. Compare the paired variants on this study's same Validation selection rows; the earlier 64-row 53.125% result is a different development subset. Validation gains are hypotheses requiring future independent evidence; neither new Validation roles nor byte summaries establish ground-truth labels or JavaScript exploit detection.

The completed paired study trained 50 models on Kaggle in 226.604 seconds, excluding startup and output import. On its same 48-row CIC Validation selection subset, structural-only stacking achieved Accuracy 56.25%, MCC 0.130551, and AUROC 0.547826; adding Markov descriptors achieved 52.0833%, MCC 0.008696, and AUROC 0.382609. The added descriptors separated formerly identical feature vectors but did not improve discrimination. The structural-only development candidate won the locked selection criterion; existing deployed models remain unchanged. All 96 saved metric rows were independently verified, and no Test inference was performed. See the [paired study evidence](../reports/experiments/static_markov_development_summary/run_20261004T174737533805Z_7b3fc6194800/summary.md).
