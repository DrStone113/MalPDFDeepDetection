# Development environment and verification

For the offline extractor launcher, admission/cancellation, credential-presence,
shell quoting and exit-status tests are in `tests/test_extraction_launcher.py`.
They use synthetic state only. The full suite also checks that shell launcher
source is sealed and source drift is refused; see
[LAB handoff](extraction_lab_handoff.md) for operator use.
The interactive flow waits for manual VMware isolation and one Enter, then
rechecks admission before any agent action or job. Tests cover opening while
connected, manual disconnect during the prompt, repeated Enter while still
connected, reconnect/code drift after confirmation and cancellation. Check-only
and noninteractive calls never stop an agent or attest readiness.

Optional local-agent shutdown is tested in `tests/test_local_agent.py` using an
owned disposable Python process/socket with tracing disabled, never a real user
agent or key store. Cases verify PID/user/name/socket checks, immutable pidfd
targeting, isolation recheck, cancellation/timeout/socket survival and retention
of all unrelated credential variables. No credential contents are read.
Stale-selection tests separately cover an exited/reaped process with no socket,
live/reused PIDs, surviving/dangling sockets, permission errors, selection/socket
changes and console-guard refusal. Only confirmed absent PID plus absent socket
permits clearing the two launcher-local variables. UI tests preserve other
credentials and prohibit cleanup before Enter/isolation or in check-only.

Use Python 3.11 for local and Codespace checks. Python 3.13 support applies to the authorized Kaggle GPU runtime; record effective package and CUDA versions for each run. The dependency declaration is [pyproject.toml](../pyproject.toml). Tests use synthetic or benign fixtures and require no external datasets.

- [Windows local setup](#windows-local-setup)
- [GitHub Codespaces](#github-codespaces)
- [Handoff checks](#handoff-checks)

See [workspace layout](workspace_layout.md) for output locations, legacy path
contracts, and disk-backed multiprocessing test commands. Keep local environments
at `.venv/` and maintenance logs under `artifacts/tmp/maintenance/`.

## Windows local setup

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
malpdf --seed 42
```

Dataset access requires an explicit human instruction. Place approved samples under `data/`, or follow the [reviewed acquisition workflow](workflows.md#explicitly-authorized-public-pdf-acquisition) after authorization. Follow the safety rules in [AGENTS.md](../AGENTS.md); never execute or manually open suspicious PDFs.

## GitHub Codespaces

To move the current private data and saved evidence to a local Lubuntu VMware
machine, follow [the transfer and restore guide](lubuntu_migration.md).
Migration archives remain ignored under `artifacts/migration/`; source datasets,
Markov matrices and checkpoints are never committed. The transfer preserves
existing splits, validation locks and Test markers, and restores a fresh Python
environment rather than copying a Codespace virtual environment.

The repository includes a Python 3.11 devcontainer for reproducible source development and synthetic-test execution. Create a Codespace from a committed revision, allow its post-create command to install the project from `pyproject.toml`, then run:

```bash
python -m pytest -q
python -m pip check
```

The devcontainer installs PyTorch 2.11.0 and torchvision 0.26.0 from the CPU wheel index, with versions declared solely in `pyproject.toml`. This avoids PyTorch's unused CUDA libraries in Codespace. It does not promise GPU availability. Authorized Kaggle GPU runs may use the corresponding CUDA builds (for example, the observed `+cu128` image) and Python 3.13; always record effective versions. XGBoost 3.2 through 3.4 is supported, covering the local baseline and observed Kaggle image. Codespaces is not an approved malware-execution sandbox and does not itself authorize uploading or downloading raw PDFs, sample hashes, or extracted sample metadata. The devcontainer never acquires or processes samples. The separate acquisition CLI requires explicit human authorization; follow `AGENTS.md` before any sample handling.

For a fresh local Linux environment using CPU wheels:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu -e '.[dev]'
.venv/bin/python -m pytest tests/
.venv/bin/python -m pip check
```

Python 3.13 can use the same project declaration in an authorized cloud environment. Kaggle images may omit `ensurepip`; create the virtual environment with `--without-pip` and use the existing pip's `--python /path/to/venv` option to install software into that isolated environment. CUDA training uses the matched PyTorch/torchvision CUDA builds and the current `torch.amp` API. A dependency upgrade does not authorize a new dataset acquisition, split, or Test evaluation.

The upgrade passed all 578 tests on both Python 3.11 and Python 3.13, with clean dependency checks. The [compatibility report](../reports/experiments/pytorch_runtime_summary/run_20261004T155638273289Z_e9ae2aee5365/summary.md) records versions, warnings, failed preparation attempts and the older FT checkpoint compatibility check.

## Handoff checks

Run these checks in the selected Python 3.11 environment before handoff:

```bash
python --version
python -m pytest tests/
python -m pip check
git diff --check
git status --short
```

Code, CLI and configuration changes need corresponding tests and technical updates in `docs/`.
The extraction foundation and offline-job fixture checks are in
`tests/test_extraction.py` and `tests/test_extraction_jobs.py`; see
[the implementation and remaining acceptance](pdf_extraction.md). These checks
do not authorize real-PDF processing in the development environment.
The filter-matrix tests are in `tests/test_stream_filters.py` and
`tests/test_stream_extraction.py`; they generate inert buffers/PDFs and exercise
LZW width changes, packed predictors, partial Flate evidence, verified blob
transport, source identity checks, byte/metadata limits and worker interruption.
`tests/test_recursive_carving.py` adds generated ZIP/PDF nesting, content reuse
with separate lineage, child feature namespaces, root-only trigger planning,
CRC/data-descriptor failures, XML/ObjStm syntax, AST reuse and shared budgets.
It injects recursive checkpoint timeouts and verifies worker cleanup without
processing real samples or running embedded code.
`tests/test_parser_inventory.py` exercises real installed QPDF/MuPDF/pypdf on
generated fixtures, compressed objects, nonzero generations, verified offsets,
key/value/stream disagreements, exact QPDF decimals, unavailable scopes and
partial worker checkpoints. `pikepdf==10.17.0` is declared in `pyproject.toml`;
record its bundled QPDF version as well as Python/package versions.
`tests/test_raw_forensic.py` verifies independent byte grammar, stream boundary
proof, incremental/hybrid/binary xrefs, compressed members, scoped orphan/free/
generation handling, synthetic missing targets, partial prefixes and native
comparison. It checks linearized sections and incomplete/forward-pointing
footers without inventing revision ordinals. All input is generated in memory
or benign test scratch; no dataset/PDF acquisition or dynamic execution occurs.
`tests/test_arlington.py` generates local TSV/Git models and benign PDF bytes to
check exact locks, drift refusal, typed expressions, unknown propagation, null,
reference/inheritance/default provenance, OR schema candidates, wildcard redaction,
repeating arrays, limits and timeout recovery. It does not depend on the external
reference snapshot. Separately, `scripts/23_arlington_model.py verify` and `smoke`
check the actual pinned model; the latter generates its own benign fixtures.
Both preserve unique maintenance evidence and append the run register. No model
download, real sample processing, rendering or script execution occurs at runtime.
`tests/test_js_semantics.py` covers source-preserving AST reuse, scope-aware
alpha normalization, finite values/unknowns, conservative effects and loops,
source-linked call graphs, XFA/nested-PDF origins, repaired flags, activation
route differences and timeout recovery. All scripts/PDFs are generated benign
fixtures; no JavaScript function or host operation is invoked. The new pass
shares worker caps and runs after primary/native/raw/Arlington checkpoints.
`tests/test_byte_images.py` verifies exact byte/pixel round trips with an
independent Pillow decoder on generated benign PNGs, padding masks, head/tail
selection, source offsets, decoded-container namespaces, repair flags, shared
retention and metadata limits. It checks unchanged primary/v8/v9 and float32
Markov results, explicit parent persistence, private CLI output paths and
checkpoint recovery/cleanup after timeout. The encoder uses the standard library;
Pillow is already present through the declared torchvision stack and is only a
test oracle on locally generated images. No PDF page or embedded image is rendered.
The byte-image parity fixture uses identical30s wall/12s CPU/1GiB limits on
its two v9 workers to allow bounded startup slack; this is not a latency test.
Configured offline jobs retain20s wall/12s CPU/1GiB. The native checkpoint
timeout test constructs its inventory before starting the one-second deadline,
so it checks checkpoint preservation rather than native startup speed.
`tests/test_extraction_exports.py` checks JSONL/Parquet reconstruction of complete
bundles and original metadata, typed bool/int/float/null values, signed zero,
bigint/locator overflow, duplicate/failure occurrences and cross-run keys. Real
Arrow/NetworkX/Torch tests retain parallel edges, self loops, isolates and empty
tables; malformed inputs, collisions, limits and interruptions preserve explicit
failed evidence. No source PDF/blob/reference is read. The tests use the declared
PyArrow/PyTorch stack; NetworkX is already a PyTorch dependency. PyG/DGL are not
added or tested as native consumers.
`tests/test_extraction_contracts.py` uses the pinned `[dev]` dependency
`jsonschema==4.26.0` to validate published Draft 2020-12 schemas independently
of `validate_bundle`. Its registry refuses remote references; network functions
are blocked during offline schema/instance tests. It covers legitimate backend
extensions, closed core shapes, all observation states, JSON-safe opaque
metadata and runtime-only counts/identity/reference checks. Production
extraction still uses the standard-library contract validator. After updating
dev dependencies, install them from `pyproject.toml` with the setup command
above and record the effective package versions rather than claiming the prior
environment is identical.
Record maintenance and experiment attempts in the [research log](../reports/research_log.md),
using saved evidence and `N/A` with a reason when no model was evaluated.

`tests/test_extraction_plugins.py` exercises the explicit static SDK with trusted
synthetic implementations. It checks source/configuration drift, import-time
CPU/RAM limits inside the spawned worker, root/child custom filter dispatch with
shared quotas, parser inventory merging, transactional namespaced features,
repaired lineage and preserved checkpoints after timeouts. It loads no external
plugin or dataset. See [the plugin authoring guide](contributing_plugins.md).

`tests/test_trigger_planner.py` verifies static event candidates from existing
exported graph/raw IR. Generated benign native/raw fixtures cover document/page/
annotation/field mappings, JavaScript name trees, XFA declarations, bookmarks,
internal destinations, typed form proposals and compressed objects/XRef streams.
It checks source IDs, repaired origins, consistent/conflicting reference evidence,
owner/backend guards, cycles versus shared DAGs and all planner quotas. A metadata
I/O-denial test blocks reparsing/decoding/network/file access; a real worker fixture
checks new plan families and unchanged primary/code/v8 output. No event is executed.
See [the plan contract and runtime limits](trigger_plans.md).
