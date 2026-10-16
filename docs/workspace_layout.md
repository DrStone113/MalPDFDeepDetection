# Workspace layout and maintenance

Use the directory roles in [AGENTS.md](../AGENTS.md) for new work. The root
[README](../README.md) stays a short project overview. Feature proposals belong
in `plans/`; their presence does not authorize implementing or executing them.

| Directory | Contents |
| --- | --- |
| `src/malpdf/` | Reusable library and orchestration logic |
| `scripts/`, `configs/` | Thin CLI entry points and declarative configuration |
| `tests/` | Deterministic synthetic or benign fixtures |
| `docs/`, `plans/` | Technical guidance/status and proposed feature designs |
| `notebooks/` | Versioned notebook templates |
| `notebooks/generated/<study>/<run>/` | Ignored, generated notebooks for individual runs |
| `checkpoints/` | Local model weights and downloaded GPU output runs |
| `data/raw/`, `data/processed/`, `data/external/` | Ignored source data, derived data, and external cohorts |
| `reports/` | Formal experiment, analysis, thesis, and progress evidence |
| `.venv/` | The local Python environment, installed from `pyproject.toml` |
| `artifacts/markov_cache/` | Existing configured cache metadata; matrix locations remain configuration controlled |
| `artifacts/tmp/maintenance/` | Private maintenance logs grouped by domain |
| `artifacts/tmp/tests/` | Disposable test fixtures, multiprocessing temporary files, and pytest cache |

## Existing experiment contracts

Some established pipelines store private manifests, frozen models, probabilities,
and exclusive Test/campaign claims under fixed `artifacts/<study>/` paths. These
paths are validated by code and saved configuration. Keep them in place until a
separately tested migration updates their producers and consumers together.
In particular, preserve `artifacts/models/`, source/acquisition manifests,
`cic_static_prepare/`, `cic_static_profile/`, `cic_v9_prepare/`, and directories
ending in `_locks` or `_campaign`. Old model references are compatibility
contracts, not new output-location recommendations.

Never relocate or regenerate a partition manifest or a single-shot evaluation
claim just to make a directory tree shorter. New processed datasets, checkpoints,
notebooks, and formal reports belong in their dedicated top-level directories.
Private per-sample evidence stays ignored; it must not be copied into a public
report as part of maintenance.

## Run provenance and generated notebooks

`malpdf.provenance.research_runs.ResearchRun` keeps its existing immutable
`reports/experiments/<study>/<run>/` reports and collision/symlink checks.
For maintenance callers, `maintenance=True` places private logs under
`artifacts/tmp/maintenance/<study>/<run>/`. Other existing study paths retain
their compatibility contract.

Each run records the generating commit, dirty worktree state, and SHA-256 of
the selected Python/YAML source files in `generating_code_sha256.json`. It no
longer copies a source tree into `generating_code/`. Hashes identify dirty
source content; they do not make an uncommitted worktree reconstructible from
HEAD. Official experiments must start from clean committed code.

Kaggle bundle, performance-notebook, and multi-cohort exporters save new notebooks
through `save_generated_notebook` under `notebooks/generated/<study>/<run>/`.
Their summaries record the returned location. The writer validates path
components, rejects symbolic links, and refuses to overwrite an existing file.
`notebooks/generated/` is ignored; the reusable template remains versioned.

The v8/v9 fresh-environment validators also use `maintenance=True` and create
environments only at the root `.venv/`. They refuse an existing directory or
symlink instead of replacing it. V9 `--environment-run` accepts only a matching
saved preparation manifest for this root environment. Historical manifests
pointing into `artifacts/` are no longer reusable environment preparations.
For ordinary checks in an existing environment, use the commands below.

## Routine verification

Run from the repository root with the existing Python 3.11 environment. A short,
disk-backed `TMPDIR` supports multiprocessing Unix sockets without filling
RAM-backed `/tmp` with test fixtures.

```bash
mkdir -p artifacts/tmp/tests
TMPDIR="$PWD/artifacts/tmp/tests" MPLBACKEND=Agg \
  OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 \
  .venv/bin/python -m pytest tests/ \
  --basetemp=artifacts/tmp/tests/pytest -o cache_dir=artifacts/tmp/tests/cache
.venv/bin/python -m pip check
git diff --check
git status --short
```

Remove this invocation's disposable fixture directory only after the test process
and its workers have exited. Keep validation logs in the existing maintenance
domain and append the outcome to `reports/research_log.md`. Do not create a new
top-level `artifacts/` directory, environment, or source snapshot for each check.

## 2026-10-15 cleanup

Historical task directories with no active source/config consumer were grouped
under `artifacts/tmp/maintenance/`; their contents were preserved by filesystem
renames. Generated notebooks were relocated under `notebooks/generated/legacy/`.
Obsolete environments under `artifacts/` were removed after checking that no
process used them; the active root `.venv/` was retained. Historical source
snapshots remain evidence of earlier runs and are not reproduced by new runs.

The cleanup grouped 113 historical directories, reducing direct artifact
directories from 157 to 43, moved nine generated notebooks, and removed nine
obsolete environments. Measured free disk space increased by 15.614 GiB.
The Python 3.11.17 CPU verification passed all 1,000 dataset-free tests with
two retained single-label sklearn warnings; dependency and diff checks passed.

Historical reports and research-log rows retain their original bytes and paths.
For relocated private evidence, consult the ignored
`artifacts/tmp/maintenance/relocations.json`: replace a matching `from` prefix
with `to`, repeating if a notebook was subsequently relocated. Entries record
the move and preserve the original run identity. Do not rewrite a historical
report to hide a relocation or a retired environment.

The maintenance outcome and verification results are recorded in the append-only
[research log](../reports/research_log.md).
