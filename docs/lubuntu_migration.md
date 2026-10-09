# Restore the private Lubuntu VMware transfer

The 2026-10-09 maintenance task packages existing local data as opaque bytes.
No dataset is downloaded, PDF parsed or rendered, model fitted, split regenerated,
or research Test evaluated. PDF samples remain untrusted: never open them in a
viewer or run embedded content. VMware does not itself authorize dynamic analysis.

The transfer is a private local file under ignored `artifacts/migration/`.
It includes a compressed data archive, all local Git branch history in
`repository.bundle`, a private file-checksum manifest, effective Python/package
versions, and a copy of these instructions. Credentials and virtual environments
are excluded. Code, configurations, aggregate reports, and the research log are
committed separately; raw data, matrices and checkpoints stay outside Git.

Keep the Codespace until you have downloaded and verified the transfer on your
machine. The source data is retained. A file left only in `/tmp` is temporary;
use the final file under `artifacts/migration/` supplied at handoff.

## Download and verify

Download the final `MalPDFDeepDetection-transfer-20261009T055256Z.tar` through
the VS Code file explorer, then copy this archive into the VM. Copying the
opaque archive does not require opening any individual PDF.

The outer archive contains `MalPDFDeepDetection-transfer-20261009T055256Z/`.
Its exact size, SHA-256 and measured storage needs are recorded in the adjacent
handoff receipt. Reserve space for both the archive and extracted data, plus the
new environment; allow additional room for future artifacts. Do not infer RAM
or GPU availability from the Codespace or Kaggle environment.

```bash
mkdir -p "$HOME/malpdf-transfer"
tar -xf "$HOME/Downloads/MalPDFDeepDetection-transfer-20261009T055256Z.tar" \
  -C "$HOME/malpdf-transfer" --no-same-owner
MALPDF_TRANSFER_DIR="$HOME/malpdf-transfer/MalPDFDeepDetection-transfer-20261009T055256Z"
cd "$MALPDF_TRANSFER_DIR"
sha256sum -c SHA256SUMS
```

Stop on any checksum failure. `data-file-checksums.jsonl` is private: it contains per-file
identities and must not be committed or uploaded.

## Restore code and existing evidence

Install Git and the system OpenMP runtime (`libgomp1`). Install Python 3.11
with `venv` support using a method appropriate to your Lubuntu release. The
Codespace baseline was checked on Python 3.11; do not claim an identical runtime
without comparing `validated_environment.json`. No Codespace virtual environment
is restored.

The original repository path reduces incompatibilities with older evidence
that records absolute Codespace paths. Use a fresh destination:

```bash
sudo mkdir -p /workspaces
sudo chown "$(id -un):$(id -gn)" /workspaces
git clone -b main "$MALPDF_TRANSFER_DIR/repository.bundle" /workspaces/MalPDFDeepDetection
cd /workspaces/MalPDFDeepDetection
git bundle verify "$MALPDF_TRANSFER_DIR/repository.bundle"
git remote set-url origin https://github.com/DrStone113/MalPDFDeepDetection
tar -xzf "$MALPDF_TRANSFER_DIR/malpdf-data-20261009T055256Z.tar.gz" \
  --strip-components=1 --no-same-owner -C /workspaces/MalPDFDeepDetection
git status --short --branch
```

Keep manifests, validation locks, completed runs, checkpoints and exclusive Test
markers together. Historical provenance remains unchanged. Snapshots under
`artifacts/code_checkouts/` contain source files; their machine-specific `.git`
control files are excluded. Recreate a Git worktree from its recorded branch or
commit if one is needed; do not treat those snapshots as active Git worktrees.
Experiments must still start from clean committed generating code.

The bundle retains the remote-tracking refs present at packaging time. After
changing the remote URL, `git fetch origin` refreshes them when network access
is available. Configure Git/Kaggle credentials afresh locally, never through
the transfer archive or Git history.

## Create and check a fresh CPU environment

The saved version constraints document the checked Python 3.11 Linux environment;
installation is still driven by `pyproject.toml`. The CPU index supplies matched
PyTorch/torchvision wheels. XGBoost's declared dependency can also install NCCL;
this does not mean PyTorch uses CUDA or that VMware provides a GPU.

```bash
cd /workspaces/MalPDFDeepDetection
python3.11 --version
python3.11 -m venv .venv
.venv/bin/python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu \
  -c "$MALPDF_TRANSFER_DIR/validated_versions.txt" -e '.[dev]'
.venv/bin/python -m pip check
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 \
  .venv/bin/python -m pytest tests/
git diff --check
git status --short --branch
```

These tests use synthetic or benign fixtures. They do not acquire data, train
research models or reevaluate locked research Test sets. Continue new work only
after the dependency check and tests pass. Use explicit `--data-root` arguments
where an entry point requires them; never edit immutable historical evidence
to replace old paths or generate a replacement Protocol G split.
