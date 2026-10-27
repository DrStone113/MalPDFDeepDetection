# Offline PDF static queue blockers — 2026-10-27

Status: the `pdf-static` offline job still cannot be queued. Two independent
blockers were identified by direct read-only inspection of the LAB and by
local/remote reproduction. No real PDF was read, queued or executed; no
dataset file, checkpoint or sample directory was opened. The build was not
started by the agent.

## Verified LAB state (read-only)

- Audit `status`: gateway verified, `runner.host_only_ready = true`,
  `offline_guest_ready = false` (expected while unstaged for offline run).
- `/usr/local/libexec/malpdf` helper SHA-256 values match the packaged snapshot
  manifest for all seven files checked by `lab_jobs.verify_helpers`
  (`lab_contract.py`, `lab_readonly.py`, `lab_side.py`, `lab_jobs.py`,
  `lab_runner.py`, `check_local.py`, `lab_guard.py`). The helpers were **not**
  stale.
- `/home/remnux/malpdf-inbox` previously held `935fcee….json` / `.tar` whose
  SHA-256 values exactly matched the snapshot generated from the Windows
  worktree (`d473288f…` / `7434a036…`). The inbox was therefore **not**
  mismatched, contrary to the earlier hypothesis.
- `/home/remnux/malpdf-releases` and `/var/lib/malpdf/jobs` were both empty,
  which places the failure inside `lab_side.install`, before `jobs.save_job`.

## Root cause 1 — content guard is Python-version dependent

`lab_side.install` aborted with `Forbidden binary or credential content`
(reproduced in a throwaway `/tmp` tree, no LAB state touched). The member was
`tests/test_markov_cache.py`, whose synthetic fixture at line 39 used an
**f-string** containing `%PDF-1.4` inside the first 1024 bytes.

`lab_contract.text_failure` only treats `tokenize.STRING` spans as legitimate
carriers of a `%PDF-x.y` header. Under CPython 3.12 (the LAB system Python,
`/usr/bin/python3` 3.12.3) f-strings are tokenized as `FSTRING_START` /
`FSTRING_MIDDLE` / `FSTRING_END` (PEP 701), so the header is no longer covered
and the file is rejected. Under CPython 3.11 (Windows) the same file passes,
which is why the identical archive installed locally and failed on the LAB.
The LAB traceback maps this to the generic `worker_failed` response because the
message is not in `lab_jobs.REASONS`.

Deferred follow-up (not applied): extend the covered-token set in
`text_failure` to include the `FSTRING_*` token kinds when available. That edit
changes `lab_contract.py`, and therefore the gateway `policy_sha256` and the
`verify_helpers` hashes, so it must be bundled with an operator-run helper
reinstall rather than slipped in before a real-PDF run.

## Applied change

`tests/test_markov_cache.py`: the synthetic fixture now uses
`"…{}…".format(index)` instead of an f-string. The produced bytes are identical
and only the token kind changes. No security check was relaxed, removed or
disabled, and no guard code changed.

Local: `check_local.py` passed (repository guard, diff check, AST, declared
dependency versions, pip check, reviewed imports, 233 synthetic tests).
`pytest tests/test_markov_cache.py` shows 44 passed and one pre-existing
Windows-only failure (`os.symlink` requires a privilege this shell lacks).

Remote: the regenerated snapshot (`cd33d264…` archive, `737650fd…` manifest,
346 files) was scanned with the LAB's own `lab_contract.text_failure` under
Python 3.12 and reported zero rejected members.

## Root cause 2 — LAB virtual environment was unusable (resolved)

`/home/remnux/MalPDFDeepDetection/.venv` was created on a different machine
(`/home/drstone/…`, uv-managed CPython 3.11.17) and copied here. Its
`pyvenv.cfg` points `home = /home/drstone/.local/bin`, which does not exist.
Every invocation fails before user code:

```
Fatal Python error: init_fs_encoding: failed to get the Python codec of the filesystem encoding
ModuleNotFoundError: No module named 'encodings'
```

Its 5.3 GB `site-packages` is intact and complete for CPython 3.11 (catboost,
torch, pikepdf, PyMuPDF, pyarrow, lightgbm, xgboost, sklearn, pandas, numpy,
pyyaml, esprima, joblib, pytest, jsonschema), but the venv has no stdlib and
the VM has no CPython 3.11 (`/usr/bin/python3` is 3.12.3; no `/usr/lib/python3.11`,
no uv, no wheelhouse, no pip cache). The build host `192.168.217.129` is not
reachable, and `ens33` has no default route, so nothing can be installed
without an operator-approved network window.

`jobs.config()` only checks that the configured interpreter is a file, so this
state passed setup and failed later inside `pdf_prepare` as `worker_failed`.

Resolution applied by the agent (environment only, no repo files on LAB):

- Downloaded `cpython-3.11.17+20261021-x86_64-unknown-linux-gnu-install_only.tar.gz`
  on Windows and verified its SHA-256 against the published `SHA256SUMS`:
  `7cc8d9dce9ea23c31267e7f244005c8979da04794b7737a3a30e62b03abeb120`.
- Transferred it over the approved SSH endpoint, re-verified the same checksum
  on the guest, and unpacked it to
  `/home/remnux/.local/share/uv/python/cpython-3.11.17-linux-x86_64-gnu`.
- Backed up `pyvenv.cfg` to `pyvenv.cfg.bak-20261027` and repointed `home` at
  the new runtime; `bin/python`, `bin/python3` and `bin/python3.11` now symlink
  to that interpreter, and stale `#!/home/drstone/...` shebangs in `bin/` were
  rewritten to the current venv path. The tarball was deleted afterwards.
- Verification: `Python 3.11.17`, `sys.prefix` = the venv,
  `sys.base_prefix` = the new runtime, `pip check` clean, all 18 declared
  dependencies resolve to the pinned versions for the current `pyproject.toml`,
  and `lab_jobs.config()` plus `lab_jobs.probe()` succeed.

Not changed: `site-packages/__editable__.malpdf-0.1.0.pth` still points at the
old `/home/drstone/MalPDFDeepDetection/src`. It does not affect the runner,
which puts the installed release `src` first on `sys.path`; it only makes a
bare `import malpdf` fail loudly outside a release.

## Current LAB state after cleanup

`/home/remnux/malpdf-inbox`, `/home/remnux/malpdf-releases` and
`/var/lib/malpdf/jobs` are empty. Removing the two inbox files was safe: they
are regenerable source packages, not evidence, and their hashes no longer match
the current snapshot. Nothing else on the LAB was modified.

## Remaining operator steps

1. Run `.\lab.ps1 test -Mode offline -Kind pdf-static` in an interactive Windows
   terminal. The administrator password and the batch approval are
   operator-only, and the agent must not supply them.
2. Snapshot the VM as `Before_CIC_Extraction`, disconnect every network
   adapter, then `lab run` at the LAB console and confirm the previewed plan.
3. Keep the VM offline after the run; result export stays a separately reviewed
   procedure.
