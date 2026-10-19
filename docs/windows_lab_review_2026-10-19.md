# Windows DEV and LAB workflow review: 2026-10-19

This is a local implementation and approval record, not a declaration that a new
LAB release has been deployed. The Windows checkout initially had no changes,
on `main` at `2ce87d7f513bb06d49c4473422511f705a1fb15b`, with origin
`https://github.com/DrStone113/MalPDFDeepDetection.git`.

## Confirmed findings and changes

The original `prepare` failure was reproduced after the indexed guard passed
2133 files. Both the Windows packager and LAB installer rejected a private-key
header substring embedded in the security detector's own source. A common
token-aware content contract now permits only inert header-only Python literals
and continues rejecting raw headers, paired/multiline key blocks, forged source
extensions, PDF/executable/archive signatures, late control bytes and invalid
UTF-8. The index/worktree guard retains the existing legacy artifact identities.

Package generation checks Git object sizes before reading blobs, batches Git
reads, creates deterministic SHA-256 manifests, and refuses differing existing
packages. LAB installation validates canonical TAR metadata, padding, members,
sizes and checksums into a new release. Reports gain run IDs, skipped counts and
restricted environment metadata; both readers reject unexpected content. Raw
SSH status and stderr are no longer displayed before validation.

The source-only check runner, public-key-only bootstrap generator, updated
pre-commit/CI checks, reviewed bounded synthetic LAB runner and SSHD installer
are implemented locally. The installer and Linux resource enforcement have not
been executed on LAB. The full operation, limits and rollback procedure are in
[the operating guide](windows_lab_workflow.md).

## Verification evidence

| Check | Evidence and limit |
| --- | --- |
| Windows source guard | PASS: all 2133 indexed files plus modified/untracked nonignored files |
| Security self-test | PASS: 24 generated-input test cases, zero failed/skipped; includes actual helper sources packaged through a disposable Git commit, LAB install simulation and AST report validation |
| AST source check | PASS: 286 approved Python files; no dataset discovery or project-code execution |
| Hook and shell syntax | PASS: actual hook invoked through Git for Windows Bash; `bash -n` for installer/hook |
| Workflow source | YAML/jobs validated locally; GitHub Actions execution and required branch checks NOT VERIFIED |
| Full Windows environment | New `.venv-windows-dev`, Python 3.11.16, all 18 runtime/dev requirement versions checked, pip consistency and reviewed imports passed; `.venv` retained |
| CUDA smoke | PASS: RTX 5060 Ti, driver 617.42, torch 2.11.0+cu128, torchvision 0.26.0+cu128, CUDA runtime 12.8, capability 12.0; generated tensor sum and CUDA NMS passed |
| Existing audit connection | PASS: validated status; nonallowlisted `id` and empty shell request refused with exit 2 |
| Existing server privileges | Forwarding/TTY/sudo/filesystem policy and full VMware isolation NOT VERIFIED by the restricted endpoint |
| Real committed source package | PASS: explicit existing SHA `2ce87d7f513bb06d49c4473422511f705a1fb15b`, 319 source files; excludes the current working changes |
| Windows receiver simulation | PASS: the real 319-file package installed into an owned temporary directory and all 284 committed Python files passed AST; this was not LAB execution |
| New implementation release | NOT VERIFIED: commit approval, bootstrap update, operator deployment and LAB execution pending |
| LAB reports returned | NOT RUN: new report retrieval/save requires the approval below |
| Real samples/dynamic execution | NOT RUN and not included in this approval batch |

The real existing-commit TAR has SHA-256
`3182aff626bce047aaf5dc7eb69cfc4ab7f1f1a74718d90ae4eb7e4e82ef696b`.
It resides with its JSON manifest under `%TEMP%/malpdf-lab-packages/` and is
historical source, not a release of these fixes. The new bootstrap requires a
commit containing `lab_contract.py`; the old commit does not satisfy that.

Timestamped local check and CUDA observations are preserved under
`artifacts/tmp/maintenance/lab_workflow/`. An earlier failed import attempt using
the system Python is retained; it was followed by the user-authorized creation
of the new environment. The old `.venv` still reports torch 2.7.1+cu128,
torchvision 0.22.1 and pypdf 5.9.0. No package versions there were changed.
The package downloads verify Windows Internet access during this task. The
LAB's route/Internet state remains NOT VERIFIED; no VM networking was changed.

The final full Level 1 record is
[`windows_20261019T151058262288Z.json`](../artifacts/tmp/maintenance/lab_workflow/windows_20261019T151058262288Z.json).
The separate
[CUDA observation](../artifacts/tmp/maintenance/lab_workflow/cuda_20261019T150850572465Z.json)
and [local receiver simulation](../artifacts/tmp/maintenance/lab_workflow/receiver_20261019T151151258979Z.json)
record their actual environment and do not assert LAB execution.

## Proposed approval batch

Review and authorize the current diff for exactly these 16 files:

```text
.gitattributes
.githooks/pre-commit
.github/workflows/repository-content-guard.yml
.gitignore
INSTALL.md
docs/README.md
docs/windows_lab_workflow.md
docs/windows_lab_review_2026-10-19.md
scripts/lab/check_local.py
scripts/lab/lab_contract.py
scripts/lab/lab_readonly.py
scripts/lab/lab_side.py
scripts/lab/labctl.py
scripts/lab/selftest.py
scripts/lab/setup_readonly.sh
scripts/security/check_repo_content.py
```

1. Commit only those reviewed workflow changes, with no push, then bind every
   following action to the resulting full Git SHA. Re-run local checks and
   prepare that clean commit plus its bootstrap manifest. No ignored environment,
   evidence output, archive, public/private key or research data is committed.
2. Approve the one-way upload of the exact four bootstrap source files,
   canonical public audit key and manifest to a fresh
   `/home/remnux/malpdf-bootstrap/<SHA>` directory. The operator compares the
   Windows/LAB SHA-256 values and runs the documented console installer. This
   changes only the listed audit account/group/helper/key/report-directory and
   SSHD drop-in settings, followed by validated SSH reload; no network or
   firewall change is authorized.
3. The operator deploys the exact source TAR/manifest using `labctl.py deploy`
   in a separate supervised session. This creates
   `/home/remnux/malpdf-releases/<SHA>` and requests only the documented AST
   check. Codex then rechecks audit status/refusal and may retrieve/save only
   its schema-1/2 sanitized report.
4. Separately include the documented non-root `lab_side.py synthetic <SHA>`
   command with its 90-second wall/60-second CPU/256-MiB/2-MiB-file/64-FD/
   64-process bounds. It executes only the reviewed security self-tests on
   generated fixtures and disposable Git repos. Approve retrieving/saving its
   sanitized counts report afterward. Retain the earlier AST observation first.
5. The operator verifies effective SSHD forwarding/TTY/password restrictions,
   sudo grants and filesystem permissions from the console. A live forwarding
   probe, if desired, needs an exact separately approved loopback-only command;
   no automatic forwarding exception is included here.

The deployment password/admin session remains outside Codex's control.
`AGENTS.md` explicitly makes deployment operator-only; approval of this batch
does not ask Codex to call deploy, script sudo or provide administrative input.
Codex continues the approved read-only checks, report analysis and Windows fixes
after the operator segment. Any newly changed source revision must be reviewed
before another release.

This batch excludes push, GitHub settings writes, LAB dependency installation,
project pytest, raw logs/paths/PDF transfers, real-PDF extraction, detonation,
firewall/adapter changes and changes to existing datasets/checkpoints. Those
remain outside the performed or proposed work.
