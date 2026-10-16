# Offline extractor handoff

## Console launcher

Current job: `run_20261016T130402057603Z_19de287ea30a`. The installed entry is
`/home/drstone/Desktop/Extract PDF Offline.desktop`; the new package is recorded
in [handoff summary](../reports/deployment/pdf_extraction_offline/run_20261016T130519507883Z_19de287ea30a/handoff_summary.json).
See [launcher verification](../reports/progress/extract_pdf_launcher_2026-10-16.md).

The interactive launcher is `scripts/launch_pdf_extraction.sh`, using the repo's
`.venv/bin/python -I` and `scripts/24_launch_pdf_extraction.py`. A generated
`Extract PDF Offline.desktop` opens it in a terminal with an **explicit sealed
job ID**. It does not discover a newest job, prepare/retry a job, install packages,
disconnect NICs, clear environment credentials or delete claims. The shell source
is included in the job fingerprint alongside Python/config source.

The entry uses the standard
[Exec and Terminal keys](https://specifications.freedesktop.org/desktop-entry/latest/recognized-keys.html)
and is checked with `desktop-file-validate`. Actual GUI double-click behavior has
not been exercised in this connected session; shell/CLI transport is tested.

```bash
sh scripts/launch_pdf_extraction.sh --prepared-run <prepared_run> --check-only
sh scripts/launch_pdf_extraction.sh --prepared-run <prepared_run>
```

`--check-only` reads metadata and presence/admission state, never prompts or
accesses PDFs, and returns2 when blocked (for example SSH/network/credentials or
dirty code). It writes no official invocation/report/claim, so an unsuccessful
precheck does not dirty the clean source needed by the real run. A bad job/model
or unreadable state returns1. Ready precheck returns0; it is **not** attestation.

Default launch requires an interactive terminal, all software checks passing,
then the exact phrase `CHAY TINH`. The operator must first verify VMware
NIC/sharing/clipboard/drag-drop controls, snapshot and the remaining credential
audit. Anything else cancels without running. The established runner rechecks
all gates after confirmation and preserves its one-attempt claim. Interruptions
keep evidence; there is no automatic restart. Only aggregate run status/paths are
printed; private exception text and sample identities are not echoed.

Credential presence now also blocks home/repo `.codex/auth.json`, including
broken symlinks, in both the launcher and direct runner. This checks names/presence
only. Closing an app or unsetting a variable is not a credential audit; use the
approved credential-free LAB. No credential is read, removed or moved by launcher.

The original package below predates this launcher. Preserve it as historical
evidence; source changes require a newly sealed job/package with the same split.

## Original metadata-only package

The offline handoff is a private metadata/runbook package for the existing
Lubuntu LAB repository, `.venv` and locked Arlington checkout. It includes the
prepared job, config/manifest checksums, effective environment, preparation
summary, preflight state and a Vietnamese console runbook. It contains no PDF,
source-tree copy, wheels, checkpoint/model weights or automatic launcher.
It is not a standalone installer.

The user-approved210-file source snapshot was committed as
`aa27c0a28dcb6482179afed6da5c76ad727a2a6d`. The sealed job passed metadata-only
verification and the clean-code gate after that commit. See the
[source-commit receipt](../reports/progress/extract_pdf_source_commit_2026-10-16.md)
for checks and the separate Git checkpoint integrity findings. The archive's
saved dirty preflight describes its preparation time; always check current Git
state again at the console. Receipt/docs/log commits do not change the sealed
source/config fingerprint. No real PDF has been run for this extractor.

The original handoff is recorded in
[`handoff_summary.json`](../reports/deployment/pdf_extraction_offline/run_20261016T104455061938Z_7d02abdb85da/handoff_summary.json).
The private archive and unpacked `RUNBOOK.vi.md` are under
`artifacts/tmp/maintenance/extract_pdf/offline_handoff/` at the recorded run ID.
Keep this package private: its job lock contains authorized sample paths/hashes.
Do not upload it to a third party or commit it to Git.

While connected, use the existing `scripts/22_extract_pdf.py check` command with
the run ID in the package. This reads saved metadata/source/config/reference
files only. It does not read/stat/hash PDF paths. Check dependencies and exact
model checksums before going offline; no dependency download is attempted there.

Two gates remain separate from package preparation:

- Review and commit the approved work so `git status --porcelain` is empty.
  [AGENTS.md](../AGENTS.md) requires: “Official experiments start from a clean
  committed worktree.” The runner enforces this with `clean_code`; do not hide
  dirty state, stage unsafe artifacts or discard unrelated local changes.
- From VMware console, confirm disconnected host/Internet NICs, disabled shared
  folders/clipboard/drag-and-drop, a normal analysis account, no SSH/agent
  forwarding and no credentials. Presence checks inspect names only; the operator
  must complete the remaining credential and hypervisor audit.

Do not disconnect the active SSH NIC remotely. The package performs no isolation
changes and does not run a PDF automatically. Once both gates and `check` pass,
the operator may invoke `run --prepared-run <id> --lab-isolated` from the approved
console. The attestation flag does not establish isolation by itself.

This job performs static byte/hash/parse/limited-filter/AST inspection only on the
locked32 Train and32 previously exposed Validation records. Test is not selected.
It does not render, emulate/execute JavaScript, open Reader or invoke CAPE.
One persistent claim prevents automatic retries; failure/partial evidence remains.
Actual output paths and recovery instructions are in the packaged runbook.

If code/config/dependencies change, the old job refuses drift. Prepare a new job
with the unchanged split, preserve earlier evidence and refresh the handoff;
preparation reports/logs must also be reviewed before the next clean run.
Preparation, a valid archive or green synthetic tests do not prove real-PDF
acceptance. See [extraction workflow](pdf_extraction.md) and
[the current maintenance report](../reports/progress/extract_pdf_triggers_2026-10-16.md).
