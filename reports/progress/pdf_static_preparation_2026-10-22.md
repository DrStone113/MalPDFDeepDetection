# Offline PDF static preparation — 2026-10-22

Status: offline runner installed by the operator; independently confirmed by
the audit endpoint. Source/installer preparation and synthetic checks passed.
No real PDF has been read, queued or executed by the agent. The user selected
a different LAB dataset, so the earlier CIC64 proposal is not selected for use.
Its exact input manifest, LAB dependencies, isolation and specific run approval
remain pending.

## Scope and independent host observations

The user requested preparation of the real-PDF workflow after the restricted
gateway became ready. The initial proposal used the existing repository
configuration: CIC 32 Train + 32 Validation, seed42, no Test. The user subsequently
selected another existing REMnux dataset and supplied the parent directory
`/home/remnux/MalPDFDeepDetection/data`, explicitly stating that it contains
malicious PDFs and that SSH and VMware copy/paste have not been disabled.
This does not identify a bounded cohort or approve processing the whole tree.
The initial proposal remains immutable, unapproved and unused. The installed
`pdf-static` profile is fixed to CIC64 and must not be presented as supporting
arbitrary sample folders. The next metadata-only operator step identifies the
specific subdirectory; the intended first run is at most five files, pending
the exact manifest and run review.
No Windows data directory, corpus PDF or LAB sample directory was browsed.

Read-only Windows checks identified the intended running REMnux VM at
`C:\VirtualMachine\Remnux.vmx`, VMware Tools running, expected address
`192.168.217.10`, one configured Host-only adapter and zero snapshots.
VMX SHA-256:
`c7517caf4a97b9880a99dc86c57205d38b2c9a75f157560a03d128715ebd0c37`.
Drag-and-drop is explicitly disabled. Copy/paste and shared folders do not have
explicit disabling metadata accepted by the checker and remain unverified.
Missing flags are not represented as proof that the features are enabled.
VMX/startup settings do not establish current NIC disconnection or guest controls.

Windows firewall profiles were enabled and VMnet1 forwarding was disabled in
the read-only PowerShell query. Default firewall actions were inherited/unspecified
in that output; it does not attest complete effective firewall containment.
No VM power, snapshot, NIC, route, firewall, sharing or clipboard setting changed.
The host isolation checker always leaves real-PDF readiness false until the
separate guest/operator gates are satisfied.

## Source changes and preservation

- `scripts/lab/setup_runner.py` and the thin `setup_runner.sh`: operator-only
  offline setup. Checks exact bootstrap hashes, existing root-owned verified
  gateway, compatible pinned helpers, existing audit public key, normal analysis
  UID and fixed destinations. Requires existing private job state to have the
  expected UID/GID and 0700 permissions. Rejects links, nonregular/root-writable
  helper files and unknown existing state. Uses bounded no-follow FD reads and
  FD-based ownership/permission operations for new state directories.
- Installation writes only the non-pinned check_local helper, runner config,
  CLI/menu and required private directories, backing up old files. Six shared
  gateway helpers are compared and retained. No key/account/SSHD/systemd
  reconfiguration or SSH reload occurs; gateway config/proof is rechecked.
- `scripts/lab/offline_prepare.py`: local bootstrap and deterministic offline
  proposal using existing source/package/job contracts. Includes no PDF/data
  transfer or execution and no implicit export permission.
- `scripts/lab/gateway_snapshot.py`, `lab_windows.py`: optional LF-normalized
  snapshot for offline preparation; real operator confirmation/password gates
  remain. Source is rechecked after confirmation. Unrelated dirty work is not
  staged or committed. Existing offline releases are never overwritten.
- `scripts/lab/gateway_transfer.py`, `lab.ps1`: explicit
  `setup -Mode offline -Transfer` copies only the verified installer to a new
  fixed manifest directory with real TTY/confirmation/password gates. It does
  not install, queue or run a job and cannot silently substitute for gateway use.
- `scripts/lab/lab_vmware.py`: bounded VMX and fixed list/listSnapshots
  observations with enum/boolean/hash/count output. Snapshot names, share paths,
  raw VMX and guest commands are not returned or executed.
- `scripts/lab/labctl.py`, `selftest.py`, `selftest_workflow.py`,
  new `selftest_offline.py` and `docs/lab_runner.md`: bootstrap manifest,
  synthetic regressions and operating instructions.

No pinned gateway helper changed. The installed/local gateway policy remains
`1d6712297acb803a78b2730003998aa0a097ba3a116b64b52345498083a6e043`.
Before-copies are under
`artifacts/tmp/maintenance/pdf_static_preparation_2026-10-22/before/`.
Existing dirty files, prior reports/claims/releases and backups are preserved.

## Reviewable package and proposal

Bootstrap: `59a749001535111a023b0c6a4642741b5de474fd588cdff9c5c473c807c31797`.
All 12 files independently validated; shared helper hashes match the gateway.
It contains source and the existing public audit key, with no PDF, dataset,
private key or source archive. Local directory:
`%TEMP%\malpdf-lab-packages\offline-bootstrap\<bootstrap-id>`.

Offline proposal:
`33bbe5a028e692a1c0a7428ea8788dcfd9b83b5cc3bde7c6d697b6caf6d0ff2c`.
346 allowlisted source files; LF-normalized source manifest
`048db19ab7930555cde7fc6dff438177d16a26c0d9010ca425b2357641d93bba`;
archive `94ecf50daeba33390761d65482b483afbf8dd90f1d22ac87a22abe2c853df3e4`.
Origin is the dirty Windows worktree based on
`935fcee48797606d718aeace47b5fd91c2b95ce3`, not a new clean Git commit.

The proposal records the three existing manifest paths and exact hashes from
`configs/cic_static_benchmark.yaml`, one worker, 64 samples, 10MiB/file,
20s wall/12s CPU/1GiB per parser, 30min maximum batch, 512MiB output cap and
8MiB/private bundle. LAB output stays in `/var/lib/malpdf/jobs/<job-id>/`.
Actual presence, checksums, rows, Python dependencies and Arlington assets on
REMnux remain unverified until operator metadata preparation. No dataset is
downloaded or substituted to bypass a mismatch.

The proposal has `real_pdf_approved=false`, `export_approved=false` and
`lab_execution=not_run`. A copy and the public bootstrap manifest are saved
under `artifacts/tmp/maintenance/pdf_static_preparation_2026-10-22/`.

## Verification actually performed

Windows Python3.11.16, 223 synthetic tests passed, 0 failed/skipped; 309 AST
files; all18 declared dependency versions/imports, pip consistency, worktree
content and diff checks passed. Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261022T163630962972Z.json`.
Installer privilege/filesystem tests use disposable directories and mocked
Linux ownership calls; they do not claim a native root install.

The existing verified gateway was then used for syntax plus its pinned lexer
synthetic profile only:

- Job: `42bdc617ac3902f418b5b6bb09fcab19023f6af0a419989c8c18cb1c8c87a789`.
- Result at `2026-10-22T16:38:50Z`: passed, AST309/309 and synthetic6/6.
- Gateway source manifest:
  `cd45ce8e78ddca1a354a8b6ba490367e8d0f972c96a00cbdf7116ca3b1e3d656`.
- Archive: `909b629fded4e5c4c40ea8a4ee36d1ad5128d674339814b151e40fa46120ce52`.

This is a separate raw-newline working-tree snapshot from the normalized offline
proposal. It does not install the offline runner or run any submitted installer,
read actual PDFs, import their feature bundles or validate malware accuracy.
Doctor at `2026-10-22T16:37:49Z` remained ready on the unchanged policy.

## Native installation and independent refresh

The operator successfully ran both installer commands from bootstrap
`59a749001535111a023b0c6a4642741b5de474fd588cdff9c5c473c807c31797`.
Reported backup: `/var/tmp/malpdf-runner-setup.ycloru8a`. The console reported
installation success with gateway helpers, accounts, keys and SSHD preserved.

Independent `lab.ps1 status` subsequently returned `runner.installed=true`,
`host_only_ready=true`, `offline_guest_ready=false`, and verified gateway policy
`1d6712297acb803a78b2730003998aa0a097ba3a116b64b52345498083a6e043`.
`lab.ps1 doctor -Refresh` at `2026-10-22T16:57:40Z` returned ready with all six
configuration checks passed, the timer active and the worker idle. This confirms
the installed runner marker and unchanged gateway readiness, not PDF readiness.

A fresh fixed VMware metadata check still reported one configured Host-only
adapter, zero snapshots, drag-and-drop disabled, copy/paste and shared folders
unverified, and no evidence of runtime NIC disconnection. VMX hash is unchanged.
No settings were modified. Native data/manifest/dependency preparation and PDF
execution have not occurred.

## Completed operator installation procedure

AGENTS.md Section4 reserves sudo/system configuration and administrative
transfer for the operator. All locally authorized preparation is complete.
Keep Host-only connected for this installer/metadata phase; no PDF processing
is authorized by copying or installing the bootstrap.

Windows PowerShell:

```powershell
.\lab.ps1 setup -Mode offline -Transfer
```

The printed manifest must match the bootstrap ID above. After copy, REMnux
console:

```sh
cd /home/remnux/malpdf-offline-bootstrap/59a749001535111a023b0c6a4642741b5de474fd588cdff9c5c473c807c31797 &&
sudo sh setup_runner.sh --check &&
sudo sh setup_runner.sh --install
```

Preserve the backup path printed by the installer. A missing data root,
unverified gateway, helper mismatch or unexpected existing state blocks setup;
do not create a fake marker or loosen permissions to get past it.

After this native check, the specific PDF cohort must be agreed. For a different
dataset, the fixed CIC64 preparation command is not applicable; first define and
review a bounded manifest and the corresponding static-only processing path.
The operator metadata-only source/queue command can then check actual LAB
dependencies/manifests.
If the same base commit already has a different offline release, stop for a
separately reviewed source version; never overwrite/delete old releases.

Before any PDF is read, the operator must verify a recovery snapshot, disable
copy/paste/drag/drop/shared folders, disconnect all guest NICs, and verify the
actual guest routes, mounts, credentials and execution limits at console.
The fixed `pdf-static` command and run/output plan need specific approval.
No renderer, embedded action, JS runtime or detonation is included.

Recovery: keep the VM offline after failures or completion; preserve job/claim/
private result evidence and root backups. Restore only reviewed prior files;
new files or snapshot rollback require separate operator review without erasing
results. Do not reconnect or export real-sample results automatically.
