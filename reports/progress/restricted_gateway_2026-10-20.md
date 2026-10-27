# Restricted LAB gateway: Windows implementation, 2026-10-20

The connected Windows `lab.ps1 test -Mode syntax|synthetic` path now uses a
separate forced-command gateway key, with no administrative password or implicit
fallback. The existing operator/offline workflow remains explicitly selectable.
This follows the user's updated standing authorization in AGENTS.md; that user
edit is preserved, unstaged and uncommitted.

The gateway accepts hashed source snapshots, so ordinary iteration need not
commit or stage user changes. Packaging reuses the canonical USTAR writer and
LAB installer/content contract; each snapshot occupies a new manifest-addressed
slot. Deterministic job IDs bind source, base commit, profile, policy and fixed
resource limits. Claims and results are preserved; connection loss cannot
silently resubmit a possibly executed job. Windows reads only bounded closed
JSON through the audit identity, whose role remains read-only.

The worker runs under a different UID from the SSH receiver, inside a minimal
systemd RootDirectory with source read-only and no user homes, corpus mounts,
credentials or host sockets. Private networking, syscall restrictions and
cgroup/RLIMIT bounds are part of the operator-reviewed unit. Each worker checks
actual kernel memory/swap/CPU/task limits, socket denial and filesystem access
before a job. The pinned synthetic harness performs six inert lexer cases and
never collects submitted tests or executes submitted package initializers.
This is a narrow lexer smoke profile, not the full extractor or ML evaluation.

The 13-file bootstrap uses a dedicated Windows-generated runner key; only its
public part is copied. Operator installation validates the exact manifest,
accounts, groups, sudo absence, effective SSHD settings, unit syntax and live
sandbox probes. Syntax is the default profile; `--allow-synthetic` approves the
bundled pinned harness once. Unsupported containment stays NOT READY.

Operator delivery is available through `.\lab.ps1 setup -Gateway -Transfer`
in a separate interactive Windows terminal. It displays the exact manifest and
fixed destination, requires human confirmation, then uses native OpenSSH
password authentication to create a new private directory and copy only the
13 verified files. It refuses existing targets, preserves partial copies, and
never executes the installer. The unattended test client does not call it.
Eight additional generated-input/mocked-transport checks cover noninteractive
refusal, changed/extra files, path injection, cancellation, revalidation after
confirmation, target/connection failure, exact delivery scope and partial-copy
failure without retry. All 97 local self-tests passed; no live transfer was run.
The full Windows check also passed 303 Python AST checks, the repository guard,
declared dependency/import checks and `pip check`. Evidence:
`artifacts/tmp/maintenance/lab_workflow/windows_20261020T143628079978Z.json`.

Operator-provided REMnux screenshots later identified a preflight failure:
`visudo -c` exited 1 because `/etc/sudoers.d/remnux` had an unexpected mode;
visudo required `0440`. The installer had not reached its installation phase.
The operator procedure documents correcting that exact file's mode and
rechecking sudo policy before retrying the existing bootstrap. The agent did
not change VM permissions or install anything remotely.

Installer diagnostics now report a bounded stage/reason and a fixed corrective
hint, including `preflight/sudo_policy_invalid`, instead of hiding all errors
behind one generic message. Captured command output, raw exception strings and
private paths are not printed. Three added local regression tests cover
preflight refusal for both actions, reason classification/redaction and
installation-stage failure. Full Windows validation passed 100 self-tests,
303 AST checks, content guard, dependency checks and pip consistency; evidence:
`artifacts/tmp/maintenance/lab_workflow/windows_20261020T145818432047Z.json`.

Windows verification covers closed job/status/report schemas, malformed
commands and PDF/path/shell rejection, immutable receipt reuse after clock
changes, claim deduplication, checksum rejection, unapproved profiles, missing
gateway without admin fallback, SSH loss, local cached reports, source-only
snapshots, pinned harness isolation from candidate tests/initializers, bootstrap
hashes, cgroup-bound rejection and installer refusal on Windows. Full-source
receiver simulations and the actual pinned lexer child use reviewed generated
inputs; Linux UID/namespace gates are mocked in Windows simulations. Final
counts/hashes and exact commands are recorded in the maintenance receipt.

Before the operator's first gateway installation, audit inspection and attempted
restricted syntax submission returned legacy schema1 / NOT READY setup_required.
No gateway job, administrative SSH,
remote write, sudo, package installation, real PDF, classifier/Test evaluation,
push or VM network change occurred. Root installation, Linux service behavior,
live runner key authentication and forwarding rejection remain unverified until
the operator installs the reviewed bootstrap and Codex's negative checks pass.

A subsequent operator-provided screenshot shows successful preflight followed
by installation/probe failure. Read-only audit now returns schema3,
`installed: true`, `verified: false`, `profiles: []` and
`reason: gateway_not_verified`; no autonomous job is permitted in that state.
The failing installation operation remains unknown until the operator supplies
the fixed probe service status. Do not rerun the write installer to obtain a
traceback or treat partial installation as an operational gateway.

Source diagnostics now distinguish SSHD validation/effective policy, systemd
unit validation, manager reload, containment/forced-command probes, SSH reload
and timer activation failures using fixed reason codes without raw stderr.
Windows verification passed 101 self-tests, 303 AST checks, repository guard,
declared dependencies/imports and pip consistency. Evidence:
`artifacts/tmp/maintenance/lab_workflow/windows_20261020T161740583218Z.json`.
The agent made no remote writes, service starts, administrator SSH calls or
VM isolation changes during this diagnosis.

The user guide is [docs/lab_gateway.md](../../docs/lab_gateway.md). The design
uses the primary [systemd execution documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html),
[systemd resource controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html),
[kernel cgroup v2 interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)
and [OpenSSH forced-command/forwarding controls](https://man.openbsd.org/sshd_config.5).
These settings and reports are not remote attestation or a guarantee against
kernel/SSH/parser vulnerabilities. Installation is not an atomic OS rollback;
preserve the root-only backups and all source/job evidence for operator recovery.
