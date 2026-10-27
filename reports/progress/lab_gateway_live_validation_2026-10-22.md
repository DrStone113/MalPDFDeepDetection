# Restricted gateway live validation — 2026-10-22

Current status: **READY for bounded syntax and pinned synthetic automation**.
The final bootstrap is installed, local and LAB policy hashes match, doctor
reports `ready/last_job_passed`, and both profiles passed again on that policy.
Real-PDF processing remains outside this verification and requires independent
VM isolation review and separate approval.

## Native installation and jobs observed

The operator installed bootstrap
`e1086730a9b88daa6b83391b546c9b2993ccb9589f34c26debba19b687d603e8`.
The root backup is `/var/tmp/malpdf-gateway-setup-h6yqumk1`; all prior backups
are preserved. The agent did not transfer this bootstrap or invoke sudo.

Read-only audit at `2026-10-22T14:01:45Z` confirmed root installation complete,
containment probe passed, all six configuration/proof checks passed and both
profiles approved under policy
`54cb230007fcba06309a2da81c658c381ddddaf83e8fb74079749e3036addc7c`.
The worker reported idle. Client `verify` returned success after matching the
audit and runner capability, local helper hashes, and testing rejection of
shell, empty command, real-PDF action, path traversal, SFTP and forwarding.

The agent then submitted bounded source-only jobs through the restricted key
under AGENTS.md Section 4 standing authorization. Only schema-validated audit
reports were retrieved. Both results passed:

| Profile | Result UTC | Job ID | AST | Pinned synthetic |
| --- | --- | --- | --- | --- |
| syntax | 2026-10-22T14:03:35Z | `c047da2b6e6f4b01bd94cdf8795ef05d82735866b38da8acf642158515d584d6` | 306 passed, 0 failed | Not requested |
| synthetic | 2026-10-22T14:10:01Z | `a66727bd553d90f5c2cf57d86543a0f5d6942389104d8f20632a4c4914e7ab42` | 306 passed, 0 failed | 6 passed, 0 failed |

Syntax manifest `e9457ee0ec89d980790abcfc0a669d30a2d8fc550c5e9eae3eb6b8c1f32a3efe`,
archive `99e1c07048c4883cee495a06b77050cae5c608ca864b6f4b8027db0983bd4b7f`.
Synthetic manifest `d97d685f2b7a0becb21b5212470014f427b49b065ba21232ab6cbf8b3806bd5c`,
archive `bf4ad040afb5d5a2aac9b54ad8dfbb1c3192a8c009207a6b592d2a707a1ded32`.
These are distinct validated working-tree snapshots based on
`935fcee48797606d718aeace47b5fd91c2b95ce3`, not clean-commit or pushed releases.
The synthetic snapshot includes the Windows test-isolation fix described below.
Each job retains the fixed 90s wall, 60s CPU, 512MiB memory, 32-task, 3000-file,
32MiB source and 16KiB report bounds. Claims/results/releases were preserved;
no failed or partially completed remote job was automatically resubmitted.

These results validate the approved syntax and six lexer cases only. They do
not establish real-PDF accuracy, malware containment against every exploit,
hypervisor isolation or detonation readiness. No real-PDF work was performed.

## Post-installation fixes on Windows

Doctor received valid configuration/probe/installation metadata but reported
`systemd_invalid` after the timer became active. Source inspection found that
`parse_units` required decimal microseconds for `LastTriggerUSecMonotonic`.
Systemd v255 formats properties containing `USec` with its timespan formatter,
so a triggered timer can produce values such as `2h 17min 4.123456s`.
The raw native property was not exported through the audit allowlist; this
diagnosis follows the exact public formatter and the observed state transition.
The corrected formatter was subsequently installed and its native doctor check
passed with an active/waiting timer and `timer_triggered=true`.

`scripts/lab/lab_diagnostics.py` now accepts capped, fixed-unit timespans for
this one property and exports only the existing boolean. It rejects unknown,
negative, unlimited, repeated/out-of-order, overflowing and sub-microsecond
values. Service start/exit timestamps remain strict uint64 values. Unit and
report schemas, output bounds, allowlists and containment policy remain closed.

Primary implementation references:
[systemd v255 bus property printer](https://github.com/systemd/systemd/blob/v255/src/shared/bus-print-properties.c),
[systemd v255 timespan formatter](https://github.com/systemd/systemd/blob/v255/src/basic/time-util.c).

The first two synthetic launch attempts stopped during local preflight, before
creating a synthetic job receipt or sending source. The failed Windows receipt
`windows_20261022T140407065812Z.json` identified the regression: after the first
gateway job, a workflow test selected the real cached gateway result and fetched
its sanitized syntax report via audit. It had isolated only the legacy cache.
It did not read samples or administrative logs and did not submit a job.

- `scripts/lab/selftest_workflow.py`: isolates both caches in disposable folders
  and rejects unmocked audit/runner transport in workflow unit tests.
- `scripts/lab/lab_windows.py`: explicit offline report mode cannot route to a
  cached connected gateway job.
- `scripts/lab/gateway_client.py`: a failed local check reports
  `local_checks_failed` and directs attention to the Windows receipt, rather
  than falsely suggesting bootstrap installation.
- `scripts/lab/selftest_gateway.py` and `selftest_diagnostics.py`: enforce these
  gates and cover the timer formats, privacy, invalid input and readiness path.
- `docs/lab_gateway.md`: documents the formats and offline/report behavior.

The corrected local preflight passed before the successful synthetic submission.
An initial new test assertion searched for the bare string `0` in serialized
metadata, colliding with legitimate numeric exit status zero. The assertion was
corrected to check for the quoted string value; the final complete check passed.
Before-copies are under ignored
`artifacts/tmp/maintenance/gateway_live_2026-10-22/before/`.

## Final local verification and next bootstrap

Windows Python 3.11.16, dirty base commit preserved. Full reviewed local check:

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
```

198 tests passed, 0 failed/skipped; 306 AST files; all 18 declared dependency
versions and reviewed imports; pip consistency; worktree content guard and diff
checks passed. Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261022T141209889470Z.json`.
This local receipt deliberately says LAB not run; the native evidence is the
separate job table above.

New bootstrap independently checked all 14 files and helper policy hashes:

- Manifest: `e74374f5d771d557e6b4563c69c43341fe258e554d9fd4ed24d9d41d1aa98110`.
- Policy: `1d6712297acb803a78b2730003998aa0a097ba3a116b64b52345498083a6e043`.
- Directory: `%TEMP%\malpdf-lab-packages\gateway-bootstrap\<manifest>`.

Only the pinned diagnostics helper changed in the bootstrap since the verified
installation; service, SSHD and containment settings are retained. The reviewed
Windows client/tests/docs changes remain in the Windows source checkout.

Because the audit formatter is root-owned and pinned, this update requires the
operator bootstrap workflow under AGENTS.md Section 4. It is not deployed through
the unprivileged job gateway. Windows transfer:

```powershell
.\lab.ps1 setup -Gateway -Transfer
```

REMnux console after successful copy:

```sh
cd /home/remnux/malpdf-gateway-bootstrap/e74374f5d771d557e6b4563c69c43341fe258e554d9fd4ed24d9d41d1aa98110 &&
sudo sh setup_gateway.sh --check &&
sudo sh setup_gateway.sh --install --allow-synthetic
```

The operator completed this handoff successfully. Installation passed at
`2026-10-22T14:39:40Z`; native containment probe passed at `14:39:37Z`. The new
operator backup is `/var/tmp/malpdf-gateway-setup-223tdy1i`. Earlier backups,
claims, releases and results were preserved.

## Final verification on the installed policy

Fresh Windows commands, using the existing restricted identities:

```powershell
.\lab.ps1 doctor -Refresh
.\lab.ps1 verify
.\lab.ps1 test -Mode syntax
.\lab.ps1 test -Mode synthetic
.\lab.ps1 report -Refresh
.\lab.ps1 status
```

Client verify returned exit 0 and the exact installed policy
`1d6712297acb803a78b2730003998aa0a097ba3a116b64b52345498083a6e043`.
Doctor at `2026-10-22T14:45:13Z` returned exit 0, status `ready`, reason
`last_job_passed`. All configuration, helper, policy, unit, SSHD and proof checks
passed; systemd metadata parsed successfully; timer enabled/active/waiting with
triggered=true; worker idle; no diagnostic record errors. The prior successful
jobs were retained and did not count as current-policy verification.

New jobs on the installed final policy:

| Profile | Result UTC | Job ID | AST | Pinned synthetic |
| --- | --- | --- | --- | --- |
| syntax | 2026-10-22T14:41:29Z | `c9a2d541f68bbfb377856e2a87dddb7a1c0ee7235e19656d5beddbd35f349e09` | 306 passed, 0 failed | Not requested |
| synthetic | 2026-10-22T14:43:39Z | `f49f0e4dbcd0ac108eac91e805b4077b74e720fe87cedcda77f358a89ed5a47e` | 306 passed, 0 failed | 6 passed, 0 failed |

Both use manifest
`e2a874e89c2147138fcb80531393e91b788bf136b6de7cabc9ab234f3bb5aded`
and archive `63114976322026b81c4adaf64bfc01528519a1fca54c9a090539d1a891d9c6e7`.
The client independently ran full local preflight before each submission. Both
receipts passed 198 tests, 0 failed/skipped, 306 AST files, all 18 declared
dependency/import checks, pip consistency, repository content and diff checks:

- `artifacts/tmp/maintenance/lab_workflow/windows_20261022T144022742501Z.json`
- `artifacts/tmp/maintenance/lab_workflow/windows_20261022T144237167719Z.json`

Native negative checks on the final installation also passed:

| Channel | Fixed check | Result |
| --- | --- | --- |
| Audit | status | Exit 0, schema 3 validated |
| Audit | `id -un`, empty command, `report ../escape` | Each exit 2, empty stdout |
| Runner | shell `id`, empty command | Each exit 2, empty stdout |
| Runner | real-PDF action, traversal argument | Each exit 2, empty stdout |
| Runner | SFTP | Exit 2, empty stdout |
| Runner | forwarding | Nonzero exit, empty stdout; verifier passed |
| Runner upload | forbidden `.pdf` filename with inert ASCII bytes | Exit 3, exact `source_rejected` response |
| Runner upload | TAR symlink entry | Exit 3, exact `source_rejected` response |
| Runner upload | TAR hardlink entry | Exit 3, exact `source_rejected` response |

The three rejected upload packets were constructed entirely in memory, each
under 12KiB, using fixed syntax actions. They contained no real PDF content or
untrusted corpus bytes. No PDF or TAR was written to Windows disk, no shell
command was requested, and no cleanup or retry was performed. Only fixed
rejection metadata was saved; no raw LAB text or payload bytes were exported.
The last completed job remained the successful final synthetic job after these
refusals. Local receipts:

- `artifacts/tmp/maintenance/gateway_live_2026-10-22/audit_checks_final.json`
- `artifacts/tmp/maintenance/gateway_live_2026-10-22/source_rejections_final.json`

`status.gateway.installed` and `verified` are true, both approved profiles are
present, and the policy matches Windows. `status.runner.installed=false` refers
to the separate legacy `/etc/malpdf/runner.json` marker; the restricted
`malpdf-runner` gateway identity has actually submitted and completed the jobs
above. Installing the administrative legacy runner to change this flag is not
required. `offline_guest_ready=false` is expected for a connected SSH workflow
and does not attest VMware isolation.

No further operator action is needed for these approved connected synthetic
profiles. Independent inspection of actual adapters/routes, VMware shares,
clipboard/drag-and-drop and host protections remains required before any
separately approved suspicious-PDF work. No real-PDF, detonation, raw export,
VM networking change, privileged agent action, commit or push was performed.
