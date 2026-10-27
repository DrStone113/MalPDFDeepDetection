# REMnux LAB automation takeover, 2026-10-22

This report preserves the initial takeover baseline, before operator bootstrap.
Its NOT READY observations and test counts below are historical evidence.
Current restricted syntax/synthetic automation is verified ready; see
[final live validation](lab_gateway_live_validation_2026-10-22.md) for the
installed policy, native jobs and remaining real-PDF isolation requirements.
No administrative SSH, sudo, bootstrap transfer, network changes or real-PDF
processing were performed by the agent.

## Verified findings and limits of diagnosis

- Audit status returned schema 3 successfully. Both audit and runner probe
  report gateway `installed=false`, `verified=false`, `profiles=[]`,
  `policy_sha256=null`, `reason=gateway_not_verified`. Runner probe returned
  exit 3. These are live observations, not cached historical status.
- `diagnose gateway` returned exit 2 with no payload. The installed audit
  endpoint does not expose the current diagnostic interface. The updated local
  doctor reports `diagnostics_upgrade_required`, includes separately validated
  `audit_status`, and retains a timestamped receipt. The last observed doctor
  timestamp was `2026-10-22T12:44:52Z` (19:44:52 Asia/Saigon).
- In the reviewed Windows implementation, `gateway.installed` becomes true
  only after config schema, helper policy hashes, unit hashes and SSHD hash all
  pass. Presence of `lab_gateway.py` alone cannot establish installation. The
  live generic response does not distinguish a missing config from unreadable
  metadata, unsafe ownership, changed helpers, unit mismatch or SSHD mismatch.
  The installed helper version/hash and exact failing remote component remain
  **unverified**. No individual missing file or dependency is asserted.
- `runner.installed` is a separate legacy marker: existence of
  `/etc/malpdf/runner.json`. The restricted gateway has separate runner/worker
  identities and does not create this marker. Installing the legacy
  administrative workflow merely to change this flag would be incorrect.
- `offline_guest_ready` requires no SSH session, connected/unknown interfaces
  or shared mounts. A connected Host-only SSH session fails that check by
  design. This field is not independent VMware/clipboard/firewall attestation.

## Windows changes

Files edited during this takeover, relative to the starting dirty worktree:

- `scripts/lab/lab_gateway.py`: shared staged config verification; strict
  schema/hash/proof types; regular root-owned files without group/other writes,
  symlinks or hardlinks. Claimed jobs survive policy upgrades; unclaimed jobs
  with superseded policy/profile fail once without executing source and no
  longer block subsequent current-policy jobs.
- `scripts/lab/lab_diagnostics.py`: closed API 2 configuration checks for
  configuration/helpers/policy/units/sshd/proof, using fixed state enums.
  API 1 remains readable. Partial checks cannot produce a ready result.
- `scripts/lab/gateway_client.py`: working direct CLI entrypoint; read-only
  legacy diagnostic fallback; rejection of ready status when the local policy
  hash differs or is unavailable; local snapshot preparation using the existing
  snapshot/content guard.
- `scripts/lab/setup_gateway.py`: invalidates prior verification before
  configuration changes; records early configuration failures; preserves the
  original exception if diagnostic writes fail; rejects indeterminate worker
  process checks. Installer flow remains operator-only with existing backups,
  containment probes and final SSHD validation/rollback.
- `scripts/lab/lab_windows.py`: routes `prepare -Gateway` to the existing
  validated snapshot implementation without SSH or commits.
- `scripts/lab/selftest_gateway.py` and `scripts/lab/selftest_diagnostics.py`:
  regression cases for the changes, including repeated installation with
  preserved evidence and rejection after failed configuration/probe.
- `docs/lab_gateway.md` and `docs/lab_runner.md`: status interpretation,
  diagnostic contracts, preparation, installation and operator rollback.
- This report.

Existing AGENTS.md and unrelated worktree changes were preserved. No files were
staged, committed or pushed. Before snapshots of the edited implementation are
under `artifacts/tmp/maintenance/lab_automation_takeover_2026-10-22/before/`.

## Final verification

Windows Python 3.11.16; base commit
`935fcee48797606d718aeace47b5fd91c2b95ce3`; dirty worktree.

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
.\.venv-windows-dev\Scripts\python.exe -B scripts/security/check_repo_content.py
git diff --cached --name-only
git diff --check
.\lab.ps1 doctor
.\lab.ps1 setup -Gateway
.\lab.ps1 prepare -Gateway
```

Local checks: **177 passed, 0 failed, 0 skipped**; 306 Python AST checks;
worktree content guard; diff check; all 18 declared dependency version/import
checks and pip consistency passed. The separate index guard passed for 2,153
tracked files. The staged-file list was empty.

The local full-check receipt is
`artifacts/tmp/maintenance/lab_workflow/windows_20261022T124413555661Z.json`.
Installer/systemd/ownership tests use disposable Windows directories and mocked
Linux processes/metadata. They do not establish native Linux installation or
VM isolation. No broad corpus-dependent pytest suite was run.

Bounded live checks used `labctl.audit_request`/`bounded_ssh` with the fixed
audit identity and `gateway_client.exchange` with the fixed runner identity:

| Channel | Request | Observed result |
| --- | --- | --- |
| Audit | `status` | Exit 0, validated schema 3 |
| Audit | `id`, `id -un`, empty request | Exit 2, no payload |
| Audit | SFTP subsystem | Exit 2, no payload |
| Audit | `report ../escape`, `report-job <64-hex>;id` | Exit 2, no payload |
| Audit | `diagnose gateway` | Exit 2, no payload; upgrade required |
| Runner | `probe` | Exit 3, validated NOT READY capability |
| Runner | `id`, empty request, SFTP | Exit 2, no payload |
| Runner | `submit-pdf <64-hex>`, `submit-syntax ../escape` | Exit 2, no payload |
| Audit and runner | Stdio forwarding to LAB `127.0.0.1:22` | Exit 255, no payload; no connection established |

Forwarding exit 255 alone does not attest the effective server configuration;
the post-install verifier and operator checks remain required. No valid submit
command or job payload was sent. Syntax/synthetic LAB jobs remain pending.

## Prepared source and installer

Local bootstrap: 14 files including manifest and separate public runner key;
all exact files/hashes were revalidated by `gateway_transfer.verified_files`.
No private key is in the package. The manifest's helper pins match the local
expected policy. Calling setup again produced the same manifest identity.

- Manifest ID:
  `52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316`
- Expected helper policy:
  `e194383b638150ee1f693e6d557f65ec9813709afbfc0f6cae3d89bee65c33f3`
- Bootstrap directory:
  `%TEMP%\malpdf-lab-packages\gateway-bootstrap\52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316`

The separate local source snapshot contains 343 allowlisted source/config
files. It is not committed source and has not been uploaded:

- Snapshot ID: `5345037ae1ea6fe69b4691c08de8046a4264e6f59863b0b6916a08a9073b161a`
- Archive SHA-256: `7425fb67ca4a60b37212da4bc1c3883b565f4464113bb4f49ed7963ce9a0cf47`
- Manifest SHA-256: `b6009438c57d34a5b3ae97e21a291e4f2d94c1e3d3d2f84d5c6c3f544355890b`
- Location: `%TEMP%\malpdf-lab-packages\snapshots\<snapshot-id>\`

The bootstrap manifest is a content hash, not a digital signature. Installation
trust still requires operator review, a distinct constrained key, root-owned
helpers/configuration and the actual Linux negative/containment probes.

## Minimal operator action and remaining verification

The installed interfaces provide no approved privileged installer command.
AGENTS.md Section 4 reserves gateway installation, SSHD/systemd changes and sudo
for the operator. The read-only audit key and unverified runner cannot perform
that setup, and are not used as deployment workarounds.

In a separate Windows PowerShell at the repository, run:

```powershell
.\lab.ps1 setup -Gateway -Transfer
```

Review/approve the displayed manifest and enter any SSH password personally.
The transfer uses the existing strict-host-key operator gate, refuses an
existing destination and does not run the installer. At the REMnux console,
open the transferred manifest directory under
`/home/remnux/malpdf-gateway-bootstrap/` and run:

```sh
sudo sh setup_gateway.sh --check
sudo sh setup_gateway.sh --install --allow-synthetic
```

The installer prints its root-only backup path. Follow
`docs/lab_gateway.md` for rollback; preserve all prior evidence and keep
verification invalid until the real checks pass. No other manual information
collection is requested while the audit interface can provide it.

After successful installation, Codex can autonomously run `verify`, `doctor`,
syntax, pinned synthetic and sanitized report retrieval. Until then, the exact
remote config failure, native ownership/limits, active timer and successful LAB
execution remain pending. Independent VM isolation review and a separate
real-PDF approval remain necessary before any suspicious-PDF work.
