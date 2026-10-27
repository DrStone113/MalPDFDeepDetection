# LAB bootstrap transfer authentication, 2026-10-22

Status: **operator authentication and bootstrap transfer succeeded; Gateway
installation/verification remains NOT READY**.

## Verified cause and remaining diagnosis

The operator's transfer reached the password prompt for
`remnux@192.168.217.10` and returned `Permission denied (publickey,password)`.
This is authentication failure on the first SSH connection, before the SCP
command in this transfer flow. No source file copy or installation was reached
in this attempt. No existing remote directory state is inferred.

Local `ssh -G` with the exact administrative transfer arguments confirmed host
192.168.217.10, port 22, user remnux, password authentication enabled on the
client, public-key authentication disabled, preferred method password, and one
password attempt per connection. Strict host-key checking and disabled
forwarding/local commands remain effective. The transfer excludes user/system
SSH configuration through `-F none`; the old lubuntu alias is not selected.

A fresh bounded audit `status` request returned exit 0 with validated schema 3;
gateway remains unverified. The Windows route to the LAB endpoint selects
source IPv4 192.168.217.1. The operator screenshot confirms a console session
as remnux. The operator subsequently supplied the filtered console results:

- `passwd -S remnux`: `P`, last password change 2026-10-14. The password field
  is not locked; this does not verify the password typed over SSH or account/PAM
  eligibility.
- `sshd -T -C ...` for the observed connection tuple: `usepam yes`,
  `pubkeyauthentication yes`, `passwordauthentication yes`,
  `kbdinteractiveauthentication no`, `authenticationmethods any`.

The supplied effective configuration permits password authentication without
requiring a combined public-key/password flow. The remaining rejection cause
cannot be identified from those fields alone; password entry, account expiry,
other access restrictions and PAM still require evidence. No change to the
authentication methods or a new account is justified by this result.

The operator then supplied sanitized labels from at most 200 SSH journal
entries filtered for remnux: `Failed password` and `authentication failure`.
This confirms failed authentication in the selected records. It does not
uniquely identify an incorrect typed password or rule out other PAM conditions;
absence of other labels is not proof they cannot apply.

The console user remnux is distinct from root (UID 0). Sudo elevates an allowed
command. Existing Gateway design already separates operator, audit, runner and
worker; the installer creates/checks the latter two, while requiring audit as
a prerequisite. No additional root or arbitrary substitute operator account
is needed. Current account installation state is not inferred from the design.

## Files changed

- `scripts/lab/gateway_transfer.py`: separate directory-preparation and file-copy
  failures; retain the exit code; distinguish timeout and missing-client errors;
  explain whether SCP was attempted. Fixed hints replace the unconditional
  suggestion to open another terminal for SSH-stage errors. No stderr,
  passwords or arbitrary exception text are copied into diagnostic messages.
- `scripts/lab/selftest_gateway.py`: authentication denial cannot advance to
  SCP; fixed diagnostic messages redact error data; timeout/client failures
  preserve the phase; SCP failures remain distinct. No automatic retry/cleanup
  was added.
- `docs/lab_gateway.md`: authentication troubleshooting and two filtered,
  read-only operator console checks.
- This report.

## Deployment and bootstrap

The operator supplied a successful transfer transcript for all 14 files and
the final `COPIED:` receipt at
`/home/remnux/malpdf-gateway-bootstrap/52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316`.
Both password-authenticated connections in the operator flow completed. This
resolves the observed authentication/transfer blocker. No password value or
exact original credential/PAM rejection cause is inferred or retained.

The agent independently revalidated the local 14-file manifest, which matches
the copied identity. Remote payload hashes still require the operator's
installer preflight; the transcript is operator-provided transfer evidence.
A fresh agent audit `status` still reports gateway `installed=false`,
`verified=false`, null policy hash and `gateway_not_verified`. The transfer
command does not execute an installer, so successful copy is not installation
or native containment evidence.

No administrative SSH, password entry, transfer, installation, service action,
account change or real-PDF operation was performed by the agent. The audit and
runner keys were not repurposed. This Windows client fix does not alter any
pinned bootstrap helper or installer. Bootstrap manifest
`52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316`
remains applicable; no new package transfer is needed solely for this fix.

## Final validation

Windows Python 3.11.16, base commit
`935fcee48797606d718aeace47b5fd91c2b95ce3`, dirty worktree preserved.

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/labctl.py status
```

Final checks passed: **180 tests, 0 failures, 0 skipped**, 306 Python AST checks,
worktree content guard, diff check, all 18 declared dependency version/import
checks and pip consistency. Authentication/transfer failure cases use mocked
processes and inert generated fixtures; no real operator password is supplied.
Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261022T125835839894Z.json`.

## Remaining issue and minimum operator action

Authentication diagnosis and copy do not need repetition. At the REMnux
console, the operator must run the reviewed preflight and, only if it passes,
the one-time privileged installation:

```sh
cd /home/remnux/malpdf-gateway-bootstrap/52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316 &&
sudo sh setup_gateway.sh --check &&
sudo sh setup_gateway.sh --install --allow-synthetic
```

The conditional chain prevents setup from proceeding in the wrong directory
or after a failed preflight. This operator step is required by AGENTS.md
Section 4; the existing audit key is read-only and runner verification has not
passed. Installer backup/rollback remains documented in `docs/lab_gateway.md`.

After successful installation, the agent may autonomously verify the gateway,
run the approved bounded syntax/synthetic profiles and retrieve sanitized
reports. No remote installation, native containment pass, completed LAB job or
full automation readiness is claimed yet. Existing source releases, reports,
claims and data are preserved; no automatic transfer retry or cleanup occurs.
