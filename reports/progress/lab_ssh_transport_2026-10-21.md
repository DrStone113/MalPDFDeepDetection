# LAB SSH transport review, 2026-10-21

The operator transfer of bootstrap
`25302b72bad42984e97a8a0a3efe683f8c07424ccadaea005a6286e30457cfce`
reported `banner exchange: Connection to UNKNOWN port -1: Connection refused`
before confirming the remote directory or file copy. No transfer success or
remote filesystem state is inferred from that failure. The agent did not run
an administrative transfer, supply confirmation/password, or retry that copy.

Read-only checks from Windows found:

- The effective installer and audit SSH profiles use host 192.168.217.10 and
  port 22, with strict host-key checking and no configured proxy/jump host.
  The approved client is OpenSSH_for_Windows_9.5p2. `ssh -G` only prints
  effective configuration; `-F none` excludes user/system configuration.
- VMnet1 is Up on Windows. This does not prove the guest IP, routing,
  isolation or SSH listener state.
- One bounded TCP connection check to 192.168.217.10:22 returned Windows
  error 10061, ConnectionRefusedError. An audit-only `status` request exited
  255 without a remote protocol banner, host-key failure or authentication
  denial. No proxy command was executed. Only fixed transport flags and
  output sizes were retained; raw SSH debug text was discarded.
- The original facade misclassified unavailable audit transport as
  `worker_failed`, although the status command submitted no job. After the
  Windows fix, an actual `lab.ps1 status` returned `blocked / ssh_unavailable`
  with exit 2. This verifies error reporting, not LAB readiness.

The client now normalizes failed/timeout/limited audit requests to
`ssh_unavailable`. Malformed successful replies become
`audit_response_invalid`. It preserves the existing validated success schema,
does not print remote response text, and performs no automatic retry or
administrative fallback. Four added mocked regressions cover failed transport,
timeouts/errors, invalid JSON/schema and valid legacy status.

Commands used for local validation:

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
.\lab.ps1 status
git diff --check
```

The full Windows check passed 136 tests (0 failed/skipped), 305 AST checks,
repository worktree content validation, all 18 declared dependency/import
checks and pip consistency. Python: 3.11.16; base commit:
935fcee48797606d718aeace47b5fd91c2b95ce3, dirty worktree.
Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261021T152422586837Z.json`.

The two requested console observations are `ip -br -4 addr` and
`ss -lnt 'sport = :22'`, both read-only. They remain pending and are needed
to distinguish guest address/listener conditions. No service, SSHD, account,
sudo policy, firewall, adapter, route, VM isolation, dataset or real PDF was
changed or processed. The existing bootstrap remains usable after the
operator resolves the approved connection; no new installer payload is
needed for this Windows-only reporting fix.

Reference: [OpenSSH options -F and -G](https://man.openbsd.org/ssh#F).
