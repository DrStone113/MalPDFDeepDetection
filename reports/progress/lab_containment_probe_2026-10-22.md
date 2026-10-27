# LAB containment probe repair — 2026-10-22

## Observed LAB failures

The operator transferred and installed bootstrap
`52364b0181d9a89eff9d8b152bb38b25a6bb765b0aa651b0469f8b61c43c9316`.
Preflight passed, but the native probe failed inside containment. The operator's
read-only check confirmed a `root` placeholder in the runtime root. The original
existence check incorrectly rejected a path made inaccessible by ProtectHome.
The first repair checks access without reading host data, validates finite soft
and hard RLIMITs, and bounds reads of individual cgroup limits.

The operator then installed bootstrap
`bc68f7f9da55f6724d1c58c02523dda25a932a56e5a1f4b995f6f33eacb720bb`.
Audit at `2026-10-22T13:52:25Z` and `13:56:12Z` confirmed:

- Configuration, helpers, policy, units and SSHD checks passed.
- Installed policy: `70fc024273a7cc1c8483812b3a8224ef28aac645a5e640d49cefe706164dea2b`.
- Installation failed at containment; probe unit result `signal`, main code `2`,
  main status `31`, started and finished. On the target x86-64 Linux this is
  SIGSYS, consistent with seccomp's default fatal rejection.
- The probe record still referred to the older policy and `13:33:35Z` run; it
  does not describe this installation attempt.
- Verification remained false, proof was invalidated, timer disabled/inactive,
  no worker execution and no submitted job.

The source contained a direct conflict: containment deliberately creates INET
and INET6 sockets and expects a denied-operation errno, while the unit denied
the entire `@network-io` group with the default fatal action. The sanitized
audit does not expose the triggering syscall number; socket creation is the
source-backed explanation consistent with the observed SIGSYS, rather than a
captured syscall trace.

Operator backups are preserved at `/var/tmp/malpdf-gateway-setup-orrk2ccw` and
`/var/tmp/malpdf-gateway-setup-21pjfmuy`. No cleanup or automatic rollback ran.

## Windows changes

- `scripts/lab/lab_gateway.py`: inaccessible host placeholders are accepted only
  on ENOENT/EACCES/EPERM; readable host paths fail without reading bytes. Both
  RLIMIT values must be finite and capped; cgroup values are independently
  bounded. Fixed containment reason codes preserve diagnostic privacy.
- `scripts/lab/setup_gateway.py`: both worker and probe deny network syscalls
  with `@network-io:EPERM`, permitting the trusted negative probe to inspect the
  rejection. The denied set is unchanged. Mount, privilege, debug, raw I/O,
  reboot and swap retain fatal rejection. No global errno override is added.
- `scripts/lab/lab_diagnostics.py`: reports failed signalled installation probes
  before an old probe record or deliberately revoked proof. Existing structured
  containment reasons and schemas remain validated.
- `scripts/lab/selftest_gateway.py` and `scripts/lab/selftest_diagnostics.py`:
  regressions for inaccessible/readable paths, strict limits, bounded cgroup
  reads, network rejection versus unrelated errors, both unit policies, and
  signalled probes with stale records.
- `docs/lab_gateway.md`: documents the checks and operator recovery workflow.

Systemd root, home protection, private networking, address-family restrictions,
resource limits, source mounts, forced commands, SSH authentication and
forwarding policy are retained. No administrative action was executed by the
agent. Windows before-copies are under the ignored maintenance directories
`containment_probe_2026-10-22/before` and `containment_signal_2026-10-22/before`.

The errno-per-group syntax and fatal default are documented in
[systemd.exec](https://www.freedesktop.org/software/systemd/man/256/systemd.exec.html#SystemCallFilter=).
The [systemd v255 group definitions](https://github.com/systemd/systemd/blob/v255/src/shared/seccomp-util.c)
include socket creation in `@network-io`.

## Local evidence

Windows Python 3.11.16; base commit
`935fcee48797606d718aeace47b5fd91c2b95ce3`, dirty worktree preserved.

Commands executed:

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/selftest.py
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
.\lab.ps1 setup -Gateway
.\lab.ps1 doctor -Refresh
git diff --check
```

Results: 193 synthetic security tests passed, 0 failed/skipped; 306 Python
files passed AST validation; all 18 declared dependency checks and reviewed
imports passed; pip consistency, repository content and diff checks passed.
Receipt: `artifacts/tmp/maintenance/lab_workflow/windows_20261022T135538915868Z.json`.
The previous placeholder repair passed 190 tests, with receipt
`windows_20261022T134438194043Z.json`; neither receipt proves native containment.

New bootstrap independently validated all 14 files and helper policy hashes:

- Manifest: `e1086730a9b88daa6b83391b546c9b2993ccb9589f34c26debba19b687d603e8`.
- Policy: `54cb230007fcba06309a2da81c658c381ddddaf83e8fb74079749e3036addc7c`.
- Local directory: `%TEMP%\malpdf-lab-packages\gateway-bootstrap\<manifest>`.
- Remote destination is a new manifest directory; existing destinations are
  refused. The package contains source, manifest and the runner public key;
  no private keys, PDFs or data artifacts.

An additional local verification snippet initially called `service` on the
gateway module rather than the installer module and failed with AttributeError.
It was corrected to use `setup_gateway.service`; independent package/hash
validation then passed. This was a local verification-script error, not a
bootstrap or LAB result.

## First operator handoff

AGENTS.md Section 4 reserves privileged gateway installation and administrative
transfer to the operator. Windows transfer command:

```powershell
.\lab.ps1 setup -Gateway -Transfer
```

Review the displayed manifest above and enter confirmation/password personally.
At the REMnux console after the copy completes:

```sh
cd /home/remnux/malpdf-gateway-bootstrap/e1086730a9b88daa6b83391b546c9b2993ccb9589f34c26debba19b687d603e8 &&
sudo sh setup_gateway.sh --check &&
sudo sh setup_gateway.sh --install --allow-synthetic
```

At the time of this handoff, native probe and client verification were pending.
The operator subsequently installed this bootstrap successfully. Installation
and probe records passed at `2026-10-22T14:01:30Z` and `14:01:28Z`; client verify
also passed. Native syntax and pinned synthetic jobs then passed. The operator
backup is `/var/tmp/malpdf-gateway-setup-h6yqumk1`.

See `lab_gateway_live_validation_2026-10-22.md` for job identities, exact results,
the post-installation doctor metadata issue and the next reviewed bootstrap.
Preserve all backups, reports, claims and releases; follow
`docs/lab_gateway.md` for operator rollback without erasing evidence. No real-PDF
work or VM isolation changes were performed or are claimed by these checks.
