# LAB Gateway SSH configuration fix, 2026-10-22

Scope: Windows source changes and offline synthetic verification only. The
current request explicitly excludes privileged REMnux changes. No SSH,
VMware guest operations, transfer, remote installation, service operation or
real PDF processing was performed during this task. Earlier administrative
setup authorization is not used for this request.

## Cause and generated configuration

`scripts/lab/setup_gateway.py:sshd_text()` generates
`/etc/ssh/sshd_config.d/00-malpdf-runner.conf`. Older bootstraps placed
`PermitUserEnvironment no` inside `Match User malpdf-runner`, causing the
confirmed line-18 SSHD parse failure. OpenSSH 9.6 marks this keyword as
global-only and defaults it to no:

- <https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c#L611>
- <https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c#L359-L362>

The generated Match block now omits that keyword. The installer relies on
the safe global default or an existing explicit global no. It still requires
the effective runner policy from `sshd -T -C ...` to contain
`permituserenvironment no`; an existing global yes blocks installation rather
than being silently accepted or overwritten. Forced command, public-key-only
authentication, fixed authorized-key location, disabled forwarding/TTY/user
RC and `MaxSessions 1` remain enforced. Client host-key verification and worker
isolation were not changed.

## Completed activation and recovery path

The prior checkout already removed the invalid generated keyword and restored
a candidate after initial syntax/policy failure. This task closes the later
activation gap: the install flow previously ran probes between validation and
SSH reload, then reloaded without rechecking or restoring after reload failure.

`validate_sshd()` now centralizes syntax and effective-policy checks.
`configure_sshd()` retains the previous bytes/mode/group and candidate for
the activation phase. Immediately before reload, `activate_sshd()` checks
candidate contents, reruns `sshd -t` and `sshd -T -C ...`, verifies the contents
again, then calls the fixed reload command. Effective policy now explicitly
requires `maxsessions 1` as well.

Failed syntax, policy, reload or interrupted validation restores the previous
file through the shared `restore_sshd()` path. If no previous file existed,
only the newly introduced candidate is removed. A root-only rejected copy is
retained. Concurrent content edits are preserved; an inability to restore
reports `sshd_restore_failed`. This restores the managed SSHD file, not all
installation state or the service's in-memory configuration. No automatic
restart or loosening of isolation was added.

## Changes and verification

Files changed for this task:

- `scripts/lab/setup_gateway.py`
- `scripts/lab/selftest_diagnostics.py`
- `docs/lab_gateway.md`
- This report.

Eight added regression methods verify the complete generated restriction set,
the exact validation-before-reload order, rollback for failed/timed-out/missing
SSHD, unsafe effective environment/session policy, reload failure, interruption,
concurrent content edits and invalid existing SSH configuration. The existing
Match-keyword and initial rollback regressions remain in the suite. All process
calls and privileged metadata in these cases are mocked; files are generated
inside disposable Windows test directories.

Commands run:

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/selftest.py --json
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
git diff --check
.\.venv-windows-dev\Scripts\python.exe scripts/security/check_repo_content.py
```

Full Windows validation passed 163 tests, 0 failed and 0 skipped; 306 Python
AST checks; repository worktree content guard; diff check; all 18 declared
dependency/version/import checks; and pip consistency. Python: 3.11.16. Base
commit: 935fcee48797606d718aeace47b5fd91c2b95ce3, dirty worktree. The user's
AGENTS.md and unrelated changes are preserved. No commit or push was made.

Receipt (UTC timestamp, corresponding to 2026-10-22 in Asia/Saigon):
`artifacts/tmp/maintenance/lab_workflow/windows_20261021T171113425724Z.json`.
Native Linux SSHD execution and installation were not run or claimed; they
remain separate from this Windows synthetic result.
