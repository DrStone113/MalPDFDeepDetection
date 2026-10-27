# SSHD Match correction and recovery, 2026-10-21

The operator screenshot confirms `/usr/sbin/sshd -t` rejects line 18 of
`/etc/ssh/sshd_config.d/00-malpdf-runner.conf`: PermitUserEnvironment is not
allowed within a Match block. The prior `systemctl start ssh` failed. This is
an installer-generated configuration bug, not evidence of a bad password or
extractor/worker failure. The earlier 14-file bootstrap 25302b72 and its
predecessors contain this bug and must not be installed again.

Official OpenSSH 9.6 marks `permituserenvironment` as SSHCFG_GLOBAL and
rejects global-only directives inside Match. Sources:

- <https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c#L611>
- <https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c#L1305-L1308>

The Windows source removes the invalid directive from the generated Match
block. Effective policy validation still requires `permituserenvironment no`
alongside forced command, authentication and forwarding restrictions. The
installer does not modify global policy for other users to force this result.
Preflight now checks the existing SSH configuration before installation writes.

The candidate SSHD drop-in is applied later, at its validation phase, with a
same-directory atomic replacement. A syntax/policy failure preserves the
candidate as root-only `sshd.rejected` and restores the previous bytes, mode
and group, or removes only that new candidate when no old drop-in existed.
Previous/rejected backups and job evidence remain. Concurrent operator edits
are not overwritten; failed/conflicting restoration reports
`sshd_restore_failed`. This is a limited SSHD restoration, not an atomic
rollback of all account/helper/systemd installation steps. Later containment
failures still leave a valid but unverified gateway.

Eight new generated/mocked regressions cover allowed Match keywords, preserved
effective environment policy, valid candidate checks, syntax/policy failure,
interruption, concurrent operator changes, restoration failure and atomic
replacement failure. Windows full validation passed 155 tests, 0 failed/skipped,
306 AST files, worktree content guard, diff check, all declared dependency/import
checks and pip consistency on Python 3.11.16. Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261021T160402609850Z.json`.
These are local synthetic/mocked results; native Linux validation of the new
candidate and live restricted-gateway readiness remain pending.

The user subsequently requested that the agent perform SSH and installation.
This authorizes the current gateway setup task, without changing the general
standing authorization or approving real PDFs, credentials collection or
network/isolation changes. A hardened, noninteractive SSH probe using the
existing dedicated REMnux identity and command `/usr/bin/true` exited 255
with zero stdout. No remote write or installer execution occurred.
The audit doctor at 2026-10-21T16:01:29Z remained `lab_unreachable`; local
VMware metadata still reported the running guest and expected IP.

The operator was given a precise console recovery for the confirmed drop-in:

```sh
sudo sed -i."$(date +%s%N)".bak '/^[[:space:]]*PermitUserEnvironment[[:space:]]\+no[[:space:]]*$/d' /etc/ssh/sshd_config.d/00-malpdf-runner.conf
sudo /usr/sbin/sshd -t && sudo systemctl start ssh
```

The first command preserves a timestamped backup and removes only the invalid
`no` directive from this fixed runner drop-in. The next starts SSH only after
the full syntax check succeeds. The agent cannot execute this recovery through
an SSH daemon that is not running, and does not substitute guest execution or
console keystrokes through VMware. Recovery success has not been observed.

Replacement bootstrap manifest:
`cf5790733c39e8c81d27b10b580ce1d12b4f76e144f0ec6c297af23d1a1e49ee`.
It has 14 reviewed source/manifest/public-key files from dirty Windows base
commit 935fcee48797606d718aeace47b5fd91c2b95ce3. The intended new immutable
bootstrap destination is
`/home/remnux/malpdf-gateway-bootstrap/cf5790733c39e8c81d27b10b580ce1d12b4f76e144f0ec6c297af23d1a1e49ee`.
Root installer backups remain under `/var/tmp/malpdf-gateway-setup-*`. No
package/dependency installation, dataset/PDF processing, Git mutation or VM
network/isolation change was performed. Previous packages/reports and the
user-owned AGENTS.md are preserved.
