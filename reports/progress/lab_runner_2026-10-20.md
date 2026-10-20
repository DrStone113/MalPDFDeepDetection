# Simplified LAB Runner: local implementation, 2026-10-20

Both requested interfaces are implemented in source: Windows `lab.ps1` and the
installed REMnux `lab` CLI/menu. Existing committed-source packaging,
`lab_side.py` TAR validation/install, AST checks, synthetic runner and strict
report contracts are reused. This is a Windows DEV verification record; the
new software has not been installed or functionally tested on REMnux.

The source baseline is `bbaa580100fe0ba3a836fa27181c7304d77bf26f`. Current changes
are uncommitted. The previously prepared bbaa580 package does not contain this
workflow. No push, administrative SSH, remote writes, dependency installation,
real-PDF processing or VM isolation changes occurred in this implementation turn.

## Resulting operation

| Interface | Behavior |
| --- | --- |
| `lab.ps1 status` | Hardened audit connection, versioned fixed readiness schema; legacy schema1 remains readable |
| `lab.ps1 prepare` | Existing clean-commit packager; no transfer |
| `lab.ps1 test` | Operator terminal only; local checks and immutable package, readiness, one batch approval, one administrative connection, receiver verification, fixed AST/synthetic job, filtered JSON return |
| `lab.ps1 report` | Reads the locally saved result without SSH; Host-only refresh uses the exact saved job identity |
| `lab.ps1 test -Mode offline -Kind syntax/synthetic` | Installs/verifies source and queues an approved job before disconnection; does not execute the offline job |
| `lab.ps1 test -Mode offline -Kind pdf-static` | Separately approves fixed CIC32-Train/32-Validation metadata preparation and queues the job; no PDF read while connected |
| `lab status/run/report/menu` | Local REMnux status, selection by menu number, console confirmation and execution, private local reports; no network restoration |
| `lab.ps1 setup` | Prepares the reviewed11-file bootstrap locally; privileged installation remains operator-only |

Job identity hashes the source commit, archive/manifest hashes, mode, fixed task,
resource policy and approval-attempt identity. Resending the same packet cannot
overwrite source or rerun a claimed job. A new explicitly approved invocation
gets a new job ID. Interrupted/running claims are distinguished from an
unstarted queue; there is no automatic resubmit after SSH loss. Results are
immutable and private operation records use fixed schemas, without raw logs.
Worker stdout/stderr are discarded after bounded capture; PDF bundles stay in
LAB and are never followed or transferred by the Windows client.

The installed helpers must match the helper hashes in the approved source
manifest before any upload is persisted and before a queued job runs. Ordinary
extractor changes reuse the installed helpers; changing security/helper code
requires a reviewed bootstrap update. Dry-check imports use `-B`, avoiding a
bytecode cache that would invalidate the bootstrap's exact-file manifest.

Mode A checks the expected guest Host-only address, adapter set, all-table IPv4
and IPv6 routes, shared mounts and the Python/Git runtime. It refuses default
routes, gateways, global IPv6 and extra active adapters. These are guest
observations, not proof of hypervisor isolation or Windows firewall policy.
The audit key still accepts only `status` and `report <SHA>`; no general shell
or write permission was added. Administrative credentials remain in the
operator's separate Windows session, with forwarding and askpass disabled.

Mode B reuses the existing guest guard for disconnected interfaces, no SSH and
no shared mounts. The operator confirms snapshot/recovery, clipboard/drag-drop
and credential controls at the console. PDF jobs additionally recheck declared
dependencies, the three checksum-locked cohort manifests, the64-row selection,
Arlington identity and resource availability. They use the existing bounded
extractor API in a child process: one parser,20s wall/12s CPU/1GiB per file,
10MiB inputs,30min per job,8MiB per private bundle and512MiB aggregate bundles.
Failures and unprocessed rows remain explicit; no classifier/Test evaluation,
renderer or JS runtime is invoked. Claims bind the console confirmation and
parent process before a PDF worker can start.

Offline refresh from Windows is refused even when an operator asks the client
to refresh: exported results require a separate review/recovery workflow. No
code enables NICs or reconnects a potentially compromised LAB.

## Verification performed on Windows

All commands used `.venv-windows-dev/Scripts/python.exe`, Python3.11.16, or the
named Windows PowerShell/Git Bash executables. Test data are generated inert
buffers, temporary source trees and disposable Git repositories, without live
corpus paths or an external service dependency.

| Command/check | Result and scope |
| --- | --- |
| `-B scripts/lab/selftest.py --json` | 62 passed,0 failed,0 skipped:24 prior security cases plus38 workflow cases |
| `scripts/lab/check_local.py --save` | Source guard, AST, declared dependencies, pip consistency, reviewed imports and combined security self-tests passed; final source hashes are in the maintenance receipt |
| `powershell.exe -NoProfile -File lab.ps1 -Help` | Exit0; wrapper/help works without remote writes |
| `powershell.exe -NoProfile -File lab.ps1 status` | Exit0; actual restricted audit endpoint returned schema1; new Runner readiness not installed/verified by that observation |
| Git Bash `bash -n scripts/lab/setup_runner.sh` | Passed; embedded installer Python also AST-checked by self-test |
| `git diff --check` and content guard | Passed after documentation whitespace corrections |

Workflow cases cover malformed job/report contracts, fixed task selection,
missing manifests, checksum corruption, wrong release/helper versions, extra
source files, repeated packets, queued versus claimed execution, loss of SSH,
refused approval, source drift after approval, bounded local-process output,
redacted errors, resource-limit restoration, IPv4/IPv6/NIC rejection, known
credential presence, disconnected report refresh refusal, console menu exit,
and refusal of PDF workers on Windows or without a console claim. Real Linux
resource calls and real parser execution are mocked or refused in these tests.
The existing packaging self-test includes actual helper sources and the guest
guard in a disposable committed release, then verifies installation and AST
parsing locally. Source-content checks remain enabled; the private-key literal
false-positive fix is retained and exercised rather than bypassed.

The authentication design leaves password entry to Windows OpenSSH, not Python
or chat. The upstream [password-input implementation](https://github.com/PowerShell/openssh-portable/blob/latestw_all/readpass.c)
and [Windows console handling](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/console.c)
were reviewed as primary implementation references. This does not verify the
installed Windows client's password prompt or binary transport against REMnux;
that integration still requires the operator acceptance below.

## One approval batch remaining

Review the exact working-tree manifest, security-rule changes and test receipt;
approve committing this workflow without push. Then generate the clean source
package and11-file bootstrap from that full SHA. Operator transfers the reviewed
bootstrap once and uses `sudo sh setup_runner.sh --check`, followed by the
separately approved `--install`. Fixed destinations and rollback are documented
in [the short user guide](../../docs/lab_runner.md).

Installation changes root-owned helpers, local runner configuration, CLI/menu
entries, job/source directories and the existing audit account/key/SSHD setup;
it does not install dependencies or change NICs/routes/firewalls/data. It is
not an atomic OS rollback: preserve both runner and audit-installer backups.
After setup, first validate the actual schema2 readiness and one source-only
Host-only syntax/synthetic job, then a queued offline synthetic job at console.
GUI/Desktop behavior, root installation, interactive SSH authentication, binary
transfer, Linux limits/cleanup, actual LAB dependencies and PDF execution remain
NOT VERIFIED. A PDF run needs its own manifest/isolation/resource approval.

TTY prompts and valid JSON are not privilege boundaries or remote attestation.
Keep administrative credentials/session outside Codex control. Windows safety
and malicious-PDF superiority are not established by these synthetic results.
