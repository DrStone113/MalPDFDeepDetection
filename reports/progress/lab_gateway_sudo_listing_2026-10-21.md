# Gateway sudo listing correction, 2026-10-21

The operator screenshot shows no PID at the time of the process check, and
`sudo -l -U malpdf-runner` and `sudo -l -U malpdf-worker` both report that the
target user is not allowed to run sudo. Those observations do not reveal the
earlier process state or the exit status of the console commands. The latest
permitted Windows `lab.ps1 doctor` returned `not_ready / lab_unreachable` at
2026-10-21T14:46:17Z, so no live gateway diagnostic or new LAB test was obtained.

Inspection identified an installer bug in both the old combined preflight
and the replacement account-specific check: a successful sudo listing was
treated as proof of a target-user grant. Official sudo 1.9.15p5 source shows
that `display_privs` prints the no-grants message and returns success, with
`sudoers_list` returning that result. This explains how root's successful
listing can block a least-privileged account without any sudo grant.

Sources reviewed:

- <https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/display.c#L499-L514>
- <https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/sudoers.c#L896-L904>

The Windows fix retains the fixed listing-only command, uses a minimal
environment with locale C, and requires the exact no-grants line for the
fixed account with exit status 0 or 1, no stderr and at most 16 KiB of output.
An actual grant listing remains blocked. Empty/unknown output, error status,
wrong account, localized output, extra lines, oversized output, or stderr
cannot establish absence of grants. No sudo policy is changed and no command
is executed through the checked account. Existing group/layout/process gates
remain in place, including checks immediately after account creation.

Five added mocked regression methods cover the root-listing success case,
fixed command/environment, missing or failed policy results, wrong/localized
subjects, appended/oversized output and stderr warnings. Existing grant and
no-grant tests now use realistic listing messages. The complete local security
self-test passed 132 tests with zero failures or skips. These are Windows
synthetic/mock results, not a measured installation or containment run on LAB.

The earlier 127-test result and bootstrap review remain historical evidence.
The new package and full validation receipt are recorded in a separate ignored
review directory; neither old package is modified. Operator transfer and
root installation remain necessary before the corrected helper can be used
in REMnux. No administrative SSH, transfer, remote write, sudo/policy change,
process termination, PDF processing or VM isolation change was performed by
the agent.
