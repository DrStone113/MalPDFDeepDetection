# Gateway account checks, 2026-10-21

The operator-provided screenshot reports
`preflight/existing_privilege_or_session` from the d101e4e bootstrap. That
combined historical reason means either an account process was found or a
sudo privilege listing succeeded. It does not identify the account or prove
which branch blocked this attempt. The live Windows doctor call returned
`not_ready / lab_unreachable`; no new LAB diagnostic observation was obtained.

The Windows installer now uses one fixed account check for existing accounts
and immediately after creating/locking new accounts. It validates the reserved
UID/home/shell/group layout, checks for processes, then checks the sudo listing.
Failures distinguish runner/worker and process/sudo branches. Unexpected exit
codes fail closed instead of being interpreted as no process/no privilege.
New accounts are checked before their homes or authorization keys are installed.
The code never kills a process or changes sudo policy to clear this gate.

Six added generated/mocked regressions cover account-specific process refusal,
sudo refusal/redaction, unknown exit status, clear no-process/denied-listing
results, fresh-account refusal before home/key installation and rejection of
unapproved account names. Full Windows validation passed 127 tests, 305 AST
checks, content guard, declared dependency/import checks and pip consistency.
Evidence:
`artifacts/tmp/maintenance/lab_workflow/windows_20261021T143329412527Z.json`.
No LAB job, administrator SSH, transfer, installation, sudo/policy change,
process termination, PDF processing or VM network change was made by the agent.

The reviewed replacement remains a 14-file source/public-key bootstrap, now
identified by manifest
`c482ac31d7e050518aa90ebbb4b8bf3b976903d5de16ac24ba74a350ce55e4a1`.
Earlier packages and evidence remain intact. The current LAB account/process
condition still needs a bounded console observation or a restored, independently
approved diagnostic connection. Do not infer its cause from local test success.
