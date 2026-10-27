# Read-only LAB doctor, 2026-10-20

The Windows facade now supports `lab.ps1 doctor`, also available through
`scripts/lab/labctl.py doctor`. It uses only the audit identity and the exact
forced command `diagnose gateway`. There is no shell, administrative password,
service action, source upload or implicit retry on this path.

The new pinned `lab_diagnostics.py` helper queries only the three fixed gateway
units using `systemctl show`. Output is capped at 16KiB with a four-second
query timeout. Returned properties are normalized to closed enums, bounded
integers and booleans. Raw stderr, unit descriptions, arbitrary service names,
hostnames, credentials, corpus paths, recovered text and journal content are
not returned. Both ends validate the closed JSON schema.

Installer checkpoints expose the current validation phase and a fixed failure
reason; private operator backups retain their own bounded checkpoint. Probe
and worker failures produce structured status records. Atomic latest-job
pointers expose queued/running/completed state while preserving immutable job
reports and claims. Job identity stays inside the existing nested job schema.
A dead oneshot unit does not imply failure or functional test success.

Doctor distinguishes an old endpoint, unavailable LAB, incomplete installation,
invalid metadata, failed units/probes/jobs, inactive timer, pending work and a
completed job. It records each observation separately in the local workflow
cache. `doctor -Mode offline` performs no SSH and reports that offline result
recovery needs its separate authorization. Historical results are never used
as a fresh successful observation when the connection is unavailable.

Windows verification passed 121 generated-input/mocked-transport self-tests,
305 Python AST checks, repository content guard, dependency/import checks and
pip consistency. Evidence:
`artifacts/tmp/maintenance/lab_workflow/windows_20261020T164929619318Z.json`.
The new tests cover command allowlisting, schema rejection, output/time caps,
redaction, oneshot/timer classification, queue/completion ordering, atomic
metadata replacement, worker/probe failure records, offline refusal and no
administrative fallback.

The live existing audit endpoint rejected the new command; the client correctly
reported `not_ready / diagnostics_upgrade_required` and saved that observation.
This is not a successful remote systemd diagnosis. No gateway source/test job,
administrative SSH, transfer, installation, service start or VM isolation
change was performed by the agent.

The reviewed replacement bootstrap has 14 files and only the runner public key.
Its manifest ID is
`d101e4e687232bfd6709e39ed2c383ca94b0234856435a42a84e86c21f459820`.
An operator must deliver and install this helper upgrade once before the agent
can use the new diagnostic endpoint. Installation may still expose an existing
root configuration/unit problem; the checkpoint is intended to make that
failure available through doctor, not bypass its checks. Real PDF processing,
administrative repair and offline recovery retain their separate approval gates.

See [the operator and daily workflow](../../docs/lab_gateway.md).
