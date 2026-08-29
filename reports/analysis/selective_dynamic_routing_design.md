# Selective Dynamic Routing Design

The architecture is static-first: the existing local static detector produces prediction availability, malicious probability, binary model verdict, extraction warnings, and a local explanation. A separate isolated sandbox may later produce an already-completed behavioural report. This layer only recommends that second stage; it cannot submit a sample or execute active content.

## Policies

`STATIC_ONLY` retains static analysis only. `ALWAYS_SANDBOX` recommends dynamic analysis for every prediction. `UNCERTAINTY_BAND` requires explicitly supplied lower and upper probability bounds; no default interval is fixed and no value is presented as optimized. `STATIC_SUSPICIOUS` can recommend dynamic evidence for a configured suspicious static verdict or extraction warning. Every result stores the policy and parameters, static probability/verdict, decision, and reason (`STATIC_CONFIDENT`, `STATIC_UNCERTAIN`, `STATIC_EXTRACTION_INCOMPLETE`, `POLICY_ALWAYS_DYNAMIC`, or equivalent policy reason).

If the 38-feature static gate cannot yield a prediction, `dynamic_on_prediction_unavailable` is a configurable recommendation option. It does not imply benignness, does not launch a sandbox, and remains disabled under `STATIC_ONLY`.

## Safety and future evaluation

Selective dynamic analysis limits exposure, compute cost, and latency relative to sandboxing every PDF. Any actual execution needs a separately authorized isolated environment with no shared credentials, host folders, clipboard, or unrestricted network. This repository's normal development environment remains parser-only.

A future study must choose routing bounds and a fusion strategy with a documented validation protocol, never by test-set optimization. It should report coverage, latency, static-gate failure cases, behavioural-data availability, and the difference between static verdicts, sandbox observations, and verified labels. There is no hybrid score or hybrid verdict in schema v1.
