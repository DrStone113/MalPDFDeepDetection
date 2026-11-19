# BUG-012 — Bulk worker bootstrap and resume

The old REMnux bulk run completed eight chunks and stopped producing artifacts in chunk 8. PID 3984 stayed in the bulk writer session after its claiming process exited. One thread remained in `pipe_write` and a child was a zombie. A review of CPython 3.12 and the worker arguments explains the observed behavior. The parent sent a large serialized catalog during `Process.start()`, before entering its deadline loop. The parent held the read end after the child exited. The cause of the child's exit remains unverified.

The candidate starts a Linux bulk subprocess with small JSON arguments and sends a one-byte admission signal after registering its process identity. Arlington is read from one bounded, hash-verified snapshot. The profile receiver handles partial frames while keeping the deadline active.

Resume adopts the eight historical chunks after checking pinned checkpoint hashes and validating the numeric output. New chunks publish through a temporary directory while holding the output lock. A budget stop records the attempt and allows a later console session after writer cleanup is confirmed. A malformed committed checkpoint blocks resume.

Regression tests cover snapshot round trip, an incomplete manifest, partial frames, resource limits and cleanup with a reviewed benign fixture, artifact comparison, and timeout handling. Real-corpus parity and throughput await the offline pilot.
