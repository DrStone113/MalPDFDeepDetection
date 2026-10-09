# Static inspection and inference improvements

This change adds evidence and removes repeated work without retraining or
rescoring v3/v4 held-out cohorts. All canonical RIT and measured security features
remain intact. Raw nulls and strict inference compatibility failures are preserved.

`StaticPDFAnalyzer` checks the size before reading/hashing, then hashes and parses
one bounded, stable byte snapshot. Symlinks, changed files and byte-cap failures
remain fatal. Both existing structural and reference parsers still run.
The bounded read requests the stable file size plus one sentinel byte rather
than allocating the whole maximum cap; growth remains a validation failure.

`StaticScanSession.iter_scan(paths)` keeps a single verified deployment-model
snapshot in RAM and predicts compatible rows in bounded batches (default 128).
Incompatible rows never enter the model. Create a new session to adopt an updated
artifact; sessions are not shared between threads. This API serves the existing
38-feature frozen XGBoost deployment, not the six-branch v3/v4 research stack.
TreeSHAP is optional in batch screening; the original single-PDF default keeps it.

## Safe JavaScript syntax inspection

`malpdf code-inspect /explicit/local/sample.pdf` follows catalog-reachable PDF
dictionaries, including decoded PDF names, and parses literal or Flate-compressed
JavaScript using Esprima 4.0.1. `malpdf scan /explicit/local/sample.pdf --json
--no-explanation --code-inspection` attaches the same evidence to a model result.
These explicit paths are manual local inspection requests, not acquisition jobs.

Results contain AST node/loop counts and syntactically named calls (`eval`,
`unescape`, `atob`, `Function`, `String.fromCharCode`, `util.printf`,
`Collab.collectEmailInfo`, `app.launchURL`). Literal computed properties such as
`util["pri"+"ntf"]` are recognized. Comments and string mentions do not count as
calls; local variable renaming does not change node histograms. Source strings,
payloads and URLs are never exported. There is no JavaScript interpreter,
deobfuscation runtime, rendering, YARA-based relabeling or dynamic submission.

Every PDF uses a disposable Linux spawn process with a 10 MiB input cap, 1 GiB
address-space cap, 4 CPU seconds and 8-second wall deadline. Traversal is bounded
to 2,000 visited values/depth 64, at most 64 scripts, 256 KiB per decoded script,
4 MiB total decoded script bytes and 20,000 total AST nodes/depth 100. Flate
decompression is explicitly capped per filter layer. The OS caps also cover
implicit pypdf xref/object-stream parsing. Parallel inspection uses bounded
processes with CPU quota/affinity and available RAM checks; worker BLAS threads
are one. Timeouts kill the child and preserve an unavailable/referral result.

Unsupported filters/DecodeParms, encrypted PDFs, malformed JavaScript, failed
decoding and budget exhaustion are explicit incomplete results requiring referral.
Observed partial counts are not evidence of absence. Positive named calls are
syntax indicators, not proof of malicious behavior: identifiers may be shadowed,
and aliases can evade name matching. AST summaries are supplementary evidence;
they do not alter frozen model features, labels, thresholds or predictions.
With `scan --code-inspection`, incomplete/suspicious syntax evidence produces
`static_decision.verdict=REFERRAL_REQUIRED` and exit code 2, even if the separate
model probability predicts benign. This is a recommendation, not execution.
Combined scanning passes the original snapshot SHA-256 into the code-inspection
child, which refuses a changed input before parsing its JavaScript.

Coverage excludes orphaned/unreachable objects, arbitrary deobfuscation, runtime
behavior, exhaustive embedded-payload analysis and exploit verification for
XFA/fonts/images/RichMedia/steganography. Structural name counts do not establish
exploit detection. Parser process limits are not a dynamic sandbox containment
claim. No new CIC accuracy claim is made.

## Reproducible performance evidence

From a clean committed checkout, run `python scripts/14_benchmark_static.py`.
Use `--report-root /path/to/authorized/repository` to retain evidence there.
The benchmark generates benign bytes and numeric rows under ignored artifacts.
It records warm-cache read/hash timings and model-load-per-row versus resident
batch timings, with exact probability/label parity. Feature parsing, TreeSHAP,
six-branch v4 inference and external PDF datasets are outside these timing scopes.
It also smoke-tests actual process-isolated AST extraction. Run directories,
methodology, package versions, timing samples and the research log are preserved;
F1/MCC/ECE/Brier are explicitly N/A for this synthetic latency study.
