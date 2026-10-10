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
The current v7 code evidence schema supports ASCIIHex/ASCII85 streams and their
bounded chains with Flate, bounded PDF text encodings, partial xref recovery,
and declared JavaScript in XFA XML. Invalid encodings and output caps
remain explicit failures. Its null/partial contract is inherited from v2;
canonical RIT features and deployment models are unchanged. The CIC offline
profiler fingerprints this version, backend versions, code and limits before
reusing complete-profile caches. See `cic_static_offline.md` for the fixed
Train/dev job and measured historical v5/v6 coverage. The new XFA path is
verified on benign fixtures; its CIC recall/FPR improvement remains unmeasured.
See [XFA scope and limits](cic_static_xfa.md).

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
4 MiB total decoded script/XML bytes and 20,000 total AST nodes/depth 100. XFA
XML uses a separate document-wide 2,000-node/depth-64 traversal cap. Flate
decompression is explicitly capped per filter layer. The OS caps also cover
implicit pypdf xref/object-stream parsing. Parallel inspection uses bounded
processes with CPU quota/affinity and available RAM checks; worker BLAS threads
are one. The default is one worker. Each child starts a separate process group;
timeouts and iterator cleanup kill that group and preserve unavailable results.
The returned OS limits describe address space, not peak resident memory (RSS).
The benchmark CLI imports its model/experiment stack only inside `main()`.
Python spawn replays the entry point before the worker applies its limits;
`RLIMIT_CPU` counts CPU time already used during that startup. Keeping that
replay lightweight preserves the existing 4-second cap for the parser. This
does not change resource limits or guarantee that arbitrary caller entry points
have the same startup costs.
When a worker exits after an initial empty-pipe check, the parent checks once
more for its final reply before reporting an unavailable result. Timeout and
process-group cleanup still apply; malformed or missing replies remain failures.

Unsupported filters/DecodeParms, encrypted PDFs, malformed JavaScript, failed
decoding and budget exhaustion are explicit incomplete results requiring referral.
Observed partial counts are not evidence of absence. Positive named calls are
syntax indicators, not proof of malicious behavior: identifiers may be shadowed,
and aliases can evade name matching. AST summaries are supplementary evidence;
they do not alter frozen model features, labels, thresholds or predictions.
The v2 evidence schema emits `ast=null` when any script cannot be parsed, and
unknown structural/script totals remain null after incomplete traversal.
`observed` holds lower bounds and AST measurements from successfully parsed
scripts. `script_sources` records bounded object IDs, redacted PDF paths and
separate extraction/AST states. These are occurrence paths, not a complete
trigger/action graph. A failed JS parse cannot become an all-zero AST vector.
The RIT deployment additionally refuses failed/incomplete structural parsing,
independent of numeric schema compatibility; it does not load the model there.
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
`synthetic_ast_evidence.json` is written before checking the AST smoke result,
so failed smoke checks retain the redacted worker evidence and error codes.
