# Bounded XFA JavaScript extraction

The completed v6 cohort has 14 newly recovered partial files with AcroForm,
XFA and embedded-file indicators but no new observed JS/AST files. The current
PDF dictionary traversal did not inspect XML stream content in `/XFA`. Generated
benign XFA fixtures reproduce the omission: the v6 inspector reports no script
for an XML-declared JavaScript body. This confirms an extractor gap, without
proving those CIC files contain missed JavaScript or malicious behavior.

Code inspection v7 reuses the existing stream filters and Esprima AST path.
An XFA stream supplies an XML document; alternating string/stream packet arrays
feed fragments in order. Expat receives bounded chunks, without constructing a
DOM or fetching external resources. XML declarations/BOMs determine encoding,
and XML character references/CDATA produce script text. Declared
`application/x-javascript` bodies enter the existing script count, AST, call
and byte budgets. Missing `contentType` defaults to FormCalc, which is recorded
as non-JavaScript and is not passed to Esprima. These conventions follow the
[Adobe XFA 3.3 specification, chapter 3](https://pdfa.org/norm-refs/XFA-3_3.pdf)
and [Adobe's stream/packet entry description](https://helpx.adobe.com/pdf/aem-forms/6-2/WorkbenchHelp.pdf).

Sources contain the containing PDF object, XML stream object, packet index,
XML byte offset and a fixed redacted path. A cross-packet script records its
starting and ending packet indices. Script payloads, XML packet names, arbitrary
XML attributes and URLs are not exported. Aliases of the same XFA container
are inspected once. XML text with a script-like mention does not become JS.
Syntax inspection does not establish that a trigger/action executed.

Limits remain 64 scripts, 256 KiB per extracted JS body, 4 MiB aggregate decoded
bytes and 20,000 aggregate AST nodes. XFA decoded XML bytes and extracted UTF-8
script text both consume that shared byte allowance; this conservative accounting
is explicit. Filter chains retain their three-layer cap and bounded output at
each layer. XML nodes share a separate document-wide budget equal to
`max_objects`, and XML depth uses `max_pdf_depth`. Worker address-space, CPU,
wall deadline and process-tree termination remain unchanged.

DTD/entity declarations, inherited/external references, unsupported languages,
non-text script markup, malformed packet arrays, unavailable indirect streams,
XML errors and budget exhaustion make the result partial. Global script/AST
totals stay unknown when XML coverage is incomplete; successfully parsed
script evidence remains an explicitly observed lower bound. AST syntax errors
retain the known extracted script separately from parse success. A FormCalc-only
fixture can have no JS within this scope; that is not a benign malware label.

Scope is catalog-reachable PDF actions and declared XFA JavaScript syntax. This
does not inspect embedded-file content, execute FormCalc/JS, fetch `usehref`,
prove complete revision history, or inspect every decoder/exploit path. Packet
fragments that do not constitute one XML document remain partial rather than
being guessed or silently rewritten.

The schema, XML helper, observed-evidence fitting implementation, Python and
Expat versions enter the prepared-job/cache fingerprint. Old jobs/caches cannot
be reused against v7. Historical v5/v6 profile readers retain their explicitly
pinned contracts; RIT canonical predictors, original bytes and frozen model
identities remain intact. RIT CSV supplies no new XFA/AST data.

The offline job keeps strict C0/C1 results and additionally reuses the existing
fixed P0/P1/P2 RF ablation: canonical RIT41 raw-feature fallback, observed
structure/AST, then parser flags. These three share identical known-input
Train/dev rows, seed 42, RF budget and threshold 0.5. All variant feature-group
boundaries are checked before fitting; imputers fit Train only. Failed/unknown
inputs remain in planned class/coverage denominators. Fitting is outside file
timings and adds no extra PDF pass. Models/predictions stay in ignored LAB
artifacts, with no selection, deployment, calibration or Test evaluation.

Benign tests cover direct/indirect and packet-fragment streams, Flate, UTF-16,
XML escapes, FormCalc, redaction/provenance, malformed XML, DTD/reference refusal,
missing packets, unsupported filters, alias deduplication, shared budgets and an
actual disposable worker. Separate synthetic numeric tests verify the reused
offline ablation's Train-only fitting, cold/warm separation and refusal counts.
Real-CIC recall/FPR and latency improvement require the newly prepared paired
same-64 console run; synthetic success does not establish that improvement.

The historical-source fixture comparison is saved in
`reports/experiments/cic_xfa_checks/run_20261010T103722594442Z_535278a7e6c7/synthetic_before_after.json`:
all three direct/Flate/packet-array cases yield zero parsed scripts in v6 and
one AST in v7. That verification attempt was interrupted before the full suite
produced output, and its interrupted status is preserved. The subsequent
`run_20261010T150741420725Z_535278a7e6c7` completed with **760 tests passed**,
two existing single-label metric warnings, consistent dependencies and clean
diff checks. No actual dataset PDFs or Test partitions were analysed in these
maintenance checks. The generating source state was recorded as dirty.

The metadata-only paired job is
`run_20261010T151403329485Z_06a272fc8e36`, using the completed v6 profile as its
baseline. The Desktop launcher pins this job, preserving exact64 inputs and
the frozen model checksum. Its real-PDF execution is deferred to the selected
disconnected console LAB. Both extraction and the reused P0/P1/P2 study run in
one invocation; results must be reviewed before any improvement claim.
