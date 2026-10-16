# Static event plans

`malpdf.extraction.triggers.plan_triggers(bundle)` reads the evidence already
exported by the static worker. It produces inert event candidates in
`trigger_plan`, saved as `trigger_plan.json` by the existing extraction writer.
Algorithm identity is `static-events-v2` in the extensible
`pdf-trigger-plan-v1` envelope. Existing saved plans retain their original bytes.

No PDF, raw blob, URL or filesystem reference is opened. No new PDF/XML parse,
stream decode or JS AST parse occurs. Planning runs in the parent on exported
metadata after extraction; worker OS caps apply to extraction, while the planner
has its own bounded node/edge/step/path/output ledger. It does not call a viewer,
Reader, browser, emulator, JavaScript function or external application.

## Candidate families and evidence

| Source | Candidate |
| --- | --- |
| Root catalog `/OpenAction` action | Open document and inspect its static action chain |
| Catalog `/Names/JavaScript` actions in the existing graph | Document script candidate on open; retain name-tree route without exporting names |
| Catalog additional actions | Close, will/did save and will/did print candidates |
| Page `/AA/O`, `/AA/C` | Open/close page, with a separate visit candidate |
| Page-owned annotations | Activate, pointer enter/exit/down/up, focus/blur and page visibility candidates |
| Field additional actions | Keystroke, formatting, validation and calculation candidates |
| AcroForm-owned XFA container, event and script edges | Declared XFA activity and linked script; no DOM selector or invocation claim |
| Latest raw catalog `/Outlines/First`, child `/First`, sibling `/Next` | Bookmark action or destination candidate after checking `/Parent` identity |
| Raw catalog `/OpenAction` destination array | Open at a declared destination; destination feasibility remains unknown |
| Raw page tree `/Annots` Link `/Dest` | Activate an internal link destination without following a URI |
| Raw AcroForm `/Fields` and `/Kids` | Typed text/choice/button input proposals; no signature filling or signing |

The legacy graph carries `/WC`; the locked Arlington model carries `/DC` in
[`AddActionCatalog.tsv`](https://github.com/pdf-association/arlington-pdf-model/blob/b7d880b7a3d3c8f505c025f17763397475e90503/tsv/latest/AddActionCatalog.tsv).
Both spellings remain distinct routes for close candidates. This mapping is
not a PDF-version conformance verdict. Save/print/close candidates describe
possible triggers; they are never operations performed by this pipeline.

The PDF Association's [outline/destination clarifications](https://pdf-issues.pdfa.org/32000-2-2020/clause12.html)
and [name-dictionary clarifications](https://pdf-issues.pdfa.org/32000-2-2020/clause07.html)
provide reference context. The implementation uses a bounded static subset;
it does not implement full ISO validation or infer runtime activation from
the presence of a token or name alone.

## Ownership and original-byte scope

Legacy candidates require an immutable root-document node with the requested
sample digest and verified owner edges of the expected source/target kinds.
Document/catalog/page/annotation/form/field contexts stay separate; action
edges cannot change backend mid-path. Child PDFs and unrelated dictionaries
do not become root event owners. XFA events require the actual reachable
AcroForm-to-XFA edge and same-backend event-to-script edge.

Additional candidates read only the public raw forensic IR. The root needs a
verified complete examined xref chain, a unique latest context and its resolved
Root reference. Every followed indirect object must have matching object number/
generation, current selected membership and a confirmed original boundary or
decoded-container lineage. Reference chains are bounded. Consistent duplicate
resolution evidence, including Root in an XRef stream, keeps all source IDs;
conflicting targets are unresolved. Earlier/historical objects are not substituted
for an unavailable selected object. No private raw tree is reparsed to fill gaps.

Dictionary keys and known names are matched by their existing decoded-byte
SHA256, so arbitrary keys, bookmark titles, field names, JS names and destinations
are not copied into a plan. Supporting IDs lead to the original public syntax
nodes, dictionary/array edges, reference resolutions and object records. Raw
compressed objects retain their container evidence; they do not acquire original
PDF offsets. Plans keep repaired lineage as the OR of their supporting nodes.

Outline traversal checks the reachable First/Next hierarchy and each item's
Parent target. Cycles/reuse, inconsistent parents and simultaneous A/Dest
placements are explicit unresolved cases. This is not complete outline/title/
Prev/Last/Count conformance validation. Named and array destinations retain their
source IDs but are not resolved into verified Reader coordinates or page numbers.

## Plan fields and uncertainty

Every event has a deterministic `id`, event name, `owner_id`, nullable `action_id`,
original `pdf_route`, `supporting_ids`, action-chain records, cycle/chain-limit
flags, source view, repaired flag and `execution_status=not_run`.
`runtime_feasibility=unverified` always applies. XFA events additionally reference
their event/script IDs. Navigation candidates have a `destination_id` and
`destination_resolution=unverified`. Page relationships retain evidence IDs;
they are not guaranteed viewer page indexes.

Action chains use bounded iterative DFS with active/completed states. Shared
subgraphs are distinct from actual cycles, including cycles crossing branches.
An action count or recognized action kind is not evidence of execution or
maliciousness. Unknown/malformed targets and unsupported scopes remain explicit.

AcroForm proposals use a public constant `malpdf-fixture` for text and null values
for unresolved choice/button state. `selector_status=evidence_id_only` means a
future approved runtime adapter must resolve the actual field. A type inherited
along Kids is labeled `ancestor_candidate_unverified`; declared types remain
separate. Flags, Parent inheritance, options, visibility and editability remain
unverified. Invalid explicit types do not fall back to an ancestor type.
Nonterminal/container field candidates may coexist; they are not a canonical
list of independently editable widgets.

XFA proposals have `selector_status=unavailable`. An activity/script association
does not provide the DOM/SOM field selector, prove XML/runtime feasibility or
make automatic field filling possible. External/inherited XFA references and
FormCalc remain outside the existing verified JS event graph. The planner does
not invent missing events from generic XML/script artifacts.

Global `traversal_complete` concerns the bounded metadata traversal only.
Observation status remains partial even when it finishes; whole-document/event
coverage is unknown. Missing input/unsupported scopes are not evidence of event
absence. Runtime attempts, success, blocking and natural/forced traces do not
exist here; dynamic execution requires the separately approved LAB environment.

## Resource limits and verification

Default `TriggerLimits`:128 events,128 actions per chain,32768 indexed nodes,
65536 edges,150000 shared steps,512 supporting-path IDs and512KiB serialized
metadata. Configuration may lower these or stay within the enforced ceilings.
Legacy and raw passes share the same step/event/output budget. BFS marks owners
when queued; DFS and raw tree traversals handle cycles without recursive walks.
Limits preserve an event prefix and fixed reason codes; oversized events are
not partially published. A final serialization guard bounds diagnostics and
keeps a complete-event prefix with a resource-limit status. Existing evidence,
primary vectors and raw bytes remain unchanged.

The Python API accepts `plan_triggers(bundle, limits=TriggerLimits(...))` and
the existing `max_events`/`max_chain` keyword overrides. The official offline job
fingerprint seals this algorithm version and all effective default limits.
No resource limits or locked Train/Validation selection are increased implicitly.

Run `.venv/bin/python -m pytest tests/test_trigger_planner.py` with the
[disk-backed test setup](development.md). Tests use synthetic graph metadata and
generated benign PDFs only. They check actual native/raw exported graphs, all
listed mappings, compressed objects/XRef streams, consistent/conflicting
references, owner/backend guards, root identity, malformed routes/indexes,
lineage, DAG/cycle handling and quotas. The worker integration fixture checks
new families and unchanged primary/code/v8 output. An I/O-denial test prevents
planning from opening files, networking, parsing or decoding again.

Real-PDF event coverage, the historical21 partial files, XFA field selectors,
Reader feasibility and runtime outcomes remain unverified. See the
[maintenance report](../reports/progress/extract_pdf_triggers_2026-10-16.md)
and [full acceptance inventory](../plans/extract-pdf/acceptance.md).
