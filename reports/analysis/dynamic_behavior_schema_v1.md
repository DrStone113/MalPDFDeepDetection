# Dynamic Behavioral Schema v1

Schema identifier: `dynamic-schema-v1`. This is an offline report-parsing contract, not a sandbox execution system. It consumes compact counts and indicators from an already-produced report; it never stores dropped bytes, memory dumps, packet captures, commands, payloads, or host-identifying raw data.

`0` means the relevant available report section observed no event. `null` means the field was unavailable because its section was absent, malformed, incomplete, or the analysis failed. These meanings must never be collapsed during future modeling.

| Feature | Type / unit | Expected evidence | Meaning and limitation |
| --- | --- | --- | --- |
| `process_count` | integer / count | `behavior.processes` | Process records observed by the provider. |
| `child_process_count` | integer / count | `behavior.processes` | Explicit child/parent relationships; provider tree metadata can be incomplete. |
| `max_process_tree_depth` | integer / levels | `behavior.processes` | Largest observed tree depth; roots have depth one. |
| `file_created_count` | integer / count | `behavior.summary.files` | Provider-reported created entries. |
| `file_modified_count` | integer / count | `behavior.summary.modified_files` | Provider-reported modified entries. |
| `file_deleted_count` | integer / count | `behavior.summary.deleted_files` | Provider-reported deleted entries. |
| `dropped_file_count` | integer / count | `dropped` | Provider-reported dropped records only. |
| `dropped_executable_count` | integer / count | `dropped` metadata | Count classified executable by report metadata; no content is inspected. |
| `registry_create_count` | integer / count | `behavior.summary.keys` | Provider-reported registry creations. |
| `registry_modify_count` | integer / count | `behavior.summary.modified_keys` | Provider-reported registry modifications. |
| `persistence_indicator` | boolean / indicator | provider signatures/categories | Only a provider-reported category, not an independent finding. |
| `dns_query_count` | integer / count | `network.dns` | Observed query records. |
| `unique_domain_count` | integer / count | `network.dns` | Domains are counted internally but not retained in normalized output. |
| `network_connection_count` | integer / count | `network.tcp`, `network.udp` | Observed TCP plus UDP records. |
| `http_request_count` | integer / count | `network.http` | Observed HTTP records; HTTPS is provider-dependent. |
| `shell_activity_indicator` | boolean / indicator | `behavior.summary.executed_commands` | Presence only; command bodies are discarded. |
| `external_process_spawn_indicator` | boolean / indicator | process tree or `pdf_effects` | Child process or explicit provider effect; not necessarily malicious. |
| `process_injection_indicator` | boolean / indicator | provider signatures/categories | Available only when the provider exposes that category. |
| `anti_analysis_indicator` | boolean / indicator | provider signatures/categories | Available only when the provider exposes that category. |
| `embedded_content_written_indicator` | boolean / indicator | `pdf_effects.embedded_content_written` | Provider-reported PDF-related effect. |
| `network_activity_indicator` | boolean / indicator | network sections | True for any observed DNS, connection, or HTTP activity; false only when all are available and zero. |

The initial adapter is `capev2-json-adapter-v1`, supporting a deliberately small CAPEv2-like JSON subset: `info`, `behavior.processes`, `behavior.summary`, `dropped`, `network`, `signatures`, and `pdf_effects`. Unknown fields are ignored with no semantic claim; malformed optional sections generate structured warnings. A failed analysis makes behavioural fields unavailable.

## Future data plan

No dynamic rows are included now: local RIT-PDFMal-2026 raw PDFs are unavailable. A future authorized corpus may separately select high-confidence static cases, errors, uncertainty-region cases, and known false positives/negatives only where lawful raw samples can be safely isolated. Candidate row fields are `sample_id`, `source`, `static_probability`, `static_verdict`, `routing_reason`, `sandbox_status`, schema-v1 features, `ground_truth_label`, and `label_source`.

Static model verdict, observed sandbox behaviour, and ground-truth malware label are distinct. Static predictions must not be fabricated as dynamic ground truth. Possible future methods are retained static verdict after routing, a separate dynamic classifier, late score fusion, or a meta-classifier; none is selected or implemented here. For a graduation thesis, the intended scope is a small authorized sandbox subset, compact normalized features, a simple evaluated second stage, and a static-only versus hybrid comparison—not full sandbox engineering.
