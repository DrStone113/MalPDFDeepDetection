# Documentation index

Technical guides, workflow contracts, and development progress belong in `docs/`.
The [project README](../README.md) provides the overview and navigation.

| Start here | Contents |
| --- | --- |
| [Development environment](development.md) | Python versions, installation, Codespaces, and handoff checks |
| [Workspace layout](workspace_layout.md) | Directory ownership, generated notebooks, maintenance storage, and legacy path contracts |
| [Research workflows](workflows.md) | Cohort preparation, Markov caches, Vision, fusion/stacking, Protocol P/G, static inspection, and offline report parsing |
| [PDF extraction implementation](pdf_extraction.md) | Evidence/feature/coverage contracts, static profiles, plan progress and guarded offline CIC jobs |
| [Static plugin SDK](contributing_plugins.md) | Explicit source-pinned parser/decoder/feature contracts, bounded worker integration and synthetic verification |
| [Static event plans](trigger_plans.md) | Document/page/form/XFA/bookmark candidates from exported graph/raw IR, provenance, quotas and runtime uncertainty |
| [Offline LAB handoff](extraction_lab_handoff.md) | Private metadata/runbook package, clean-code gate and VMware-console transition for the locked static PDF job |
| [Research status](research_status.md) | Recorded extractor changes, Kaggle development studies, outcomes, and limitations |
| [Lubuntu migration](lubuntu_migration.md) | Private transfer verification and local environment restoration |

## Evidence and project rules

| Reference | Purpose |
| --- | --- |
| [AGENTS.md](../AGENTS.md) | Safety, partition discipline, provenance, and contribution requirements |
| [PDF extraction proposal](../plans/extract-pdf/plan.md) | Planned extractor design; separate from implemented functionality |
| [Research log](../reports/research_log.md) | Append-only register of experiments and maintenance |
| [Experiment reports](../reports/experiments/) | Immutable run evidence |
| [Existing analyses](../reports/analysis/) | Saved feature, pipeline, protocol, and containment analyses |
| [Thesis evidence index](../reports/thesis/thesis_evidence_index.md) | Methodology and result provenance |
| [Thesis limitations](../reports/thesis/limitations.md) | Boundaries on interpretation of saved results |
| [Vietnamese progress report](../reports/progress/progress_report_2026-10-11.html) | Offline presentation with links to saved evidence |

Existing analysis and experiment files remain at their recorded paths to preserve
provenance. Write new technical guidance and development updates in `docs/`;
keep per-run evidence in `reports/` and append maintenance records to the research log.

## Documentation maintenance

On 2026-10-15, the long-form README content was organized into the development,
workflow, and research-status guides above. Existing commands, results, caveats,
and the Vietnamese progress-report link were retained, with Markdown links made
relative to their new locations. This maintenance changes documentation only.
