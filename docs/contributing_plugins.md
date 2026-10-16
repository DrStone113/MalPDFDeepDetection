# Static extraction plugins

The SDK in `malpdf.extraction.plugins` adds operator-selected parser, decoder
and feature implementations to the existing `deep-static` worker. Its contract
version is `pdf-static-plugins-v1`. No plugin is enabled by default. The CLI and
locked CIC job do not load plugins; registration uses the Python API explicitly.
See [the extraction contract](pdf_extraction.md) and
[the synthetic verification report](../reports/progress/extract_pdf_plugins_2026-10-16.md).

Plugins are trusted Python source reviewed by the operator. PDF names/content
cannot select a module, install a dependency or construct an import path. Review
imports as well as methods: imported Python can perform work. CPU/RAM/deadline
limits bound the existing disposable worker; this SDK does not establish network,
filesystem or malicious-Python containment. Use only static byte operations and
the approved LAB scope. Never render, execute PDF scripts/actions, follow URLs,
start commands, acquire samples or access credentials in a static plugin.

## Registration and source identity

Implement exactly one abstract base and register an importable concrete class
with `PluginSpec(plugin_id, version, implementation, parameters={})`. Classes in
`__main__`, local functions, extension modules or non-`.py` files are refused.
Source files must be regular, nonsymlink files no larger than1MiB. IDs use
`[a-z][a-z0-9_]{0,31}`; version strings are at most64 ASCII characters.

`PluginRegistry((spec, ...), seed=42, limits=PluginLimits())` accepts at most8
unique IDs. Parameters are a bounded JSON object, snapshotted at registration;
runtime constructors receive a fresh copy. Keep credentials out of configuration.
Exported descriptors include API/plugin versions, module/class, absolute source
path, source SHA256, parameter SHA256 and decoder selectors, without parameter
values. Descriptors and seed appear in provenance and coverage.

Source checks run before PDF admission and again in the worker. Only JSON data
crosses the process boundary; the worker checks the pinned module path/checksum
and resolves classes **after** applying OS limits. Constructors and plugin methods
run there. Changing source or canonical configuration invalidates registration.
This pins the implementation file, not its complete dependency tree; pin and
record imported dependencies separately for a study. `set_random_seed` applies
the registry seed; plugins must use deterministic operations and declare any
additional stochastic state. Volatile measurements such as PID/timing are not
stable features.

## Feature example

Place this class in an importable source module, for example
`src/malpdf/custom_features.py`. This example measures already-admitted original
bytes and produces no parse, decode or execution:

```python
from malpdf.extraction.plugins import BaseFeaturePlugin, PluginContribution

class ByteLength(BaseFeaturePlugin):
    def extract(self, context):
        node = context.observation("source", "root_length",
            status="observed", details={"length": len(context.data)})
        value = context.measurement("length", "raw_layout", len(context.data),
            "observed", [node["evidence_id"]],
            "complete admitted original byte buffer", complete=True)
        return PluginContribution(evidence=(node,), features=(value,))
```

Call from a guarded Python entry point under `scripts/`, on a benign generated
fixture or an explicitly authorized offline LAB path:

```python
from malpdf.custom_features import ByteLength
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.plugins import PluginSpec, PluginRegistry

if __name__ == "__main__":
    plugins = PluginRegistry((PluginSpec("byte_length", "0.1", ByteLength),), seed=42)
    bundle = extract_pdf("/explicit/authorized/benign.pdf", plugins=plugins)
```

`FeatureContext` provides immutable original `data`, a detached normalized
`bundle`, the effective code `limits`, seed, and `blob(sha256)` lookup of bytes
already retained by the worker. Missing buffers return `None`; lookup never
opens a path or performs another decode. Context JSON is capped at4MiB; original
data and retained buffers remain under their existing byte caps. The plugin
must reuse these sources and use parser/decoder hooks for new parsing/decoding.

Use `identifier(local_name)` for new edge IDs and the observation/measurement
helpers for namespaced records. An observation's `source_ref` defaults to the
original-byte evidence node; explicit references must resolve to existing or
new contributions and end at an existing source without cycles. Repaired lineage
propagates through forward references. Optional `start`/`end` verify a half-open
original-byte range and record its hash; object identity/reachability remain
unverified. These range helpers do not describe decoded-buffer offsets.

Each plugin batch is transactional: validation, source/namespace failure or
quota exhaustion rejects its new records together. Existing features cannot be
overwritten. Later plugins can still run; completed batches survive worker
timeouts. All plugins share limits of256 evidence records,512 features,1024
edges (including generated source edges) and512KiB serialized metadata with a
terminal reserve. `PluginLimits` can lower these ceilings. The core bundle
validator checks statuses, values, references, JSON safety and counts.

## Decoder contract

Subclass `BaseDecoderPlugin` and implement `decode(data, parameters, output)`.
Register canonical PDF filter names with `filters=("/MyDecode",)` and optionally
`parameter_keys=("/MyIntegerParameter",)`. A registry cannot replace built-in
filters, aliases or `/Crypt`, or assign one filter to multiple plugins. Existing
aliases route to their canonical name. Unknown routes remain unsupported.

Input is immutable bytes from the current filter stage; parameters are declared
integer scalars only. Unsupported keys/types are refused before invocation.
Write incremental bytes with `output.write(chunk)` and return `None`. Its
`remaining`/`limit` are bounded by the same stage/ratio/chain/shared-byte ledger
used by built-ins. Do not invoke another decoder outside this ledger. Custom
predictor handling is the plugin's responsibility; no built-in predictor is
silently applied to custom output.

Use `PluginDecodeFailure(status, reason_code)` for supported failure states:
`unsupported`, `encrypted`, `decode_error` or `resource_limit`. Codes use lowercase
letters/digits/underscores, starting with a letter. Generic exception messages
are not exported. On failure, the retained bounded prefix remains incomplete
and is never passed to the next filter. Catching an overflow exception inside
the plugin cannot turn its prefix into completed output. Memory/recursion
failure conservatively consumes the remaining shared allowance. Internal codec
allocations need separate implementation review; only emitted bytes are charged
by this wrapper, while OS limits bound the process.

Dispatch is shared by root streams, recursive children and raw structural
XRef/ObjStm streams. It grants no new decoded-byte allowance. Checkpoints record
attempted construction and method invocation; registration alone is `not_run`.

## Parser contract

Subclass `BaseParserPlugin`; `open(data, limits)` returns a reader implementing:

| Member | Contract |
| --- | --- |
| `repaired` | Strict bool; conservative default `True` |
| `candidates()` | Bounded by the core iteration; dictionaries with integer `number`, nullable `generation` and nullable original `offset`; optional `xref_type`, `object_stream_number`, `object_stream_index`, JSON `metadata` |
| `object(candidate, allowance)` | `(value, complete_bool, reason_codes_list)` using existing pypdf generic containers as a common projection; `allowance.remaining` is read-only |
| `warnings()` | `{"count": nonnegative_int, "codes": [fixed_reason_codes]}` |
| `close()` | Release reader resources; failure makes the view partial |

Return raw `StreamObject._data` bytes only; do not call native decoded-stream
APIs or execute/render content. The wrapper charges raw stream bytes to the
same inventory allowance, and all per-view object/depth/metadata limits remain.
An oversized returned body is unavailable, with a null digest; clearing it does
not prove an observed empty stream. Source offsets require matching original
object/generation headers; unsupported claims are retained as unverified metadata
with a null public offset. Byte matches alone do not prove active revision identity.

Views appear as `plugin:<id>` alongside the original pypdf/QPDF/MuPDF inventories
and enter the conservative differential merger. Their objects/disagreements
remain separate; no plugin becomes the primary model input or establishes
whole-document conformance. A generic projection does not make an additional
parser implementation independent if it internally reuses another parser.

## Verification and release boundary

Run `.venv/bin/python -m pytest tests/test_extraction_plugins.py` using the
disk-backed test setup in [development](development.md). Fixtures are generated
benign bytes only. Cases cover all three real worker hooks, source/configuration
drift, import-time CPU/RAM limits, nested custom-plus-Flate decoding, shared byte
and feature quotas, invalid contributions, repaired sources and timeout recovery.
Run the full suite, `pip check` and `git diff --check` before handoff.

The official CIC diagnostic fingerprint explicitly seals `enabled: []`; its
config rejects extra fields and never activates a registry implicitly. A plugin
study needs its own reviewed configuration/lock and unchanged Protocol G/Test
discipline. These SDK fixtures establish no real-PDF coverage, new codec support,
classifier improvement, dynamic execution approval or completed community release.
