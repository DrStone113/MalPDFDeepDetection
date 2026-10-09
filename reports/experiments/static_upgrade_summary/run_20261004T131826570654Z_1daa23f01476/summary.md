# Static upgrade evidence

Static inspection now hashes and parses one stable capped byte snapshot after
checking the file size. Allocation uses the file size plus one sentinel byte;
symlinks and file changes still fail closed. Security features and raw nulls remain.
Frozen v3/v4 models and held-out cohorts were not retrained, tuned or rescored.

JavaScript syntax inspection supports literal and bounded Flate streams, AST
node/loop counts invariant to local variable renaming and literal computed calls
such as util["pri"+"ntf"]. It uses a disposable Linux parser process with byte,
object, depth, memory, CPU and wall caps. It exports only redacted evidence, never
executes JavaScript and recommends referral for unsupported/failed/suspicious
analysis. Combined CLI scanning checks the original snapshot SHA before AST
parsing; incomplete analysis cannot silently become a final benign decision.

| Synthetic timing scope | Previous median | Current median |
| :--- | ---: | ---: |
| Read/hash, generated 2 MiB PDF | 0.002823 s | 0.002733 s |
| XGBoost inference, 256 generated rows | 1.516945 s | 0.192147 s |

Resident batch inference is 7.89 times faster in this five-repeat
synthetic benchmark, with exact probabilities/labels and one model load instead
of 256. This measures the existing 38-feature XGBoost deployment API, excluding
feature parsing and TreeSHAP; it does not measure the full v3/v4 stack. The
read/hash difference is small with overlapping p95: no reliable I/O speed claim.
The AST smoke took 3.375 seconds including child startup;
optional deep syntax inspection incurs extra cost. These fixtures do not prove
exploit coverage or increased CIC Accuracy. Source evidence:
reports/experiments/static_performance/run_20261004T130945651994Z_1daa23f01476/performance_comparison.csv.

564 offline tests passed; two existing single-class fixture warnings. Both
Python environments pass pip check; git diff check passes. 188 source,
config and test files in main match the committed tested branch. Default Python
was installed from pyproject .[dev]; duplicate package payloads were verified
identical before removing only venv copies. Venv now uses approximately 27 MiB;
about 5.9 GiB workspace storage remains. No raw/cache/checkpoint was copied,
staged or deleted. Existing main changes remain intact and dirty.
Generating code: 1daa23f014761e23a249cb0b4ab5640d973b4865.

Initial docstring safety-check failure, first slower read/hash benchmark and
missing-default-dependency summary attempt are preserved. Informal allocation
measurement made during full tests is recorded separately and excluded from
speed claims. F1/MCC/ECE/Brier are N/A: no new held-out classifier evaluation.
