"""Synthetic-only measurements of static ingestion and resident inference."""

import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import subprocess
from time import perf_counter

import numpy as np
import pandas as pd
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, TextStringObject
from xgboost import XGBClassifier

from malpdf.inference.predictor import StaticScanSession, scan_pdf
from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.code_inspector import CodeInspectionLimits, inspect_pdf_codes
from malpdf.static.result import StaticInspectionResult
from malpdf.static.safety import read_bounded_bytes
from malpdf.static.schema import RIT_FEATURES, implementation_statuses


def benchmark_static(root, code_root, *, samples=256, repeats=5, batch_size=128):
    """No acquisition, external data, PDF execution or held-out evaluation."""
    root, code_root = Path(root).absolute(), Path(code_root).absolute()
    if any(type(n) is not int for n in (samples, repeats, batch_size)) or not (16 <= samples <= 1024 and 3 <= repeats <= 10 and 1 <= batch_size <= 1024):
        raise ValueError("Invalid bounded synthetic benchmark settings")
    status = subprocess.check_output(["git", "-C", str(code_root), "status", "--porcelain"], text=True)
    if status.strip():
        raise ValueError("Benchmark must start from clean committed code")
    methodology = {"protocol": "synthetic performance benchmark", "samples": samples,
        "repeats": repeats, "batch_size": batch_size, "seed": 42,
        "scope": "existing 38-feature deployment API, not v3/v4 ensemble latency or accuracy",
        "data": "generated benign PDF and synthetic numeric rows only",
        "prediction_parity": "exact probabilities and labels; reject mismatch",
        "io_scope": "warm-cache read/hash stage only, excluding feature parsing",
        "io_baseline": "previous three opens: streaming hash, header read, read_bytes",
        "inference_baseline": "one artifact checksum/load/predict per row, no TreeSHAP",
        "uncertainty": "descriptive medians/p95; no significance or general runtime guarantee",
        "parser_limits": CodeInspectionLimits().__dict__, "test_access": False}
    with ResearchRun(root, "static_performance", methodology, code_root=code_root) as run:
        set_random_seed(42)
        write_json(run.report / "static_package_versions.json", {name: importlib.metadata.version(name)
                   for name in ("esprima", "pypdf", "PyMuPDF", "xgboost", "pandas", "numpy")})
        writer = PdfWriter()
        writer.add_blank_page(72, 72)
        output = io.BytesIO()
        writer.write(output)
        data = output.getvalue() + b"\n%" + b"A" * (2 * 1024**2) + b"\n"
        pdf = run.artifacts / "synthetic_benign.pdf"
        pdf.write_bytes(data)
        io_times = {"previous_read_hash": [], "bounded_single_snapshot": []}
        for repeat in range(repeats):
            # Alternate order after one warm-up read; report warm-cache results.
            pdf.read_bytes()
            order = list(io_times) if repeat % 2 == 0 else list(reversed(io_times))
            for mode in order:
                start = perf_counter()
                if mode == "previous_read_hash":
                    digest = hashlib.sha256()
                    with open(pdf, "rb") as handle:
                        for chunk in iter(lambda: handle.read(1024**2), b""):
                            digest.update(chunk)
                    with open(pdf, "rb") as handle:
                        header = handle.read(16)
                    snapshot = pdf.read_bytes()
                    digest = digest.hexdigest()
                else:
                    snapshot = read_bounded_bytes(pdf, boundary=run.artifacts, max_bytes=10 * 1024**2)
                    digest, header = hashlib.sha256(snapshot).hexdigest(), snapshot[:16]
                io_times[mode].append(perf_counter() - start)
                if snapshot != data or digest != hashlib.sha256(data).hexdigest() or not header.startswith(b"%PDF-"):
                    raise ValueError("Synthetic read/hash parity failed")

        rng = np.random.default_rng(42)
        features = pd.DataFrame(rng.normal(size=(samples, len(DEPLOYMENT_FEATURE_ORDER))), columns=DEPLOYMENT_FEATURE_ORDER)
        labels = (features.iloc[:, 0].to_numpy() > 0).astype(int)
        model = XGBClassifier(n_estimators=32, max_depth=3, n_jobs=1, random_state=42, tree_method="hist")
        model.fit(features, labels)
        artifact = run.artifacts / "synthetic_model.json"
        model.save_model(artifact)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest = {"model_id": "synthetic_performance_only", "artifact_sha256": digest,
                    "training_dataset": {"sha256": hashlib.sha256(features.to_numpy().tobytes()).hexdigest()},
                    "feature_schema": "synthetic ordered 38-feature rows", "threshold": 0.5}
        inspections = []
        for row in range(samples):
            values = {name: 0 for name in RIT_FEATURES}
            values.update(features.iloc[row].to_dict())
            inspections.append(StaticInspectionResult(input={"size_bytes": 0}, parser={"success": True},
                features=values, compatibility=dict(implementation_statuses()), diagnostics={}))
        def inspector(position, limits=None):
            return inspections[position]
        loads = 0
        def loader(_root):
            nonlocal loads
            loads += 1
            content = read_bounded_bytes(artifact, boundary=run.artifacts, max_bytes=1024**2)
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Synthetic model artifact changed")
            restored = XGBClassifier(n_jobs=1)
            restored.load_model(bytearray(content))
            return restored, manifest
        expected = model.predict_proba(features)[:, 1].astype(float)
        infer_times = {"reload_per_row": [], "resident_batch": []}
        load_counts = {}
        for repeat in range(repeats):
            order = list(infer_times) if repeat % 2 == 0 else list(reversed(infer_times))
            for mode in order:
                before, start = loads, perf_counter()
                if mode == "reload_per_row":
                    results = [scan_pdf(row, repository_root=root, inspector=inspector, model_loader=loader, explain=False)
                               for row in range(samples)]
                else:
                    results = StaticScanSession(repository_root=root, inspector=inspector, model_loader=loader,
                                                batch_size=batch_size).scan_many(range(samples))
                infer_times[mode].append(perf_counter() - start)
                load_counts[mode] = loads - before
                if (not all(result.prediction["available"] for result in results)
                        or not np.array_equal(expected, [result.prediction["malicious_probability"] for result in results])
                        or not np.array_equal(expected >= 0.5, [result.prediction["predicted_label"] for result in results])):
                    raise ValueError("Synthetic inference probability/label parity failed")

        script_writer = PdfWriter()
        script_writer.add_blank_page(72, 72)
        script_writer._root_object[NameObject("/OpenAction")] = script_writer._add_object(DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"), NameObject("/JS"): TextStringObject('var count=1; util["pri"+"ntf"]("test");')}))
        scripted = run.artifacts / "synthetic_syntax.pdf"
        with scripted.open("wb") as handle:
            script_writer.write(handle)
        start = perf_counter()
        syntax = dict(inspect_pdf_codes([scripted], boundary=run.artifacts, workers=1))[0]
        syntax_seconds = perf_counter() - start
        write_json(run.report / "synthetic_ast_evidence.json", {"elapsed_seconds": syntax_seconds, "evidence": syntax})
        if not syntax["complete"] or syntax["ast"]["named_calls"]["util.printf"] != 1:
            reason = ", ".join(syntax["errors"]) or "unexpected_syntax_evidence"
            raise ValueError("Isolated synthetic AST smoke failed: " + reason)
        rows = []
        for stage, modes, count in (("read_hash", io_times, 1), ("model_inference", infer_times, samples)):
            for mode, timings in modes.items():
                median = float(np.median(timings))
                rows.append({"stage": stage, "mode": mode, "samples": count, "repeats": repeats,
                             "median_seconds": median, "p95_seconds": float(np.percentile(timings, 95)),
                             "samples_per_second": count / median,
                             "model_loads_per_repeat": load_counts.get(mode, "N/A")})
        pd.DataFrame(rows).to_csv(run.report / "performance_comparison.csv", index=False)
        write_json(run.report / "timing_samples.json", {"read_hash": io_times, "inference": infer_times,
                   "probability_parity": "exact", "classification_metrics": "N/A: synthetic latency study"})
        run.state["notes"] = "Synthetic benchmark only; no external PDFs/Test cohorts, no fitting on Validation/Test. Exact probability/label parity. Classification F1/MCC/ECE/Brier N/A. AST calls are syntax evidence, not exploit proof. See performance_comparison.csv."
        run.state["performance"] = rows
        run.state["status"] = "completed"
    return run.state
