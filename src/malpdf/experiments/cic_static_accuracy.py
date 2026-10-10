"""Train-only CIC static adaptation using already controlled numeric evidence.

This study reads no PDFs, never scores Test, and keeps the frozen RIT artifact.
Validation is retrospective development evidence, not an independent holdout.
"""

from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re

import numpy as np
import pandas as pd
import yaml

from malpdf.experiments.cic_static_benchmark import (
    checked_table, clean_code, load_profile_model, select_subset, verify_label_provenance,
)
from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER, EXCLUDED_CONSTANT_FEATURES
from malpdf.models.classical import create_model, model_configurations
from malpdf.evaluation.selective import calibration_metrics
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes

CIC_FEATURE_ORDER = (*DEPLOYMENT_FEATURE_ORDER, "script_ratio", "ObfuscationCount")
CIC_FEATURE_SCHEMA = "cic-static-40/v1"
CIC_MODEL_ID = "xgb-cic-train-static40-v1"


def load_development_tables(root, cfg):
    """Discard Test identities before converting any feature values to numbers."""
    split = checked_table(root, cfg["split_manifest"])
    sources = checked_table(root, cfg["source_manifest"])
    select_subset(split, sources, count=cfg.get("audit_stratum_size", 32))
    indexed = {row["sample_id"]: row for row in sources}
    chosen = [{**row, **{key: indexed[row["sample_id"]][key] for key in ("pdf_sha256", "pdf_relative_path", "related_group_id")}}
              for row in split if row["cohort"] == "cic" and row["split"] in {"train", "validation"}]
    verify_label_provenance(chosen, checked_table(root, cfg["normalization_manifest"]))
    selected = {row["sample_id"]: row for row in chosen}
    records = {}
    for row in checked_table(root, cfg["feature_table"]):
        identifier = row["sample_id"]
        if identifier not in selected:
            continue
        if identifier in records or row["Label"] != selected[identifier]["Label"]:
            raise ValueError("Cached feature identity/label changed")
        values = {name: float(row[name]) if row[name] else np.nan for name in CIC_FEATURE_ORDER}
        if any(np.isinf(value) for value in values.values()):
            raise ValueError("Non-finite cached static measurement")
        records[identifier] = {**selected[identifier], **values,
            **{name: float(row[name]) if row[name] else np.nan for name in EXCLUDED_CONSTANT_FEATURES}}
    if set(records) != set(selected):
        raise ValueError("Cached feature table lacks selected CIC development rows")
    frame = pd.DataFrame([records[key] for key in sorted(records)])
    if frame.groupby("duplicate_group_id").split.nunique().max() != 1:
        raise ValueError("Saved groups cross development partitions")
    counts = {f"{part}/{label}": n for (part, label), n in Counter(zip(frame.split, frame.Label)).items()}
    if counts != cfg["expected_counts"]:
        raise ValueError("CIC development class/partition counts changed")
    train = frame.loc[frame.split.eq("train")]
    if any(train[name].nunique(dropna=False) != 1 or train[name].iloc[0] != 0 for name in EXCLUDED_CONSTANT_FEATURES):
        raise ValueError("Previously excluded constants are not zero constants on CIC Train")
    def vector_keys(cell):
        return {tuple(None if pd.isna(value) else float(value) for value in row)
                for row in cell.loc[:, list(CIC_FEATURE_ORDER)].to_numpy()}
    if vector_keys(train) & vector_keys(frame.loc[frame.split.eq("validation")]):
        raise ValueError("Model feature-equivalence groups cross the saved split")
    return frame


def feature_information(frame):
    """Descriptive label collision bound; this is not attainable model accuracy."""
    output = {}
    for partition, rows in frame.groupby("split"):
        vectors = {}
        for _, row in rows.iterrows():
            key = tuple(None if pd.isna(row[name]) else float(row[name]) for name in CIC_FEATURE_ORDER)
            vectors.setdefault(key, Counter())[int(row.Label)] += 1
        output[partition] = {"rows": len(rows), "unique_vectors": len(vectors),
            "conflicting_vectors": sum(len(labels) > 1 for labels in vectors.values()),
            "label_oracle_correct_ceiling": sum(max(labels.values()) for labels in vectors.values()),
            "interpretation": "diagnostic ceiling on these labeled vectors only; no classifier/generalization claim"}
    return output


def load_cic_candidate(root, identifier):
    if re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier or "") is None:
        raise ValueError("Unsafe CIC candidate run identifier")
    report = root / "reports/experiments/cic_static_accuracy" / identifier
    state = json.loads(read_bounded_bytes(report / "run_summary.json", boundary=root / "reports/experiments", max_bytes=1024**2))
    if state["status"] != "completed":
        raise ValueError("CIC candidate study did not complete")
    spec = json.loads(read_bounded_bytes(report / "model_manifest.json", boundary=root / "reports/experiments", max_bytes=64 * 1024))
    expected = {"model_id": CIC_MODEL_ID, "feature_order": list(CIC_FEATURE_ORDER), "feature_schema": CIC_FEATURE_SCHEMA,
        "threshold": 0.5, "model_configuration": model_configurations(42)["xgboost"]}
    if any(spec.get(name) != value for name, value in expected.items()):
        raise ValueError("CIC candidate contract changed")
    target = root / "artifacts/cic_static_accuracy" / identifier / "cic_xgb40.json"
    if spec["artifact_relative_path"] != str(target.relative_to(root)):
        raise ValueError("CIC candidate artifact path changed")
    content = read_bounded_bytes(target, boundary=root / "artifacts/cic_static_accuracy", max_bytes=64 * 1024**2)
    if hashlib.sha256(content).hexdigest() != spec["artifact_sha256"]:
        raise ValueError("CIC candidate checksum changed")
    from xgboost import XGBClassifier
    model = XGBClassifier()
    model.load_model(bytearray(content))
    if tuple(model.get_booster().feature_names or ()) != CIC_FEATURE_ORDER or not np.array_equal(model.classes_, [0, 1]):
        raise ValueError("CIC candidate binary/feature schema changed")
    model.set_params(n_jobs=1)
    return model, spec


def train_cic_static(root, configuration):
    root = Path(root).absolute()
    clean_code(root)
    cfg = yaml.safe_load(Path(configuration).read_text())
    if cfg["seed"] != 42 or cfg["threshold"] != 0.5:
        raise ValueError("Locked seed/threshold changed")
    method = {"protocol": "retrospective CIC Train-only static adaptation; saved Protocol G partitions",
        "configuration": cfg, "feature_order": list(CIC_FEATURE_ORDER),
        "model_configuration": model_configurations(42)["xgboost"],
        "selection": "one fixed candidate; no hyperparameter/calibration/threshold selection",
        "baseline": "frozen user-supplied RIT G-drop3constant; original training lineage user-reported",
        "test_access": False, "pdf_access": False,
        "scope": "cached numeric feature classification; raw-to-result coverage/latency require offline PDF benchmark",
        "limitations": "Validation previously exposed; RIT PDF overlap cannot be excluded from CSV-only identities"}
    with ResearchRun(root, "cic_static_accuracy", method) as run:
        set_random_seed(42)
        frame = load_development_tables(root, cfg)
        train = frame.split.eq("train").to_numpy()
        validation = frame.split.eq("validation").to_numpy()
        features = frame.loc[:, list(CIC_FEATURE_ORDER)]
        # Common finite eligibility keeps baseline/candidate denominators equal.
        eligible = np.isfinite(features.to_numpy()).all(axis=1)
        baseline_bytes = read_bounded_bytes(root / cfg["baseline_manifest"]["path"],
            boundary=root / "reports/experiments", max_bytes=64 * 1024)
        if hashlib.sha256(baseline_bytes).hexdigest() != cfg["baseline_manifest"]["sha256"]:
            raise ValueError("Frozen RIT model metadata checksum changed")
        baseline_spec = json.loads(baseline_bytes)
        baseline, _ = load_profile_model(root, baseline_spec)
        baseline.set_params(n_jobs=1)
        candidate = create_model("xgboost", 42)
        candidate.fit(features.loc[train], frame.loc[train, "Label"].astype(int))
        target = run.artifacts / "cic_xgb40.json"
        candidate.save_model(str(target))
        manifest = {"model_id": CIC_MODEL_ID, "artifact_relative_path": str(target.relative_to(root)),
            "artifact_sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "feature_schema": CIC_FEATURE_SCHEMA,
            "feature_order": list(CIC_FEATURE_ORDER), "threshold": 0.5,
            "model_configuration": model_configurations(42)["xgboost"],
            "training_dataset": {"sha256": cfg["feature_table"]["sha256"], "training_rows": int(train.sum()),
                "fit_scope": "saved CIC Train only; no Test rows used"},
            "excluded_train_constants": list(EXCLUDED_CONSTANT_FEATURES), "excluded_nonpredictors": ["sample_id", "Label", "split", "cohort", "path", "hash", "source", "parser_failed"]}
        write_json(run.report / "model_manifest.json", manifest)
        mask = validation & eligible
        output = {}
        probabilities = {}
        for name, model, columns in (("RIT_frozen_to_CIC", baseline, DEPLOYMENT_FEATURE_ORDER),
                                      ("CIC_train_static40", candidate, CIC_FEATURE_ORDER)):
            scores = model.predict_proba(features.loc[mask, list(columns)])[:, 1]
            labels = frame.loc[mask, "Label"].astype(int).to_numpy()
            metrics = calibration_metrics(labels, scores, threshold=0.5)
            predicted = scores >= 0.5
            planned_malicious = int((validation & frame.Label.eq("1").to_numpy()).sum())
            planned_benign = int(validation.sum()) - planned_malicious
            output[name] = {"metrics": metrics, "validation_planned": int(validation.sum()), "classified": int(mask.sum()),
                "coverage_numeric": float(mask.sum() / validation.sum()), "refusals": int((validation & ~eligible).sum()),
                "malicious_planned": planned_malicious, "benign_planned": planned_benign,
                "malicious_classified": int((labels == 1).sum()), "benign_classified": int((labels == 0).sum()),
                "tp": int(((labels == 1) & predicted).sum()), "fp": int(((labels == 0) & predicted).sum()),
                "fpr": float(predicted[labels == 0].mean()), "recall_malicious": metrics["recall_malicious"]}
            probabilities[name] = scores.tolist()
            run.state["metrics"][name + "/cic_validation_numeric"] = metrics
        write_json(run.report / "validation_comparison.json", {"models": output,
            "scope": "same cached CIC Validation rows; numeric eligibility only; no new raw-PDF coverage or independent Test claim"})
        write_json(run.report / "feature_information.json", feature_information(frame))
        write_json(run.artifacts / "validation_predictions.json", {"sample_ids": frame.loc[mask, "sample_id"].tolist(), "probabilities": probabilities})
        run.state["notes"] = "Fixed CIC Train-only XGBoost candidate compared with preserved frozen RIT model on the same cached Validation rows. Native candidate artifact ignored; threshold0.5 unchanged; no tuning/Test/PDF access. Validation was previously exposed; no independent generalization or raw-pipeline improvement claimed."
    return run.state
