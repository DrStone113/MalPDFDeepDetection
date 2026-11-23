from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import subprocess
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import torch
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from malpdf.data.graph_export_v2_loader import verify_graph_export_v2_directory
from malpdf.evaluation.binary import evaluate_binary_predictions
from scripts.lab.export_vapd_retrospective_inputs import (
    SPLITS, STATUSES, TABULAR_FEATURES, digest, finite_number,
)
from scripts.lab.run_vapd_retrospective import (
    BATCH_SIZE, EPOCHS, FPR_BUDGET, NEURAL_MODES, SEED, TREE_PARAMS, batches,
    deduplicate_development, fit_neural, load_inputs, neural_scores, operating_point, write_json,
)

CIC_DIR = REPO / "data/processed/graph_exports_v2/export_20261106T135440198431Z_89bf66f04d93"
VAPD_INPUT = REPO / "data/processed/vapd_retrospective/analysis_inputs_v1.jsonl.gz"
CIC_MANIFEST_SHA256 = "70f1b3452bd89e20dcd2705e42e77bce73929c5e8590192ef52cfa9b406ddf78"
VAPD_INPUT_SHA256 = "a700b3a31d0d3a76de04557e67fbb21d926cb2a5427d0a463faef44cbc324586"
CIC_COUNTS = {"train": 870, "validation": 291, "test": 291}
SUPPLEMENT_PER_CLASS = 216
ARMS = ("cic_only", "cic_plus_vapd")


def vector_key(row):
    normalized = np.asarray(row, dtype=np.float32).copy()
    normalized[normalized == 0] = 0
    return normalized.tobytes()


def pick_supplement(ids, table, roles, labels, complete, cic_ids, cic_table, per_class):
    known_vectors = {vector_key(row) for row in cic_table}
    candidates = np.flatnonzero((roles == 0) & complete)
    ranked = sorted(candidates, key=lambda i: (sha256(f"{SEED}:{ids[i]}".encode("ascii")).digest(), ids[i]))
    chosen = []
    retained = Counter()
    for index in ranked:
        label = int(labels[index])
        key = vector_key(table[index])
        if retained[label] >= per_class or ids[index] in cic_ids or key in known_vectors:
            continue
        known_vectors.add(key)
        retained[label] += 1
        chosen.append(index)
    for label in (0, 1):
        if retained[label] != per_class:
            raise ValueError(f"Supplement class {label} has only {retained[label]} eligible records")
    return np.asarray(chosen, dtype=int)


def load_cic(path):
    if digest(path / "manifest.json") != CIC_MANIFEST_SHA256:
        raise ValueError("CIC manifest changed")
    verified = verify_graph_export_v2_directory(path)
    rows, graphs = verified["tabular_rows"], verified["graph_dict"]
    if Counter(row["split"] for row in rows) != CIC_COUNTS:
        raise ValueError("CIC partition denominators changed")
    blank_tokens = torch.zeros(32, dtype=torch.long)
    samples, features, roles, labels, statuses = [], [], [], [], []
    ids = set()
    for row in rows:
        identity = row["sha256"]
        label = row["label"]
        if identity in ids or type(label) is not int or label not in (0, 1):
            raise ValueError("Invalid CIC identity or label")
        ids.add(identity)
        values = [row["features"][feature]["value"] for feature in TABULAR_FEATURES]
        if not all(map(finite_number, values)):
            raise ValueError("CIC table has invalid values")
        graph = graphs.get(identity)
        if graph is not None and graph["label"] != label:
            raise ValueError("CIC graph label differs from table")
        samples.append({
            "sha256": identity, "label": label, "index": row["index"], "ast_tokens": blank_tokens,
            "gnn_message_passing_eligible": graph is not None,
            "node_features": torch.tensor(graph["node_features"], dtype=torch.float32) if graph else None,
            "node_types": torch.tensor(graph["node_types"], dtype=torch.long) if graph else None,
            "edge_src": torch.tensor(graph["edge_src"], dtype=torch.long) if graph else None,
            "edge_dst": torch.tensor(graph["edge_dst"], dtype=torch.long) if graph else None,
            "edge_rel": torch.tensor(graph["edge_rel"], dtype=torch.long) if graph else None,
        })
        features.append(values)
        roles.append(SPLITS.index(row["split"]))
        labels.append(label)
        statuses.append(row["status"])
    return samples, np.asarray(features, dtype=np.float32), np.asarray(roles), np.asarray(labels), np.asarray(statuses)


def membership_hash(samples, indices):
    document_ids = sorted(samples[i]["sha256"] for i in indices)
    return sha256("".join(value + "\n" for value in document_ids).encode("ascii")).hexdigest()


def fitted_scores(models, samples, indices, table, device):
    scores = {}
    for name in TREE_PARAMS:
        scores[name] = models[name].predict_proba(table[indices])[:, 1]
    scores["tab_only"] = neural_scores(models["tab_only"], batches(samples, indices, "tab_only"), device)
    has_graph = np.asarray([samples[i]["gnn_message_passing_eligible"] for i in indices])
    scores["tab_graph"] = scores["tab_only"].copy()
    scores["tab_graph"][has_graph] = neural_scores(
        models["tab_graph"], batches(samples, indices[has_graph], "tab_graph"), device,
    )
    return scores


def metrics_for_test(labels, scores, predicted, statuses):
    metrics = evaluate_binary_predictions(labels, predicted, scores)
    tn, fp = metrics["confusion_matrix"][0]
    metrics["fpr"] = fp / (tn + fp)
    metrics["by_extraction_status"] = {}
    for status in np.unique(statuses):
        mask = statuses == status
        pos = mask & (labels == 1)
        neg = mask & (labels == 0)
        metrics["by_extraction_status"][status] = {
            "n_malicious": int(pos.sum()), "n_benign": int(neg.sum()),
            "tp": int((predicted & pos).sum()), "fp": int((predicted & neg).sum()),
        }
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Compare CIC with and without supplemental VAPD D1 Train")
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    if not torch.cuda.is_available():
        raise RuntimeError("A CUDA device is required for this comparison")
    torch.set_num_threads(4)
    device = torch.device("cuda")
    if digest(VAPD_INPUT) != VAPD_INPUT_SHA256:
        raise ValueError("VAPD numeric bundle hash changed")
    cic, cic_table, cic_roles, cic_labels, cic_statuses = load_cic(CIC_DIR)
    _, vapd, vapd_table, vapd_roles, vapd_labels, vapd_statuses = load_inputs(VAPD_INPUT)
    supplement = pick_supplement(
        [sample["sha256"] for sample in vapd], vapd_table, vapd_roles, vapd_labels,
        (vapd_statuses == STATUSES.index("bounded_complete"))
        & np.asarray([sample["gnn_message_passing_eligible"] for sample in vapd]),
        {sample["sha256"] for sample in cic}, cic_table, SUPPLEMENT_PER_CLASS,
    )
    samples = cic + [vapd[i] for i in supplement]
    table = np.concatenate((cic_table, vapd_table[supplement]))
    roles = np.concatenate((cic_roles, np.zeros(len(supplement), dtype=int)))
    labels = np.concatenate((cic_labels, vapd_labels[supplement]))
    train, validation, test = deduplicate_development(table, roles)
    if not (len(validation) == CIC_COUNTS["validation"] and len(test) == CIC_COUNTS["test"]):
        raise ValueError("Shared-vector overlap would change canonical validation or test membership")
    graph_ok = np.asarray([sample["gnn_message_passing_eligible"] for sample in samples])
    train = train[graph_ok[train]]
    cic_train = train[train < len(cic)]
    supplement_train = train[train >= len(cic)]
    if len(supplement_train) != 2 * SUPPLEMENT_PER_CLASS:
        raise ValueError("Supplement membership changed during validation")
    graph_validation = validation[graph_ok[validation]]
    if not graph_ok[test].all():
        raise ValueError("Canonical Test graph availability changed")

    out = args.run_directory
    out.mkdir(parents=True, exist_ok=False)
    code_paths = [Path(__file__), Path(__file__).with_name("run_vapd_retrospective.py"),
                  Path(__file__).with_name("export_vapd_retrospective_inputs.py"),
                  REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "study": "cic_with_vapd_train_supplement",
        "started_utc": datetime.now(timezone.utc).isoformat(), "seed": SEED,
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "code_sha256": {str(path.relative_to(REPO)): digest(path) for path in code_paths},
        "cic_manifest_sha256": CIC_MANIFEST_SHA256, "vapd_numeric_bundle_sha256": VAPD_INPUT_SHA256,
        "feature_names": TABULAR_FEATURES, "cic_train_original": CIC_COUNTS["train"],
        "cic_train_after_overlap_and_graph_checks": len(cic_train),
        "supplement_n": len(supplement_train), "supplement_per_label": SUPPLEMENT_PER_CLASS,
        "supplement_policy": "Historical VAPD Train, bounded_complete, graph eligible, balanced deterministic SHA ranking with seed 42. Check exact SHA and float32 table aliases against all CIC partitions.",
        "train_n": {ARMS[0]: len(cic_train), ARMS[1]: len(train)},
        "cic_validation_n": len(validation), "cic_test_n": len(test), "cic_validation_graph_n": len(graph_validation),
        "membership_hashes": {key: membership_hash(samples, group) for key, group in
                              (("cic_train", cic_train), ("supplement", supplement_train),
                               ("cic_validation", validation), ("cic_test", test))},
        "test_type": "Previously used canonical CIC Test, retrospective paired comparison",
        "fit_policy": "Fixed tree hyperparameters. Neural epoch selection on shared graph-eligible CIC Validation. Full CIC Validation threshold selection at FPR <= 1%, with same-arm table fallback for unavailable graphs.",
        "tree_parameters": TREE_PARAMS, "neural_modes": NEURAL_MODES,
        "epochs": EPOCHS, "batch_size": BATCH_SIZE, "validation_fpr_budget": FPR_BUDGET,
        "environment": {"python": sys.version.split()[0], "torch": torch.__version__,
                        "cuda": torch.version.cuda, "device": torch.cuda.get_device_name(device)},
    })

    arms, locks = {}, {}
    for arm_name, indices in zip(ARMS, (cic_train, train), strict=True):
        fitted = {"random_forest": RandomForestClassifier(**TREE_PARAMS["random_forest"]),
                  "xgboost": XGBClassifier(**TREE_PARAMS["xgboost"])}
        for tree in fitted.values():
            tree.fit(table[indices], labels[indices])
        scaled = StandardScaler().fit(table[indices]).transform(table).astype(np.float32)
        dedup = deduplicate_development(scaled, roles)
        if not (np.isin(indices, dedup[0]).all() and np.array_equal(dedup[1], validation)
                and np.array_equal(dedup[2], test)):
            raise ValueError("Scaler introduced cross-partition numeric aliases")
        arm_samples = [dict(sample, tab_features=torch.from_numpy(values))
                       for sample, values in zip(samples, scaled, strict=True)]
        selections = {}
        print(f"{arm_name} training with {len(indices)} rows", flush=True)
        for mode in NEURAL_MODES:
            fitted[mode], selections[mode] = fit_neural(
                mode, arm_samples, indices, graph_validation, labels[graph_validation], device,
            )
        scores = fitted_scores(fitted, arm_samples, validation, table, device)
        locks[arm_name] = {
            "operating_points": {name: operating_point(labels[validation], values, FPR_BUDGET)
                                 for name, values in scores.items()},
            "neural_epoch_selection": selections,
        }
        arms[arm_name] = (fitted, arm_samples)
    write_json(out / "validation_lock.json", locks)
    write_json(out / "test_evaluation_started.json", {
        "validation_lock_sha256": digest(out / "validation_lock.json"), "cic_test_n": len(test),
        "cic_test_sha256": membership_hash(samples, test),
    })

    metrics, decisions = {}, {}
    for name, (fitted, arm_samples) in arms.items():
        scores = fitted_scores(fitted, arm_samples, test, table, device)
        decisions[name] = {
            model: values >= locks[name]["operating_points"][model]["threshold"]
            for model, values in scores.items()
        }
        metrics[name] = {model: metrics_for_test(labels[test], values, decisions[name][model], cic_statuses[test])
                         for model, values in scores.items()}
    paired = {}
    for model, base_prediction in decisions[ARMS[0]].items():
        augmented_prediction = decisions[ARMS[1]][model]
        truth = labels[test] == 1
        base_correct = base_prediction == truth
        aug_correct = augmented_prediction == truth
        paired[model] = {group: {"fixed": int((~base_correct & aug_correct & mask).sum()),
                                 "introduced": int((base_correct & ~aug_correct & mask).sum())}
                         for group, mask in (("malicious", truth), ("benign", ~truth))}
    write_json(out / "metrics.json", {"schema_version": 1, "test_n": len(test), "arms": metrics, "paired": paired})
    print(f"Completed {out}", flush=True)


if __name__ == "__main__":
    main()
