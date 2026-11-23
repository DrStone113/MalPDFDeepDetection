from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re
import subprocess

import numpy as np
import torch

from malpdf.data.graph_export_v2_loader import load_multimodal_dataset_v2
from malpdf.models.pdf_transgraph import PDFTransGraph
from scripts.lab.export_vapd_retrospective_inputs import STATUSES, digest, graph_arrays
from scripts.lab.run_cic_vapd_graph_transfer import (
    CIC_COUNTS, CIC_DIR, CIC_EPOCHS, CIC_INPUT_HASHES, DEFAULT_PARQUET_CIC,
    DEFAULT_PARQUET_OURS, FPR_BUDGET, PRETRAIN_EPOCHS, SEED,
    SUPPLEMENT_PER_CLASS, SUPPLEMENT_SHA256, VAPD_INPUT, VAPD_INPUT_SHA256,
    evaluate_split_v2, load_cic, load_inputs, membership_hash, operating_point,
    pick_supplement, set_deterministic_seed, train, write_json,
)

REPO = Path(__file__).resolve().parents[2]
PILOT_INPUT_SHA256 = "0b2c514d593621a881e850e91a9dc0c36ae7e36994a712e2d04dae62503cd9df"
EXPECTED_COUNTS = {"govdocs1_review": 132, "vapd_d1_positive": 13}
EXPECTED_CLUSTERS = {"govdocs1_review": 132, "vapd_d1_positive": 10}
LABELS = {"govdocs1_review": None, "vapd_d1_positive": 1}
GRAPH_KEYS = ("node_features", "node_types", "edge_src", "edge_dst", "edge_rel")
ARMS = ("cic_graph_only", "vapd_pretrained_graph_then_cic")


def pilot_rows(path):
    seen = {}
    with gzip.open(path, "rt", encoding="ascii") as stream:
        header = json.loads(stream.readline(10000))
        if (header["schema_version"] != 1 or header["candidate_counts"] != EXPECTED_COUNTS
                or header["cluster_counts"] != EXPECTED_CLUSTERS
                or header["reference_exact_sha256_count"] != 21414 or header["reference_tlsh_count"] != 21413):
            raise ValueError("unexpected_pilot_header")
        for line in stream:
            sha, cluster, group, label, status, distance, *values = json.loads(line)
            if (len(seen) >= sum(EXPECTED_COUNTS.values()) or sha in seen
                    or not re.fullmatch(r"[0-9a-f]{64}", sha) or label != LABELS[group]
                    or type(distance) is not int or distance <= header["distance_threshold_inclusive"]):
                raise ValueError("unexpected_pilot_row")
            graph = dict(zip(GRAPH_KEYS, values, strict=True), node_feature_dim=23)
            graph_arrays(graph)
            seen[sha] = dict(sha256=sha, cluster=cluster, group=group, label=label, status=status,
                             tls_distance=distance, **{k: torch.tensor(graph[k], dtype=torch.float32 if k == "node_features"
                                                                     else torch.long) for k in GRAPH_KEYS})
    if (Counter(row["group"] for row in seen.values()) != EXPECTED_COUNTS
            or Counter(row["group"] for row in seen.values() if row["cluster"] == row["sha256"]) != EXPECTED_CLUSTERS
            or any(row["cluster"] not in seen or seen[row["cluster"]]["group"] != row["group"]
                   or seen[row["cluster"]]["cluster"] != row["cluster"] for row in seen.values())):
        raise ValueError("prior_pilot_group_membership_changed")
    return header, [seen[sha] for sha in sorted(seen)]


@torch.inference_mode()
def score_pilot(model, rows, device):
    model.eval()
    scores = []
    for offset in range(0, len(rows), 64):
        features, kinds, batch, starts, targets, relations = [], [], [], [], [], []
        nodes = 0
        for index, sample in enumerate(rows[offset:offset + 64]):
            node_features = sample["node_features"]
            features.append(node_features)
            kinds.append(sample["node_types"])
            batch.append(torch.full((len(node_features),), index, dtype=torch.long))
            starts.append(sample["edge_src"] + nodes)
            targets.append(sample["edge_dst"] + nodes)
            relations.append(sample["edge_rel"])
            nodes += len(node_features)
        graph = (torch.cat(features), torch.cat(kinds), torch.stack((torch.cat(starts), torch.cat(targets))),
                 torch.cat(relations), torch.cat(batch))
        values, _ = model(*(tensor.to(device) for tensor in graph), None, None)
        scores.extend(values.sigmoid().cpu().tolist())
    if len(scores) != len(rows) or not np.isfinite(scores).all():
        raise ValueError("invalid_pilot_scores")
    return scores


def summarize_pilot(rows, scores, threshold):
    counts = {
        group: {"n": 0, "alerts": 0, "representatives": 0, "representative_alerts": 0}
        for group in EXPECTED_COUNTS
    }
    status_counts = {group: Counter() for group in EXPECTED_COUNTS}
    for row, score in zip(rows, scores, strict=True):
        entry = counts[row["group"]]
        entry["n"] += 1
        hit = score >= threshold
        entry["alerts"] += hit
        if row["cluster"] == row["sha256"]:
            entry["representatives"] += 1
            entry["representative_alerts"] += hit
        if hit:
            status_counts[row["group"]][row["status"]] += 1
    for group, statuses in status_counts.items():
        counts[group]["alerts_by_extraction_status"] = dict(statuses)
    return counts


def main():
    parser = argparse.ArgumentParser(description="Run locked CIC graph-only diagnostic pilot")
    parser.add_argument("--pilot", required=True, type=Path)
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    if digest(args.pilot) != PILOT_INPUT_SHA256 or digest(VAPD_INPUT) != VAPD_INPUT_SHA256:
        raise ValueError("a pinned pilot or VAPD input changed")
    if any(digest(path) != checksum for path, checksum in CIC_INPUT_HASHES.items()):
        raise ValueError("a pinned CIC input changed")
    if not torch.cuda.is_available():
        raise RuntimeError("This diagnostic is locked to the Windows CUDA environment")
    torch.set_num_threads(4)
    device = torch.device("cuda")

    header, pilot = pilot_rows(args.pilot)
    canonical = load_multimodal_dataset_v2(CIC_DIR, DEFAULT_PARQUET_OURS, DEFAULT_PARQUET_CIC)
    full, gnn = canonical["full_split_samples"], canonical["gnn_eligible_samples"]
    if {name: len(full[name]) for name in CIC_COUNTS} != CIC_COUNTS:
        raise ValueError("canonical_CIC_partition_changed")
    cic, common_table, *_ = load_cic(CIC_DIR)
    _, vapd, table, roles, labels, statuses = load_inputs(VAPD_INPUT)
    chosen = pick_supplement([row["sha256"] for row in vapd], table, roles, labels,
        (statuses == STATUSES.index("bounded_complete"))
        & np.asarray([sample["gnn_message_passing_eligible"] for sample in vapd]),
        {row["sha256"] for row in cic}, common_table, SUPPLEMENT_PER_CLASS)
    if membership_hash(vapd, chosen) != SUPPLEMENT_SHA256:
        raise ValueError("VAPD_supplement_changed")
    pilot_ids = {row["sha256"] for row in pilot}
    if pilot_ids & ({vapd[i]["sha256"] for i in chosen} | {r["sha256"] for part in full.values() for r in part}):
        raise ValueError("pilot_overlaps_CIC_or_supplement")
    supplement = [dict(vapd[i], tab_features=torch.from_numpy(table[i])) for i in chosen]
    del vapd, table

    out = args.run_directory
    out.mkdir(parents=True, exist_ok=False)
    methods = [Path(__file__), Path(__file__).with_name("export_local_holdout_pilot.py"),
               Path(__file__).with_name("run_cic_vapd_graph_transfer.py"), REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "study": "CIC_graph_only_local_holdout_diagnostic",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_sha256": {str(path.relative_to(REPO)): digest(path) for path in methods},
        "numeric_inputs": {"pilot": PILOT_INPUT_SHA256, "VAPD": VAPD_INPUT_SHA256,
                           "CIC": {str(k.relative_to(REPO)): v for k, v in CIC_INPUT_HASHES.items()}},
        "holdout": header, "supplement_sha256": SUPPLEMENT_SHA256, "supplement_rows": len(supplement),
        "primary_train": "CIC Protocol G Train with a measured 23D graph",
        "CIC_train_n": len(gnn["train"]), "CIC_validation_n": len(gnn["validation"]),
        "roles": {"GovDocs1": "unlabeled alert cohort", "VAPD": "publisher-labeled positive diagnostic"},
        "representative_policy": "Minimum SHA-256 in each TLSH-connected cluster, fixed before inference",
        "arms": ARMS, "seed": SEED, "CIC_epochs": CIC_EPOCHS, "VAPD_pretrain_epochs": PRETRAIN_EPOCHS,
        "thresholds": "0.5 and maximum recall at empirical CIC graph Validation FPR <= 1%",
        "branch_policy": "Graph-only. AST, tabular inputs and parser flags are not used.",
        "device": torch.cuda.get_device_name(device),
    })

    set_deterministic_seed(SEED)
    warm = PDFTransGraph(node_in_dim=23, tabular_in_features=25, ablation_mode="graph_only").to(device)
    train(warm, supplement, PRETRAIN_EPOCHS, device)
    encoder = {name: value.detach().cpu().clone() for name, value in warm.graph_encoder.state_dict().items()}
    del warm, supplement
    models, locks = {}, {}
    validation = gnn["validation"], gnn["validation"]
    for arm, weights in zip(ARMS, (None, encoder), strict=True):
        set_deterministic_seed(SEED)
        model = PDFTransGraph(node_in_dim=23, tabular_in_features=38, ablation_mode="graph_only").to(device)
        if weights is not None:
            model.graph_encoder.load_state_dict(weights, strict=True)
        model_selection = train(model, gnn["train"], CIC_EPOCHS, device, validation=validation)
        observed = evaluate_split_v2(model, *validation, device)
        point = operating_point(np.asarray(observed["targets"]), np.asarray(observed["probs"]), FPR_BUDGET)
        locks[arm] = {"model_selection": model_selection, "validation_half": observed["full_denominator"],
                      "validation_point": point}
        models[arm] = model
    write_json(out / "validation_lock.json", locks)

    result = {}
    for arm, model in models.items():
        scores = score_pilot(model, pilot, device)
        point = locks[arm]["validation_point"]["threshold"]
        result[arm] = {
            "reference_0_50": summarize_pilot(pilot, scores, 0.5),
            "validation_locked": summarize_pilot(pilot, scores, point),
        }
        write_json(out / f"{arm}_scores.json", [
            {name: row[name] for name in ("sha256", "cluster", "group", "label", "status", "tls_distance")}
            | {"probability": score} for row, score in zip(pilot, scores, strict=True)
        ])
    write_json(out / "pilot_metrics.json", {"schema_version": 1, "inputs": header, "arms": result,
               "formal_binary_test": False, "new_malware_labels": 0, "deployed_model_changed": False})
    print(out, flush=True)


if __name__ == "__main__":
    main()
