"""Checksum-locked retrospective cohort union; established source splits stay fixed."""
import hashlib
import io
import json
import re
import numpy as np
import pandas as pd
from malpdf.data.cic_normalization import locked_bytes, validate_external_features
from malpdf.data.raw_cohort import assert_group_partitions
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids
from malpdf.experiments.cic_cross_dataset import exclude_source_feature_groups
from malpdf.experiments.raw_tri_modal_v3 import load_locked_cohort, safety_feature_order, validation_roles
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes


def read_spec(root, spec, boundary, *, csv=False):
    content = locked_bytes(root, spec, boundary)
    return pd.read_csv(io.BytesIO(content)) if csv else json.loads(content)


def exact_group_subset(groups, benign, malicious):
    """Bounded class-count subset sum on a seeded group ordering, without group splitting."""
    if (type(benign) is not int or type(malicious) is not int or min(benign, malicious) < 1
            or (benign + 1) * (malicious + 1) > 100_000):
        raise ValueError("Bounded positive class targets required")
    reached = np.zeros((benign + 1, malicious + 1), bool)
    reached[0, 0] = True
    previous = np.full(reached.shape, -1, int)
    for i, row in enumerate(groups.itertuples()):
        b, m = int(row.benign), int(row.malicious)
        if b < 0 or m < 0 or not b + m:
            raise ValueError("Invalid group class counts")
        if b > benign or m > malicious:
            continue
        old = reached.copy()
        fresh = old[:benign + 1 - b, :malicious + 1 - m] & ~old[b:, m:]
        ys, xs = np.where(fresh)
        previous[ys + b, xs + m] = i
        reached[b:, m:] |= fresh
        if reached[benign, malicious]:
            break
    if not reached[benign, malicious]:
        raise ValueError("Exact stratified targets cannot preserve whole groups")
    selected, b, m = [], benign, malicious
    while b or m:
        i = previous[b, m]
        if i < 0: raise RuntimeError("Invalid subset backtrack")
        row = groups.iloc[i]
        selected.append(groups.index[i])
        b, m = b - int(row.benign), m - int(row.malicious)
    return selected


def split_cic_groups(frame, feature_order):
    if (len(frame) != 1452 or not frame.sample_id.is_unique
            or frame.Label.value_counts().to_dict() != {1: 800, 0: 652}):
        raise ValueError("V4 requires exactly the established 1452-row CIC cohort")
    set_random_seed(42)
    frame = frame.sort_values("sample_id", kind="stable").reset_index(drop=True)
    vector = build_duplicate_group_ids(frame.loc[:, feature_order].astype(float).assign(Label=0))
    manifest = frame[["sample_id", "Label"]].copy()
    manifest["duplicate_group_id"] = "cic_v4_" + vector.astype(str)
    groups = manifest.groupby("duplicate_group_id", sort=True).Label.agg(["size", "sum"])
    groups["benign"], groups["malicious"] = groups["size"] - groups["sum"], groups["sum"]
    groups = groups.iloc[np.random.default_rng(42).permutation(len(groups))]
    manifest["split"] = "train"
    for split in ("test", "validation"):
        chosen = exact_group_subset(groups, 131, 160)
        manifest.loc[manifest.duplicate_group_id.isin(chosen), "split"] = split
        groups = groups.drop(chosen)
    assert_group_partitions(manifest)
    return manifest


def validate_combined_groups(labeled, manifest, sources, order):
    assert_group_partitions(manifest)
    frame = labeled.set_index("sample_id").loc[manifest.sample_id]
    groups = build_duplicate_group_ids(frame.loc[:, order].astype(float).reset_index(drop=True).assign(Label=0))
    audit = manifest.copy().assign(vector=groups.to_numpy())
    for key in ("pdf_sha256", "related_group_id"):
        audit[key] = sources.loc[manifest.sample_id, key].to_numpy()
    for key in ("vector", "pdf_sha256", "related_group_id"):
        if audit.groupby(key).split.nunique().max() != 1:
            raise ValueError(f"Combined partition leakage: {key}")


def preparation_state(root, run_id):
    if not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", run_id):
        raise ValueError("Unsafe preparation identifier")
    path = root / "reports/experiments/multi_cohort_v4_prepare" / run_id / "run_summary.json"
    state = json.loads(read_bounded_bytes(path, boundary=root / "reports/experiments", max_bytes=1024**2))
    if state.get("status") != "completed" or state.get("test_evaluation_count") != 0:
        raise ValueError("Completed unevaluated preparation required")
    return state


def load_v4_cohort(root, state):
    result = load_locked_cohort(root, {"inputs": state["inputs"], "expected_samples": {"labeled": 21410, "unlabeled": 4}})
    validate_combined_groups(*result[:3], state["feature_order"])
    return result


def prepare_v4(root, code_root, configuration):
    method = {"configuration": configuration, "study": "Retrospective multi-cohort v4",
        "source": "Preserve raw-PDF Protocol G partitions and roles; source4050 is not historical RIT table",
        "cic_split": "Seed42 whole v3-input-equivalence groups; exact Train870/Val291/Test291; keep publisher labels",
        "previous_exposure": "Both source and CIC v3 outcomes were already inspected; not a confirmatory untouched holdout",
        "selection": "Train-only base fitting; four disjoint Validation roles; one v4 dual Test after lock"}
    with ResearchRun(root, "multi_cohort_v4_prepare", method, code_root=code_root) as run:
        if configuration.get("seed") != 42 or run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official preparation requires clean committed seed42 code")
        cfg = read_spec(root, configuration["source_configuration"], "reports/experiments")["configuration"]
        labeled, old_manifest, old_sources, unknown = load_locked_cohort(root, cfg)
        external = read_spec(root, configuration["external_summary"], "reports/experiments")
        source_result = read_spec(root, configuration["source_summary"], "reports/experiments")
        lock = read_spec(root, configuration["external_cohort_lock"], "reports/experiments")
        if external.get("external_evaluation_count") != 1 or source_result.get("test_evaluation_count") != 1 or lock.get("evaluated_rows") != 1452:
            raise ValueError("Locked previous v3 evidence required")
        saved = read_spec(root, configuration["external_predictions"], "artifacts", csv=True)
        features = read_spec(root, lock["inputs"]["features"], "data/processed", csv=True)
        cache = read_spec(root, lock["inputs"]["cache"], "data/processed", csv=True)
        plan = read_spec(root, lock["inputs"]["plan"], "data/processed", csv=True)
        if len(saved) != 1452 or any(not f.sample_id.is_unique for f in (saved, features, cache, plan)):
            raise ValueError("Established external identities invalid")
        cic = features.set_index("sample_id").loc[saved.sample_id].reset_index()
        validate_external_features(cic)
        eligibility = plan.set_index("sample_id").loc[cic.sample_id]
        if (not np.array_equal(cic.Label, saved.Label) or not np.array_equal(eligibility.Label, saved.Label)
                or not eligibility.exclusion_reason.fillna("").eq("").all() or not eligibility.target_pdf_byte_verified.all()):
            raise ValueError("CIC labels/eligibility changed")
        if exclude_source_feature_groups(labeled, cic, lock["feature_order"]).any():
            raise ValueError("CIC feature group overlaps source")
        cic_manifest = split_cic_groups(cic, lock["feature_order"])
        hashes = cache.set_index("sample_id").loc[cic.sample_id].pdf_sha256
        if not hashes.is_unique or set(hashes) & set(old_sources.pdf_sha256):
            raise ValueError("Cross-cohort PDF overlap")
        rename = dict(zip(cic.sample_id, "public_pdf:" + hashes.to_numpy()))
        cic_manifest.sample_id = cic_manifest.sample_id.map(rename)
        cic.sample_id = cic.sample_id.map(rename)
        old_manifest = old_manifest.assign(cohort="source_raw")
        cic_manifest["cohort"] = "cic"
        manifest = pd.concat((old_manifest, cic_manifest), ignore_index=True)
        combined = pd.concat((labeled, cic.loc[:, labeled.columns]), ignore_index=True).set_index("sample_id").loc[manifest.sample_id].reset_index()
        full = pd.concat((combined, unknown), ignore_index=True)
        cic_sources = pd.DataFrame({"sample_id": cic.sample_id, "Label": cic.Label.astype(str), "pdf_sha256": hashes.to_numpy(),
            "pdf_relative_path": eligibility.pdf_relative_path.to_numpy(),
            "related_group_id": cic_manifest.set_index("sample_id").loc[cic.sample_id].duplicate_group_id.to_numpy()})
        sources = pd.concat((old_sources.reset_index(), cic_sources), ignore_index=True).fillna("").set_index("sample_id")
        order, removed = safety_feature_order(combined.loc[manifest.split.eq("train")])
        validate_combined_groups(combined, manifest, sources, order)
        roles = read_spec(root, configuration["source_roles"], "artifacts", csv=True)
        old_val = old_manifest.loc[old_manifest.split.eq("validation")].set_index("sample_id")
        roles = roles.set_index("sample_id").loc[old_val.index].reset_index()
        if not np.array_equal(roles.Label, old_val.Label) or not np.array_equal(roles.duplicate_group_id, old_val.duplicate_group_id):
            raise ValueError("Original Validation roles changed")
        cic_val = cic_manifest.loc[cic_manifest.split.eq("validation")].reset_index(drop=True)
        new_roles = cic_val.assign(role="")
        for role, positions in validation_roles(cic_val).items():
            new_roles.loc[positions, "role"] = role
        columns = ["sample_id", "Label", "duplicate_group_id", "split", "role"]
        roles = pd.concat((roles.loc[:, columns], new_roles.loc[:, columns]), ignore_index=True)
        directory = root / "data/processed/multi_cohort_v4" / run.identifier
        directory.mkdir(parents=True, exist_ok=False)
        inputs = {}
        for name, table in (("dataset", combined), ("all_features", full), ("split_manifest", manifest), ("source_manifest", sources.reset_index())):
            p = directory / (name + ".csv")
            table.to_csv(p, index=False)
            inputs[name] = {"path": str(p.relative_to(root)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        roles.to_csv(run.artifacts / "validation_roles.csv", index=False)
        baseline = saved.copy(); baseline.sample_id = baseline.sample_id.map(rename)
        baseline.to_csv(run.artifacts / "v3_cic_saved_predictions.csv", index=False)
        write_json(run.artifacts / "training_configuration.json", {**cfg, "inputs": inputs, "expected_samples": {"labeled": 21410, "unlabeled": 4}})
        run.state.update(inputs=inputs, configuration=configuration, feature_order=list(order), train_constant_exclusions=list(removed),
            partition_rows=manifest.groupby(["cohort", "split"]).size().unstack().to_dict("index"),
            validation_role_rows=roles.groupby("role").size().to_dict(), cic_groups=int(cic_manifest.duplicate_group_id.nunique()),
            cic_partition_groups=cic_manifest.groupby("split").duplicate_group_id.nunique().to_dict(),
            source_baseline=source_result["metrics"]["stacking_v3/test"], test_evaluation_count=0,
            validation_roles_sha256=hashlib.sha256((run.artifacts / "validation_roles.csv").read_bytes()).hexdigest(),
            training_configuration_sha256=hashlib.sha256((run.artifacts / "training_configuration.json").read_bytes()).hexdigest(),
            baseline_cic_sha256=hashlib.sha256((run.artifacts / "v3_cic_saved_predictions.csv").read_bytes()).hexdigest(),
            notes="Retrospective preparation only; v3 outcomes exposed; source is raw PDF cohort, not RIT table. CIC whole-group870/291/291; source split/roles unchanged. No invented metrics or labels.")
        load_v4_cohort(root, run.state)
        write_json(run.report / "data_provenance.json", {"inputs": inputs, "partition_rows": run.state["partition_rows"],
            "zero_group_identity_overlap": True, "previous_v3_outcomes_exposed": True, "source_is_historical_rit_table": False,
            "cic_partition_groups": run.state["cic_partition_groups"], "feature_order": list(order)})
    return run.state
