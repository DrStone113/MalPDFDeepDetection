"""V4 tree training, sealed GPU handoff and a once-only retrospective dual Test."""

import hashlib
import io
import inspect
import json
from pathlib import Path
import time
import zipfile

import numpy as np
import pandas as pd
import torch

from malpdf.data.kaggle_export import CODE_FILES, anonymize_rows
from malpdf.data.kaggle_notebook import attach_existing_numeric_bundle, render_kaggle_notebook, save_generated_notebook, writable_numeric_bundle
from malpdf.data.multi_cohort import load_v4_cohort, preparation_state, read_spec
from malpdf.data.rit_pdfmal import sha256_file
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments.raw_tri_modal_v3 import BRANCHES, ROLE_ORDER, fail_closed_routing, group_folds
from malpdf.models.late_fusion import entropy_routing
from malpdf.models.safe_stacking import fit_validation_v3
from malpdf.models.v3_base_learners import METADATA_FEATURES, fit_v3_fold, load_v3_fold
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.static.cache_manager import load_cached_markov_pdf
from malpdf.static.safety import read_bounded_bytes

TREE_BRANCHES = BRANCHES[:4]


def _json(root, relative, boundary):
    return json.loads(read_bounded_bytes(root / relative, boundary=root / boundary, max_bytes=2 * 1024**2))


def _roles(root, preparation, validation):
    path = Path(preparation["artifact_path"]) / "validation_roles.csv"
    content = read_bounded_bytes(root / path, boundary=root / "artifacts", max_bytes=16 * 1024**2)
    if hashlib.sha256(content).hexdigest() != preparation["validation_roles_sha256"]:
        raise ValueError("Combined Validation roles changed")
    frame = pd.read_csv(io.BytesIO(content))
    if not frame.sample_id.is_unique or set(frame.sample_id) != set(validation.sample_id):
        raise ValueError("Saved combined Validation role identities differ")
    aligned = frame.set_index("sample_id").loc[validation.sample_id]
    if (not np.array_equal(aligned.Label, validation.Label)
            or not np.array_equal(aligned.duplicate_group_id, validation.duplicate_group_id)
            or set(aligned.role) != set(ROLE_ORDER)
            or aligned.groupby("duplicate_group_id").role.nunique().max() != 1):
        raise ValueError("Saved combined Validation role groups/labels differ")
    return frame, {role: np.flatnonzero(aligned.role.eq(role).to_numpy()) for role in ROLE_ORDER}


def train_v4_trees(root, code_root, prepared_run):
    preparation = preparation_state(root, prepared_run)
    with ResearchRun(root, "multi_cohort_v4_trees", {"prepared_run": prepared_run, "inputs": preparation["inputs"],
        "fit_policy": "Four tree families, five combined-Train group folds each; no Test inference",
        "gpu_policy": "FT five folds and scratch Vision remain separate explicitly authorized GPU jobs",
        "study_type": "Retrospective adaptation; not a new untouched holdout"}, code_root=code_root) as run:
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Official training requires clean committed code")
        labeled, manifest, _, _ = load_v4_cohort(root, preparation)
        cfg = _json(root, preparation["artifact_path"] + "/training_configuration.json", "artifacts")
        if sha256_file(root / preparation["artifact_path"] / "training_configuration.json") != preparation["training_configuration_sha256"]:
            raise ValueError("Training configuration changed")
        train_manifest = manifest.loc[manifest.split.eq("train")].reset_index(drop=True)
        validation_manifest = manifest.loc[manifest.split.eq("validation")].reset_index(drop=True)
        indexed = labeled.set_index("sample_id")
        train = indexed.loc[train_manifest.sample_id].reset_index()
        validation = indexed.loc[validation_manifest.sample_id].reset_index()
        role_frame, roles = _roles(root, preparation, validation_manifest)
        role_frame.to_csv(run.artifacts / "validation_roles.csv", index=False)
        order = preparation["feature_order"]
        folds = group_folds(train_manifest, partition="train", count=5)
        val_scores, oof = np.zeros((len(validation), 4)), np.full((len(train), 4), np.nan)
        metadata = []
        for column, name in enumerate(TREE_BRANCHES):
            for number, (fitting, held) in enumerate(folds, 1):
                run.progress("tree_fold_started", model=name, fold=number, rows=len(fitting))
                model, info = fit_v3_fold(name, cfg, train.iloc[fitting].loc[:, order], train.Label.to_numpy()[fitting],
                    validation.iloc[roles["base_selection"]].loc[:, order], validation.Label.to_numpy()[roles["base_selection"]],
                    run.artifacts / "tabular" / name / f"fold_{number}", feature_order=order, impute_metadata=True)
                oof[held, column] = model.predict_proba(train.iloc[held].loc[:, order])
                val_scores[:, column] += model.predict_proba(validation.loc[:, order]) / 5
                metadata.append({**info, "fold": number, "checkpoint": str(Path(info["checkpoint"]).relative_to(root))})
                run.progress("tree_fold_completed", model=name, fold=number)
        if not np.isfinite(oof).all():
            raise RuntimeError("Incomplete Train out-of-fold predictions")
        for partition, rows, probabilities in (("train_oof", train, oof), ("validation", validation, val_scores)):
            pd.DataFrame({"sample_id": rows.sample_id, "Label": rows.Label,
                **{name: probabilities[:, i] for i, name in enumerate(TREE_BRANCHES)}}).to_csv(run.artifacts / f"{partition}_predictions.csv", index=False)
        for i, name in enumerate(TREE_BRANCHES):
            run.state["metrics"][name + "/train_oof"] = calibration_metrics(train.Label, oof[:, i])
        run.state.update(prepared_run=prepared_run, inputs=preparation["inputs"], configuration=cfg,
            feature_order=order, fit_metadata=metadata, completed_tree_folds=len(metadata), test_evaluation_count=0,
            gpu_training_pending=True, notes="20 new combined-Train tree folds completed. FT/Vision and v4 Test metrics pending GPU; no Test inference or threshold fitting.")
    return run.state


def export_v4_gpu(root, code_root, prepared_run, tree_run):
    preparation = preparation_state(root, prepared_run)
    prior = _json(root, f"reports/experiments/multi_cohort_v4_trees/{tree_run}/run_summary.json", "reports/experiments")
    if (prior.get("status") != "completed" or prior.get("prepared_run") != prepared_run
            or prior.get("completed_tree_folds") != 20 or prior.get("test_evaluation_count") != 0):
        raise ValueError("A completed matching 20-fold tree run is required")
    with ResearchRun(root, "multi_cohort_v4_gpu_handoff", {"prepared_run": prepared_run, "tree_run": tree_run,
        "inputs": preparation["inputs"], "policy": "Local opaque numeric package only; no upload/network calls",
        "training": "Five FT Train folds + one Vision from scratch; base_selection-only stopping; FP16 GPU AMP",
        "Test_policy": "Unlabeled probability export only; dual Test scoring awaits local Validation lock"}, code_root=code_root) as run:
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("GPU exports require clean committed code")
        labeled, manifest, sources, unknown = load_v4_cohort(root, preparation)
        roles, _ = _roles(root, preparation, manifest.loc[manifest.split.eq("validation")].reset_index(drop=True))
        portable, mapping, exported_roles = anonymize_rows(labeled, manifest, sources, unknown, roles)
        mapping.to_csv(run.artifacts / "private_id_map.csv", index=False)


        source_result = read_spec(root, preparation["configuration"]["source_summary"], "reports/experiments")
        legacy_run = source_result["handoff_run"]
        legacy = _json(root, f"reports/experiments/kaggle_handoff/{legacy_run}/run_summary.json", "reports/experiments")
        legacy_archive = root / legacy["archive"]
        if legacy.get("status") != "completed" or sha256_file(legacy_archive) != legacy["archive_sha256"]:
            raise ValueError("Existing source numeric archive changed")
        with zipfile.ZipFile(legacy_archive) as z:
            old_metadata = z.read("bundle_metadata.json")
            if hashlib.sha256(old_metadata).hexdigest() != legacy["metadata_sha256"]:
                raise ValueError("Existing source metadata changed")
            old_manifest_content = z.read("manifest.csv")
            if hashlib.sha256(old_manifest_content).hexdigest() != json.loads(old_metadata)["file_sha256"]["manifest.csv"]:
                raise ValueError("Existing source manifest changed")
            old_portable = pd.read_csv(io.BytesIO(old_manifest_content))
        source_ids = set(manifest.loc[manifest.cohort.eq("source_raw"), "sample_id"])
        source_labeled = labeled.loc[labeled.sample_id.isin(source_ids)]
        expected_old, old_mapping, _ = anonymize_rows(source_labeled,
            manifest.loc[manifest.cohort.eq("source_raw")], sources, unknown,
            roles.loc[roles.sample_id.isin(source_ids)])
        if not old_portable.loc[:, expected_old.columns].equals(expected_old):
            raise ValueError("Existing numeric source split/identity mismatch")
        old_ids = old_mapping.set_index("sample_id").export_sample_id.to_dict()
        old_hashes = old_portable.set_index("sample_id").npy_sha256.to_dict()
        local_ids = mapping.set_index("export_sample_id").sample_id.to_dict()
        reuse_rows = []
        gpu = {"tabular": prior["configuration"], "vision": {"batch_size": 256, "max_epochs": 20, "patience": 5,
            "learning_rate": 0.0003, "weight_decay": 0.0001, "min_delta": 0.0, "preload_ram": True,
            "mixed_precision": True, "num_workers": 2, "prefetch_factor": 1, "max_ram_cache_gib": 6},
            "feature_order": preparation["feature_order"], "metadata_features": list(METADATA_FEATURES)}

        gpu["tabular"] = {k: prior["configuration"][k] for k in ("models", "training", "cpu_threads")}
        train_manifest = manifest.loc[manifest.split.eq("train")].reset_index(drop=True)
        train_folds = train_manifest[["sample_id"]].copy().assign(fold=0)
        for i, (_, held) in enumerate(group_folds(train_manifest, partition="train", count=5), 1):
            train_folds.loc[held, "fold"] = i
        id_map = mapping.set_index("sample_id").export_sample_id
        train_folds.sample_id = train_folds.sample_id.map(id_map)
        full = pd.concat((labeled, unknown), ignore_index=True).set_index("sample_id")
        tabular = full.loc[mapping.sample_id, preparation["feature_order"]].reset_index()
        tabular.sample_id = tabular.sample_id.map(id_map)
        files = {"manifest.csv": portable, "validation_roles.csv": exported_roles,
                 "train_folds.csv": train_folds, "tabular_features.csv": tabular}
        archive = run.artifacts / "malpdf-v4-numeric.zip"
        hashes = {}
        private_hashes = mapping.set_index("export_sample_id").pdf_sha256
        started, last = time.monotonic(), time.monotonic()
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out:
            new_matrix_count = 0
            for i, row in enumerate(portable.itertuples()):
                original_id = local_ids[row.sample_id]
                if original_id in old_ids:
                    old_id = old_ids[original_id]
                    portable.loc[i, "npy_sha256"] = old_hashes[old_id]
                    reuse_rows.append({"sample_id": row.sample_id, "legacy_sample_id": old_id})
                    continue
                digest = private_hashes.loc[row.sample_id]
                _, metadata = load_cached_markov_pdf(digest, cache_directory=root / "data/processed/markov_cache")
                content = read_bounded_bytes(root / "data/processed/markov_cache" / (digest + ".npy"),
                    boundary=root / "data/processed/markov_cache", max_bytes=1024**2)
                if hashlib.sha256(content).hexdigest() != metadata["npy_sha256"]:
                    raise ValueError("Matrix changed while exporting")
                portable.loc[i, "npy_sha256"] = metadata["npy_sha256"]
                out.writestr(row.cache_relative_path, content)
                new_matrix_count += 1
                if time.monotonic() - last >= 10:
                    run.progress("v4_zip_progress", rows=i + 1, total=len(portable))
                    last = time.monotonic()
            if portable.loc[portable.split.ne("unlabeled")].groupby("npy_sha256").split.nunique().max() != 1:
                raise ValueError("Identical Vision matrices cross partitions")
            files["source_matrix_reuse.csv"] = pd.DataFrame(reuse_rows)
            payloads = {name: frame.to_csv(index=False).encode() for name, frame in files.items()}
            payloads.update({"vision_configuration.json": json.dumps(gpu["vision"]).encode(),
                             "v4_gpu_configuration.json": json.dumps(gpu).encode()})
            for name in (*CODE_FILES, "experiments/multi_cohort_gpu.py", "data/kaggle_notebook.py"):
                payloads["code/src/malpdf/" + name] = (code_root / "src/malpdf" / name).read_bytes()
            for name, content in payloads.items():
                if len(content) > (16 * 1024**2 if name.endswith(".csv") else 1024**2):
                    raise ValueError("Portable member exceeds notebook cap")
                out.writestr(name, content)
                hashes[name] = hashlib.sha256(content).hexdigest()
            inventory = {"seed": 42, "shape": [1, 256, 256], "dtype": "float32", "code_commit": run.commit,
                "raw_pdfs_included": False, "raw_pdf_hashes_included": False,
                "partition_rows": portable.split.value_counts().to_dict(), "file_sha256": hashes,
                "study": "retrospective_multi_cohort_v4", "tabular_measurements_included": True,
                "source_bundle_metadata_sha256": legacy["metadata_sha256"],
                "source_bundle_archive_sha256": legacy["archive_sha256"],
                "source_dataset": "nguyenkhang294/malpdf-markov-cache",
                "reused_source_matrices": len(reuse_rows), "new_cic_matrices": new_matrix_count}
            content = json.dumps(inventory, indent=2).encode()
            out.writestr("bundle_metadata.json", content)
        notebook = render_kaggle_notebook(code_root / "notebooks/kaggle_vision_resnet18.ipynb", hashlib.sha256(content).hexdigest())
        notebook["cells"] = notebook["cells"][:2]
        notebook["cells"][0]["source"] = ["# MalPDF v4: retrospective multi-cohort GPU training\n",
            "Attach this v4 delta dataset AND nguyenkhang294/malpdf-markov-cache. Train five FT folds and Vision from scratch. Download the whole output run; Test metrics are computed later in Codespace.\n"]
        bootstrap = "".join(notebook["cells"][1]["source"])
        bootstrap += "\n" + inspect.getsource(writable_numeric_bundle)
        bootstrap += "\nBUNDLE_ROOT = writable_numeric_bundle(BUNDLE_ROOT, metadata)\n"
        bootstrap += "\n" + inspect.getsource(attach_existing_numeric_bundle)
        bootstrap += "\nprint({'reused_source_matrices': attach_existing_numeric_bundle(BUNDLE_ROOT, INPUT_ROOT, metadata)})\n"
        notebook["cells"][1]["source"] = bootstrap.splitlines(keepends=True)
        source = "from malpdf.experiments.multi_cohort_gpu import train_v4_gpu\nOUTPUT_DIR = train_v4_gpu(BUNDLE_ROOT, Path('/kaggle/working/v4_outputs'))\nprint(OUTPUT_DIR)\n"
        notebook["cells"].append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": source.splitlines(keepends=True)})
        notebook_path = save_generated_notebook(root, run.state["study"], run.identifier,
            "kaggle_multi_cohort_v4.ipynb", notebook)
        for key, value in (("prepared_summary", preparation), ("tree_summary", prior)):
            write_json(run.artifacts / (key + ".json"), value)
        run.state.update(prepared_run=prepared_run, tree_run=tree_run, samples=len(portable),
            prepared_summary_sha256=sha256_file(root / preparation["report_path"]),
            tree_summary_sha256=sha256_file(root / prior["report_path"]),
            archive=str(archive.relative_to(root)), archive_bytes=archive.stat().st_size, archive_sha256=sha256_file(archive),
            metadata_sha256=hashlib.sha256(content).hexdigest(), inventory=inventory,
            notebook=str(notebook_path.relative_to(root)),
            private_mapping=str((run.artifacts / "private_id_map.csv").relative_to(root)),
            reused_source_matrices=len(reuse_rows), new_cic_matrices=new_matrix_count,
            elapsed_seconds=time.monotonic() - started, upload_performed=False, test_evaluation_count=0,
            notes="Local numeric GPU bundle prepared; includes opaque tabular measurements and unchanged float32 Markov matrices. No PDF/original hash/path; private ID map stays local. GPU training and dual Test pending.")
        write_json(run.report / "bundle_inventory.json", {**inventory, "archive_bytes": run.state["archive_bytes"],
            "archive_sha256": run.state["archive_sha256"], "metadata_sha256": run.state["metadata_sha256"]})
    return run.state


def claim_v4_tests(root, run, split_sha256, validation_lock_sha256):
    directory = root / "artifacts/multi_cohort_v4_test_locks"
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ValueError("Unsafe Test marker directory")
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / (split_sha256 + ".json"), {"report": str(run.report.relative_to(root)),
        "validation_lock_sha256": validation_lock_sha256, "allowed_evaluations_per_test": 1})
    write_json(run.report / "test_evaluation_started.json", {"source_A": 1, "cic_B": 1, "split_sha256": split_sha256})


def align_gpu_scores(frame, mapping, partition, prediction):
    rows = frame.loc[frame.split.eq(partition)]
    expected = mapping.set_index("export_sample_id")
    if (set(prediction) != {"sample_id", "p_malicious"} or not prediction.sample_id.is_unique
            or set(prediction.sample_id) != set(rows.sample_id)):
        raise ValueError("GPU probability identities/partition do not match export")
    out = prediction.set_index("sample_id").loc[rows.sample_id].p_malicious.to_numpy(float)
    if not np.isfinite(out).all() or (out < 0).any() or (out > 1).any():
        raise ValueError("GPU probabilities must be finite within [0,1]")
    return pd.Series(out, index=expected.loc[rows.sample_id].sample_id.to_numpy())


def resume_v4(root, code_root, handoff_run, gpu_directory):
    export = _json(root, f"reports/experiments/multi_cohort_v4_gpu_handoff/{handoff_run}/run_summary.json", "reports/experiments")
    if export.get("status") != "completed" or export.get("test_evaluation_count") != 0:
        raise ValueError("Completed v4 handoff required")
    preparation = preparation_state(root, export["prepared_run"])
    prior = _json(root, f"reports/experiments/multi_cohort_v4_trees/{export['tree_run']}/run_summary.json", "reports/experiments")
    if (sha256_file(root / prior["report_path"]) != export["tree_summary_sha256"]
            or sha256_file(root / preparation["report_path"]) != export["prepared_summary_sha256"]):
        raise ValueError("Prepared/tree evidence changed after export")
    with ResearchRun(root, "multi_cohort_v4_evaluation", {"handoff_run": handoff_run, "inputs": preparation["inputs"],
        "meta_policy": "Disjoint combined Validation roles; candidate MCC, separate Platt fitting, Youden threshold",
        "evaluation_policy": "One v4 pass each on unchanged source4050 and CIC291; v3 comparator from saved predictions",
        "exposure": "Retrospective adaptation; original v3 outcomes were previously inspected"}, code_root=code_root) as run:
        if run.state["code_worktree"]["status"] != "clean":
            raise ValueError("Dual Test evaluation requires clean committed code")
        gpu_directory = gpu_directory.absolute()
        if not gpu_directory.is_relative_to(root / "checkpoints"):
            raise ValueError("Imported GPU evidence must stay in ignored checkpoints")
        def gpu_json(name):
            return json.loads(read_bounded_bytes(gpu_directory / name, boundary=root / "checkpoints", max_bytes=2 * 1024**2))
        checksums = gpu_json("output_checksums.json")
        for name, digest in checksums.items():
            content = read_bounded_bytes(gpu_directory / name, boundary=gpu_directory,
                max_bytes=64 * 1024**2 if name.endswith(".pt") else 16 * 1024**2)
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("GPU output checksum differs")
        state = gpu_json("run_summary.json")
        ft_lock = gpu_json("ft_selection_lock.json")
        vision_dir = gpu_directory / state["vision_directory"]
        vision_lock = json.loads(read_bounded_bytes(vision_dir / "vision_selection_lock.json", boundary=gpu_directory, max_bytes=2 * 1024**2))
        if (state.get("status") != "completed" or state.get("bundle_metadata_sha256") != export["metadata_sha256"]
                or state.get("code_commit") != export["code_commit"] or state.get("seed") != 42
                or state.get("test_metrics_computed") is not False or len(state.get("ft_folds", [])) != 5
                or ft_lock.get("bundle_metadata_sha256") != export["metadata_sha256"]
                or ft_lock.get("selected_role") != "validation_base_selection"
                or vision_lock.get("bundle_metadata_sha256") != export["metadata_sha256"]
                or vision_lock.get("selected_role") != "validation_base_selection"):
            raise ValueError("GPU training evidence violates the exported v4 lock")

        archive = root / export["archive"]
        if sha256_file(archive) != export["archive_sha256"]:
            raise ValueError("V4 numeric archive changed")
        with zipfile.ZipFile(archive) as z:
            metadata = z.read("bundle_metadata.json")
            if hashlib.sha256(metadata).hexdigest() != export["metadata_sha256"]:
                raise ValueError("Sealed metadata changed")
            portable = pd.read_csv(io.BytesIO(z.read("manifest.csv")))
        labeled, manifest, sources, unknown = load_v4_cohort(root, preparation)
        role_frame, roles = _roles(root, preparation, manifest.loc[manifest.split.eq("validation")].reset_index(drop=True))
        expected, mapping, _ = anonymize_rows(labeled, manifest, sources, unknown, role_frame)
        if not portable.loc[:, expected.columns].equals(expected):
            raise ValueError("Portable identities differ from locked combined cohort")
        validation_manifest = manifest.loc[manifest.split.eq("validation")].reset_index(drop=True)
        validation = labeled.set_index("sample_id").loc[validation_manifest.sample_id].reset_index()
        selection_rows = len(roles["base_selection"])
        if ft_lock.get("selection_rows") != selection_rows or vision_lock.get("selection_rows") != selection_rows:
            raise ValueError("GPU selection row count differs from saved Validation roles")
        train_manifest = manifest.loc[manifest.split.eq("train")].reset_index(drop=True)
        train = labeled.set_index("sample_id").loc[train_manifest.sample_id].reset_index()
        folds = group_folds(train_manifest, partition="train", count=5)
        for number, (fitting, _) in enumerate(folds, 1):
            info = state["ft_folds"][number - 1]
            path = gpu_directory / "ft_transformer" / f"fold_{number}" / "model.pt"
            if str(path.relative_to(gpu_directory)) not in checksums:
                raise ValueError("FT checkpoint absent from checksum inventory")
            load_v3_fold(path, info["checkpoint_sha256"], train.iloc[fitting].loc[:, preparation["feature_order"]],
                prior["configuration"], boundary=gpu_directory, base_selection_rows=selection_rows)
        vision_path = vision_dir / "vision_resnet_best.pt"
        if sha256_file(vision_path) != vision_lock["checkpoint_sha256"]:
            raise ValueError("Vision selected checkpoint changed")
        payload = torch.load(io.BytesIO(read_bounded_bytes(vision_path, boundary=gpu_directory, max_bytes=64 * 1024**2)),
            map_location="cpu", weights_only=True)
        if (payload.get("architecture") != "single_channel_resnet18" or payload.get("seed") != 42
                or payload.get("code_commit") != export["code_commit"]
                or payload.get("best_epoch") != vision_lock.get("best_epoch")
                or any(not torch.isfinite(value).all() for value in payload["model_state_dict"].values())):
            raise ValueError("Vision checkpoint/selection metadata mismatch")
        tree_scores = pd.read_csv(root / prior["artifact_path"] / "validation_predictions.csv").set_index("sample_id")
        scores = tree_scores.loc[validation.sample_id, list(TREE_BRANCHES)].to_numpy(float)
        def csv_gpu(path):
            relative = str(path.relative_to(gpu_directory))
            if relative not in checksums:
                raise ValueError("Required output absent from GPU checksum inventory")
            return pd.read_csv(io.BytesIO(read_bounded_bytes(path, boundary=gpu_directory, max_bytes=16 * 1024**2)))
        ft_val = align_gpu_scores(portable, mapping, "validation", csv_gpu(gpu_directory / "ft_probs_val.csv"))
        vision_val = align_gpu_scores(portable, mapping, "validation", csv_gpu(vision_dir / "vision_probs_val.csv"))
        scores = np.column_stack((scores, ft_val.loc[validation.sample_id], vision_val.loc[validation.sample_id]))
        stack, candidates = fit_validation_v3(validation_manifest, scores,
            prior["configuration"]["meta_regularization_cs"], branches=BRANCHES, roles=roles)
        write_json(run.report / "validation_lock.json", {**stack.lock_metadata(), "feature_order": preparation["feature_order"],
            "inputs": preparation["inputs"], "gpu_metadata_sha256": export["metadata_sha256"],
            "tree_fit_metadata": prior["fit_metadata"], "ft_fit_metadata": state["ft_folds"],
            "vision_checkpoint_sha256": vision_lock["checkpoint_sha256"], "previous_v3_outcomes_exposed": True})
        pd.DataFrame(candidates).to_csv(run.report / "validation_candidates.csv", index=False)
        claim_v4_tests(root, run, preparation["inputs"]["split_manifest"]["sha256"], sha256_file(run.report / "validation_lock.json"))

        torch.set_num_threads(2)
        train_manifest = manifest.loc[manifest.split.eq("train")].reset_index(drop=True)
        train = labeled.set_index("sample_id").loc[train_manifest.sample_id].reset_index()
        test_manifest = manifest.loc[manifest.split.eq("test")].reset_index(drop=True)
        test = labeled.set_index("sample_id").loc[test_manifest.sample_id].reset_index()
        test_scores = np.zeros((len(test), 6))
        folds = group_folds(train_manifest, partition="train", count=5)
        for i, name in enumerate(TREE_BRANCHES):
            for number, (fitting, _) in enumerate(folds, 1):
                entries = [item for item in prior["fit_metadata"] if item["model"] == name and item["fold"] == number]
                if len(entries) != 1:
                    raise ValueError("Missing tree fold metadata")
                info = entries[0]
                model, _ = load_v3_fold(root / info["checkpoint"], info["checkpoint_sha256"],
                    train.iloc[fitting].loc[:, preparation["feature_order"]], prior["configuration"],
                    boundary=root / prior["artifact_path"], base_selection_rows=selection_rows)
                test_scores[:, i] += model.predict_proba(test.loc[:, preparation["feature_order"]]) / 5
        ft_test = align_gpu_scores(portable, mapping, "test", csv_gpu(gpu_directory / "ft_probs_test.csv"))
        vision_test = align_gpu_scores(portable, mapping, "test", csv_gpu(vision_dir / "vision_probs_test.csv"))
        test_scores[:, 4], test_scores[:, 5] = ft_test.loc[test.sample_id], vision_test.loc[test.sample_id]
        fused = stack.predict_proba(test_scores)
        baseline_cic = pd.read_csv(root / preparation["artifact_path"] / "v3_cic_saved_predictions.csv").set_index("sample_id")
        if sha256_file(root / preparation["artifact_path"] / "v3_cic_saved_predictions.csv") != preparation["baseline_cic_sha256"]:
            raise ValueError("Saved v3 comparator changed")
        comparison, routing = [], []
        for cohort, name in (("source_raw", "test_A_source_raw_4050"), ("cic", "test_B_cic_291")):
            mask = test_manifest.cohort.eq(cohort).to_numpy()
            rows, p = test.loc[mask], fused[mask]
            metrics = calibration_metrics(rows.Label, p, threshold=stack.threshold)
            closed, referred = fail_closed_routing(rows.Label, p, rows.sample_id, rows.parser_failed, threshold=stack.threshold)
            pure, _ = entropy_routing(rows.Label, p, rows.sample_id, threshold=stack.threshold)
            routing.extend([{"cohort": cohort, **closed}, {"cohort": cohort, **pure}])
            run.state["metrics"]["stacking_v4/" + name] = metrics
            run.state["metrics"]["stacking_v4/" + name + "_retained"] = closed["retained_metrics"]
            if cohort == "source_raw":
                baseline = preparation["source_baseline"]
            else:
                baseline = calibration_metrics(rows.Label, baseline_cic.loc[rows.sample_id].p_fused.to_numpy(),
                    threshold=preparation["source_baseline"]["threshold"])
            comparison.extend([{"model": "stacking_v3", "cohort": name, "rows": len(rows), "status": "saved_prediction_aggregation", **baseline},
                               {"model": "stacking_v4", "cohort": name, "rows": len(rows), "status": "evaluated_once_retrospective", **metrics}])
            pd.DataFrame({"sample_id": rows.sample_id, "Label": rows.Label, "p_fused": p, "referred": referred}).to_csv(
                run.artifacts / (name + "_predictions.csv"), index=False)
        pd.DataFrame(comparison).to_csv(run.report / "v3_v4_comparison.csv", index=False)
        write_json(run.report / "routing_analysis.json", routing)
        run.state.update(test_evaluation_count={"A": 1, "B": 1}, base_models_fitted_locally=0,
            threshold=stack.threshold, previous_v3_outcomes_exposed=True,
            notes="Retrospective dual-cohort v4 comparison, one evaluation each. Source4050 is raw-PDF cohort, not RIT table. V3 comparator uses saved predictions. No label reassignment; referrals do not count as corrected predictions.")
    return run.state
