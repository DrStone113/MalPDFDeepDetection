"""Unit tests for hybrid CPU+GPU extraction acceleration, clean manifest hygiene, and chunked export."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest
import torch

from malpdf.extraction.bulk_pipeline import (
    CleanCorpusEntry,
    build_clean_corpus_manifest,
    run_hybrid_bulk_extraction,
)
from malpdf.extraction.gpu_accel import (
    byte_transition_matrices_batch,
    compute_rwse_batch_torch,
    hardware_profile,
    resolve_extraction_device,
    window_entropy_batch,
)
from malpdf.extraction.graph_projection_v2 import (
    compute_rwse_v2,
    project_graph_bundle_v2,
    project_graph_bundles_batch_v2,
)
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.static.markov import byte_transition_matrix


def _synthetic_bundle(sha256: str, *, with_nodes: bool = True) -> dict:
    base = normalize_profile(
        {
            "status": "complete",
            "errors": [],
            "worker_cleanup_complete": True,
            "worker_exit_code": 0,
            "last_stage": "parse_pdf",
        },
        sha256,
        "deep-static",
    )
    base["status"] = "bounded_complete"
    base["extraction_status"] = "bounded_complete"
    base["coverage_report"]["extraction_status"] = "bounded_complete"
    base["coverage_report"]["worker"]["status"] = "complete"
    base["coverage_report"]["worker"]["worker_cleanup_complete"] = True
    if not with_nodes:
        base["evidence_store"]["records"] = []
        base["evidence_store"]["edges"] = []
        return base
    records = [
        {
            "evidence_id": f"cat:{sha256}",
            "kind": "catalog",
            "backend": "pypdf",
            "observation_status": "observed",
            "object_number": 1,
            "generation": 0,
            "revision": None,
            "byte_offset_start": 10,
            "byte_offset_end": None,
            "filter_chain": None,
            "is_synthetic_repaired": False,
            "details": {"projection": {"value_type": "dict", "projection_complete": True}},
        },
        {
            "evidence_id": f"act:{sha256}",
            "kind": "action",
            "backend": "pypdf",
            "observation_status": "observed",
            "object_number": 2,
            "generation": 0,
            "revision": None,
            "byte_offset_start": None,
            "byte_offset_end": None,
            "filter_chain": None,
            "is_synthetic_repaired": False,
            "details": {"projection": {"value_type": "dict", "projection_complete": True}, "raw_bytes": 128},
        },
    ]
    edges = [
        {
            "id": f"e0:{sha256}",
            "source": f"cat:{sha256}",
            "target": f"act:{sha256}",
            "kind": "indirect_reference",
            "status": "verified",
        }
    ]
    base["evidence_store"]["records"] = records
    base["evidence_store"]["edges"] = edges
    return base


def _devices_to_test() -> list[str]:
    devices = ["cpu"]
    if torch.cuda.is_available():
        devices.append("cuda")
    return devices


@pytest.mark.parametrize("device", _devices_to_test())
def test_compute_rwse_batch_matches_reference(device: str) -> None:
    graphs = [
        (0, [], []),
        (1, [], []),
        (4, [0, 1, 2, 1], [1, 2, 0, 2]),
        (6, [0, 1, 2, 3, 4], [1, 2, 0, 4, 3]),
    ]
    batched = compute_rwse_batch_torch(graphs, steps=16, device=device, max_batch_graphs=2)
    assert len(batched) == len(graphs)
    for (n, src, dst), got in zip(graphs, batched):
        ref = compute_rwse_v2(n, src, dst, steps=16)
        assert len(got) == len(ref) == n
        for r_row, g_row in zip(ref, got):
            assert np.allclose(g_row, r_row, rtol=1e-5, atol=1e-5)


@pytest.mark.parametrize("device", _devices_to_test())
def test_byte_transition_matrices_batch_matches_markov_and_respects_boundaries(device: str) -> None:
    rng = np.random.default_rng(123)
    bufs = [
        b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n",
        rng.integers(0, 256, size=2048, dtype=np.uint8).tobytes(),
        b"\x00\xff\x00\xff\x10\x20",
    ]
    batched = byte_transition_matrices_batch(bufs, device=device, max_batch_bytes=700, max_batch_samples=2)
    assert len(batched) == len(bufs)
    for buf, mat in zip(bufs, batched):
        ref = byte_transition_matrix(buf)
        assert mat.dtype == np.float32
        assert mat.shape == (256, 256)
        assert np.allclose(mat, ref, rtol=1e-6, atol=1e-6)

    with pytest.raises(ValueError, match="At least two bytes"):
        byte_transition_matrices_batch([b"A"], device=device)


@pytest.mark.parametrize("device", _devices_to_test())
def test_window_entropy_and_raw_layout_parity(device: str) -> None:
    rng = np.random.default_rng(77)
    data = rng.integers(0, 256, size=300_000, dtype=np.uint8).tobytes()
    layout = inspect_raw_layout(data)
    global_ent, win_ents = window_entropy_batch(data, window_bytes=4096, device=device)
    assert np.isclose(global_ent, layout["entropy"], atol=1e-9)
    ref_wins = [w["entropy"] for w in layout["entropy_windows"]]
    assert len(win_ents) == len(ref_wins)
    assert np.allclose(win_ents, ref_wins, atol=1e-9)


def test_hardware_profile_and_device_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    assert resolve_extraction_device("cuda").type == "cpu"
    assert resolve_extraction_device("auto").type == "cpu"
    info = hardware_profile("auto")
    assert info["resolved_device"] == "cpu"
    assert info["cuda_available"] is False


@pytest.mark.parametrize("device", _devices_to_test())
def test_project_graph_bundles_batch_matches_single_projection(device: str) -> None:
    shas = ["1" * 64, "2" * 64, "3" * 64]
    bundles = [
        _synthetic_bundle(shas[0], with_nodes=True),
        _synthetic_bundle(shas[1], with_nodes=False),
        _synthetic_bundle(shas[2], with_nodes=True),
    ]
    batched = project_graph_bundles_batch_v2(list(zip(bundles, shas)), device=device)
    for bundle, sha, proj in zip(bundles, shas, batched):
        single = project_graph_bundle_v2(bundle, sha)
        assert proj["graph"]["num_nodes"] == single["graph"]["num_nodes"]
        assert proj["graph"]["edge_src"] == single["graph"]["edge_src"]
        assert np.allclose(proj["graph"]["node_features"], single["graph"]["node_features"], rtol=1e-5, atol=1e-5)


def test_build_clean_corpus_manifest_filters_junk_and_resolves_labels(tmp_path: Path) -> None:
    pdfs_dir = tmp_path / "pdfs"
    pdfs_dir.mkdir()

    def make_pdf(name: str, body: bytes) -> str:
        sha = hashlib.sha256(body).hexdigest()
        rel = pdfs_dir / f"{sha}.pdf"
        rel.write_bytes(body)
        return sha

    sha_cic_benign = make_pdf("cic0", b"%PDF-1.4\n%cic_benign\n%%EOF\n")
    sha_vapd_benign = make_pdf("vapd0", b"%PDF-1.4\n%vapd_benign\n%%EOF\n")
    sha_mal_2011 = make_pdf("mal11", b"%PDF-1.4\n%mal_2011\n%%EOF\n")
    sha_z17_only = make_pdf("z17", b"%PDF-1.4\n%z17_only\n%%EOF\n")
    sha_safedocs = make_pdf("sd", b"%PDF-1.4\n%safedocs\n%%EOF\n")
    sha_conflict = make_pdf("conf", b"%PDF-1.4\n%conflict\n%%EOF\n")
    sha_json = make_pdf("json", b'{"header": "%PDF-1.4"}')
    sha_mpl = make_pdf("mpl", b"%PDF-1.4\n%matplotlib_icon\n%%EOF\n")

    bulk_csv = tmp_path / "manifest.csv"
    with bulk_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "source", "filename", "bytes", "label_source", "magic_offset0", "stored_relpath"])
        w.writerow([sha_cic_benign, "zenodo_3464032_malware_2017", f"PDF/{sha_cic_benign}", 28, "publisher_reported_malicious_virustotal_2017", "True", f"pdfs/{sha_cic_benign}.pdf"])
        w.writerow([sha_vapd_benign, "zenodo_3464032_malware_2017", f"PDF/{sha_vapd_benign}", 28, "publisher_reported_malicious_virustotal_2017", "True", f"pdfs/{sha_vapd_benign}.pdf"])
        w.writerow([sha_vapd_benign, "vapd_v5", "vapd_src/data/PDFs/D1 dataset/train/ben/a.pdf", 28, "vapd_v5_path_provenance:vapd_src/data/PDFs/D1 dataset/train/ben/a.pdf", "True", f"pdfs/{sha_vapd_benign}.pdf"])
        w.writerow([sha_mal_2011, "zenodo_3464032_malware_2011", "mal.pdf", 25, "publisher_reported_malicious_virustotal_2011", "True", f"pdfs/{sha_mal_2011}.pdf"])
        w.writerow([sha_z17_only, "zenodo_3464032_malware_2017", f"PDF/{sha_z17_only}", 26, "publisher_reported_malicious_virustotal_2017", "True", f"pdfs/{sha_z17_only}.pdf"])
        w.writerow([sha_safedocs, "safedocs_0928", "0928/doc.pdf", 26, "unlabeled_safedocs_cc_main_2021_31", "True", f"pdfs/{sha_safedocs}.pdf"])
        w.writerow([sha_conflict, "vapd_v5", "vapd_src/data/PDFs/D1 dataset/train/ben/c.pdf", 26, "vapd_v5_path_provenance:vapd_src/data/PDFs/D1 dataset/train/ben/c.pdf", "True", f"pdfs/{sha_conflict}.pdf"])
        w.writerow([sha_conflict, "vapd_v5", "vapd_src/data/PDFs/D1 dataset/train/mal/c.pdf", 26, "vapd_v5_path_provenance:vapd_src/data/PDFs/D1 dataset/train/mal/c.pdf", "True", f"pdfs/{sha_conflict}.pdf"])
        w.writerow([sha_json, "zenodo_3464032_malware_2017", f"PDF/{sha_json}.json", 22, "publisher_reported_malicious_virustotal_2017", "False", f"pdfs/{sha_json}.pdf"])
        w.writerow([sha_mpl, "vapd_v5", "vapd_src/env/lib/python3.11/site-packages/matplotlib/mpl-data/images/home.pdf", 32, "vapd_v5_path_provenance", "True", f"pdfs/{sha_mpl}.pdf"])

    cic_csv = tmp_path / "cic_manifest.csv"
    with cic_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "Label", "split", "pdf_sha256"])
        w.writerow(["cic_0", "0", "validation", sha_cic_benign])

    entries, stats = build_clean_corpus_manifest([bulk_csv], base_dir=tmp_path, cic_manifest_csv=cic_csv)
    by_sha = {e.sha256: e for e in entries}

    assert sha_json not in by_sha
    assert sha_mpl not in by_sha
    assert stats["skipped_non_dataset"] == 2
    assert by_sha[sha_cic_benign].label == 0
    assert by_sha[sha_cic_benign].split == "validation"
    assert by_sha[sha_vapd_benign].label == 0
    assert by_sha[sha_mal_2011].label == 1
    assert by_sha[sha_z17_only].label is None
    assert by_sha[sha_z17_only].label_source == "unverified_zenodo_2017"
    assert by_sha[sha_safedocs].label is None
    assert by_sha[sha_conflict].label is None
    assert by_sha[sha_conflict].label_conflict is True


def test_run_hybrid_bulk_extraction_chunks_resumes_and_prunes(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    entries: list[CleanCorpusEntry] = []
    for idx in range(5):
        payload = f"%PDF-1.4\n%sample_{idx}\n%%EOF\n".encode("ascii")
        sha = hashlib.sha256(payload).hexdigest()
        pdf_path = raw_dir / f"{sha}.pdf"
        pdf_path.write_bytes(payload)
        entries.append(CleanCorpusEntry(
            index=idx,
            sha256=sha,
            pdf_path=pdf_path,
            stored_relpath=f"{sha}.pdf",
            source="synthetic",
            label=idx % 2 if idx < 4 else None,
            label_source="synthetic_test",
        ))

    calls: list[int] = []

    def fake_extractor(chunk_entries, *, limits, workers):
        for item in chunk_entries:
            calls.append(item.index)
            yield item.index, _synthetic_bundle(item.sha256, with_nodes=(item.index != 2))

    out_dir = tmp_path / "out"
    summary = run_hybrid_bulk_extraction(
        entries,
        base_dir=raw_dir,
        output_dir=out_dir,
        workers=2,
        chunk_size=2,
        device="auto",
        include_markov=True,
        prune_raw_after_chunk=True,
        extractor_fn=fake_extractor,
    )
    assert calls == [0, 1, 2, 3, 4]
    assert summary["planned_denominator"] == 5
    assert summary["gnn_exported_graphs"] == 4
    assert summary["unavailable_empty_graphs"] == 1
    assert summary["chunks_completed"] == 3
    assert summary["markov_shard_count"] == 3
    assert not any(e.pdf_path.exists() for e in entries)

    with gzip.open(out_dir / "final/hetero_graphs_v2.jsonl.gz", "rt", encoding="utf-8") as fh:
        graphs = [json.loads(line) for line in fh if line.strip()]
    assert len(graphs) == 4
    assert all(g["node_feature_dim"] == 23 for g in graphs)

    markov_manifest = json.loads((out_dir / "final/markov_manifest.json").read_text(encoding="utf-8"))
    total_mats = 0
    for shard in markov_manifest["shards"]:
        npz_path = (out_dir / "final" / shard["npz_relpath"]).resolve()
        with np.load(npz_path, allow_pickle=False) as data:
            total_mats += data["matrices"].shape[0]
            assert data["matrices"].dtype == np.float32
    assert total_mats == 5

    calls.clear()
    summary2 = run_hybrid_bulk_extraction(
        entries,
        base_dir=raw_dir,
        output_dir=out_dir,
        workers=2,
        chunk_size=2,
        device="auto",
        include_markov=True,
        extractor_fn=fake_extractor,
    )
    assert calls == []
    assert summary2["gnn_exported_graphs"] == 4


def test_profile_worker_include_byte_images_and_coalesce_flag_signatures() -> None:
    import inspect
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.static.profile_worker import profile_pdf, _profile_child

    assert inspect.signature(extract_pdf).parameters["include_byte_images"].default is True
    assert inspect.signature(profile_pdf).parameters["include_byte_images"].default is True
    assert inspect.signature(_profile_child).parameters["include_byte_images"].default is True
    assert inspect.signature(extract_pdf).parameters["coalesce_checkpoints"].default is False
    assert inspect.signature(profile_pdf).parameters["coalesce_checkpoints"].default is False
    assert inspect.signature(_profile_child).parameters["coalesce_checkpoints"].default is False


def test_checkpoint_scheduler_coalesces_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from malpdf.extraction.checkpointing import CheckpointScheduler
    from malpdf.static.code_inspector import CodeInspectionLimits

    monkeypatch.delenv("MALPDF_COALESCE_CHECKPOINTS", raising=False)
    default_sched = CheckpointScheduler(CodeInspectionLimits(), clock=lambda: 0.0)
    assert default_sched.coalesce is False

    monkeypatch.setenv("MALPDF_COALESCE_CHECKPOINTS", "1")
    coalesced_sched = CheckpointScheduler(CodeInspectionLimits(), clock=lambda: 0.0)
    assert coalesced_sched.coalesce is True
    assert coalesced_sched.due() is True
    coalesced_sched.completed()
    assert coalesced_sched.due() is False
    assert coalesced_sched.due(force=True) is True


def test_evidence_policy_v9_avoids_heavy_ml_imports() -> None:
    import subprocess
    import sys

    probe = (
        "import sys, malpdf.inference.evidence_policy_v9 as ep; "
        "ep.derive_feature_provenance({}, {}); "
        "loaded = [m for m in ('sklearn', 'scipy', 'joblib', 'xgboost', 'lightgbm', 'catboost') if m in sys.modules]; "
        "assert not loaded, f'Unexpected ML imports: {loaded}'"
    )
    subprocess.run([sys.executable, "-c", probe], check=True)


def test_bulk_pipeline_enables_coalesced_checkpoints_and_defers_cuda(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import malpdf.extraction.batch as batch_mod
    import malpdf.extraction.bulk_pipeline as bulk_mod

    payload = b"%PDF-1.4\n%bulk_opts\n%%EOF\n"
    sha = hashlib.sha256(payload).hexdigest()
    pdf_path = tmp_path / f"{sha}.pdf"
    pdf_path.write_bytes(payload)
    entry = CleanCorpusEntry(
        index=0,
        sha256=sha,
        pdf_path=pdf_path,
        stored_relpath=f"{sha}.pdf",
        source="synthetic",
        label=0,
        label_source="synthetic_test",
    )

    events: list[str] = []
    seen_opts: dict = {}

    def fake_extract_pdfs(paths, **opts):
        events.append("extract_pdfs")
        seen_opts.update(opts)
        yield 0, _synthetic_bundle(sha, with_nodes=True)

    def fake_resolve(device):
        events.append("resolve_device")
        return torch.device("cpu")

    def fake_hw(device):
        events.append("hardware_profile")
        return {
            "requested_device": str(device),
            "resolved_device": "cpu",
            "cuda_available": False,
            "cpu_count": 1,
            "torch_version": torch.__version__,
            "gpu_name": None,
            "gpu_memory_bytes": None,
        }

    monkeypatch.setattr(batch_mod, "extract_pdfs", fake_extract_pdfs)
    monkeypatch.setattr(bulk_mod, "resolve_extraction_device", fake_resolve)
    monkeypatch.setattr(bulk_mod, "hardware_profile", fake_hw)

    summary = run_hybrid_bulk_extraction(
        [entry],
        base_dir=tmp_path,
        output_dir=tmp_path / "out",
        workers=1,
        chunk_size=1,
        device="auto",
        include_markov=False,
    )
    assert summary["gnn_exported_graphs"] == 1
    assert seen_opts["coalesce_checkpoints"] is True
    assert seen_opts["include_byte_images"] is False
    assert events == ["extract_pdfs", "resolve_device", "hardware_profile"]


def test_cloud_script_uses_relative_arlington_lock_path() -> None:
    import importlib.util

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "cloud_bulk_extract.py"
    spec = importlib.util.spec_from_file_location("cloud_bulk_extract_check", script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert isinstance(mod.ARLINGTON_LOCK_REL, str)
    assert not Path(mod.ARLINGTON_LOCK_REL).is_absolute()
    assert mod.ARLINGTON_LOCK_REL == "configs/arlington.lock.json"


def test_cloud_bulk_extract_spawn_worker_avoids_torch_and_ml_imports(tmp_path: Path) -> None:
    import subprocess
    import sys

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "cloud_bulk_extract.py"
    out_file = tmp_path / "spawn_modules.json"
    child_code = (
        "import json, sys; from pathlib import Path; "
        "bad = sorted({'torch', 'numpy', 'scipy', 'sklearn', 'joblib', 'malpdf.extraction.gpu_accel'} & set(sys.modules)); "
        f"Path({str(out_file)!r}).write_text(json.dumps(bad), encoding='utf-8')"
    )
    parent_code = (
        "import importlib.util, multiprocessing, sys\n"
        f"spec = importlib.util.spec_from_file_location('cloud_bulk_probe', {str(script_path)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "assert 'torch' not in sys.modules\n"
        "assert 'malpdf.extraction.gpu_accel' not in sys.modules\n"
        f"sys.modules['__main__'].__file__ = {str(script_path)!r}\n"
        "ctx = multiprocessing.get_context('spawn')\n"
        f"proc = ctx.Process(target=exec, args=({child_code!r},))\n"
        "proc.start()\n"
        "proc.join(timeout=30)\n"
        "assert proc.exitcode == 0, f'exitcode={proc.exitcode}'\n"
    )
    subprocess.run([sys.executable, "-c", parent_code], check=True)
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded == [], f"Unexpected heavy modules in spawn worker: {loaded}"

    probe_bp = (
        "import sys, malpdf.extraction.bulk_pipeline; "
        "bad = sorted({'torch', 'sklearn', 'scipy', 'joblib', 'malpdf.extraction.gpu_accel'} & set(sys.modules)); "
        "assert not bad, f'Unexpected heavy imports in bulk_pipeline: {bad}'"
    )
    subprocess.run([sys.executable, "-c", probe_bp], check=True)


def test_build_clean_corpus_manifest_supports_multi_cohort_v4_and_cic_split(tmp_path: Path) -> None:
    raw_public = tmp_path / "data" / "raw" / "public_pdf_sources"
    raw_cic = tmp_path / "data" / "raw" / "cic_pdf"
    raw_bulk = tmp_path / "data" / "raw" / "bulk" / "pdfs"
    for folder in (raw_public, raw_cic, raw_bulk):
        folder.mkdir(parents=True)

    def make_file(folder: Path, name: str, body: bytes) -> tuple[str, Path]:
        sha = hashlib.sha256(body).hexdigest()
        target = folder / f"{name}.pdf"
        target.write_bytes(body)
        return sha, target

    sha_cic, _ = make_file(raw_cic, "cic", b"%PDF-1.4\n%cic\n%%EOF\n")
    sha_clean, _ = make_file(raw_public, "clean9000", b"%PDF-1.4\n%c9000\n%%EOF\n")
    sha_mal, _ = make_file(raw_public, "mal2011", b"%PDF-1.4\n%m2011\n%%EOF\n")
    sha_contagio, _ = make_file(raw_public, "contagio", b"%PDF-1.4\n%contagio\n%%EOF\n")
    sha_gov, _ = make_file(raw_bulk, "gov", b"%PDF-1.4\n%gov\n%%EOF\n")

    source_csv = tmp_path / "source_manifest.csv"
    with source_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source", "source"])
        w.writerow(["cic_0", "1", "data/raw/cic_pdf/cic.pdf", sha_cic, "verified", ""])
        w.writerow(["pub_c", "0", "data/raw/public_pdf_sources/clean9000.pdf", sha_clean, "publisher_reported_benign_not_independently_verified", "zenodo_clean_pdf_9000"])
        w.writerow(["pub_m", "1", "data/raw/public_pdf_sources/mal2011.pdf", sha_mal, "publisher_reported_malicious_not_independently_verified", "zenodo_malware_pdf_2011"])
        w.writerow(["pub_u", "", "data/raw/public_pdf_sources/contagio.pdf", sha_contagio, "unlabeled_public_contagio_archive", "contagio_s3_pdf_sample"])

    split_csv = tmp_path / "split_manifest.csv"
    with split_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "duplicate_group_id", "split", "Label", "cohort"])
        w.writerow(["cic_0", "d0", "test", "1", "cic"])
        w.writerow(["pub_m", "d1", "train", "1", "source_raw"])

    bulk_csv = tmp_path / "data" / "raw" / "bulk" / "manifest.csv"
    with bulk_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "source", "filename", "bytes", "label_source", "magic_offset0", "stored_relpath"])
        w.writerow([sha_gov, "govdocs1_sample", "sample/gov.pdf", 21, "unverified_govdocs1_sample", "True", "pdfs/gov.pdf"])

    entries, _ = build_clean_corpus_manifest(
        [source_csv, bulk_csv],
        base_dir=tmp_path,
        cic_manifest_csv=source_csv,
        cic_split_manifest_csv=split_csv,
    )
    by_sha = {e.sha256: e for e in entries}
    assert set(by_sha) == {sha_cic, sha_clean, sha_mal, sha_contagio, sha_gov}
    assert by_sha[sha_cic].label == 1 and by_sha[sha_cic].split == "test"
    assert by_sha[sha_cic].label_source == "cic_protocol_g_verified"
    assert by_sha[sha_clean].label == 0
    assert by_sha[sha_clean].label_source == "publisher_reported_benign_clean_9000"
    assert by_sha[sha_mal].label == 1
    assert by_sha[sha_mal].split is None
    assert by_sha[sha_mal].label_source == "publisher_reported_malicious_2011"
    assert by_sha[sha_contagio].label is None
    assert by_sha[sha_gov].label is None
