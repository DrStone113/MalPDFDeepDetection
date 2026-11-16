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


def test_profile_worker_include_byte_images_flag_signature() -> None:
    import inspect
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.static.profile_worker import profile_pdf, _profile_child

    assert inspect.signature(extract_pdf).parameters["include_byte_images"].default is True
    assert inspect.signature(profile_pdf).parameters["include_byte_images"].default is True
    assert inspect.signature(_profile_child).parameters["include_byte_images"].default is True
