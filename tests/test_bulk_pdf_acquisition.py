"""Synthetic unit tests for 20 GB-capped bulk PDF acquisition and deduplication."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/lab"))
import acquire_bulk_pdf_corpus as acq


def test_build_queue_enforces_hard_cap_and_packs_smallest_safedocs() -> None:
    z34 = [
        {"key": "CLEAN_PDF_9000_files.zip", "size": 683_344_001, "md5": "a" * 32, "url": "https://zenodo.org/1"},
        {"key": "MALWARE_PDF_PRE_04-2011.zip", "size": 129_118_746, "md5": "b" * 32, "url": "https://zenodo.org/2"},
        {"key": "2017-12-05-PDF.7z", "size": 258_034_184, "md5": "c" * 32, "url": "https://zenodo.org/3"},
    ]
    z15 = [{"key": "vapd_src.zip", "size": 1_486_391_345, "md5": "d" * 32, "url": "https://zenodo.org/4"}]
    hf = [{"path": f"sample/{i:06d}.pdf", "size": 500_000, "url": f"https://huggingface.co/{i}"} for i in range(4)]
    sd = [
        {"key": "big.zip", "name": "9999.zip", "size": 2_500_000_000, "url": "https://digitalcorpora.s3.amazonaws.com/big.zip"},
        {"key": "s1.zip", "name": "0001.zip", "size": 900_000_000, "url": "https://digitalcorpora.s3.amazonaws.com/s1.zip"},
        {"key": "s2.zip", "name": "0002.zip", "size": 950_000_000, "url": "https://digitalcorpora.s3.amazonaws.com/s2.zip"},
    ]
    queue = acq.build_queue(
        hard_cap=4_000_000_000,
        target_bytes=3_900_000_000,
        zenodo_3464032=z34,
        zenodo_15603773=z15,
        hf_govdocs=hf,
        safedocs_zips=sd,
    )
    assert queue["total_queued_bytes"] <= 4_000_000_000
    assert queue["safedocs_zip_count"] == 2
    assert [it["item_id"] for it in queue["items"][-2:]] == ["safedocs_0001", "safedocs_0002"]
    assert any(s["source"] == "cic_pdfmal_2022" for s in queue["skipped"])


def test_extract_zip_skips_unsafe_paths_pickles_and_dedups_summary(tmp_path: Path) -> None:
    pdf_a = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"
    pdf_b = b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n"
    archive = tmp_path / "vapd.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("data/benign/a.pdf", pdf_a)
        zf.writestr("data/mal/b.pdf", pdf_b)
        zf.writestr("../escape.pdf", pdf_a)
        zf.writestr("models/vapd_weights.pkl", b"pickle-placeholder")
        zf.writestr("data/labels.csv", "name,label\na.pdf,0\n")

    out_dir = tmp_path / "out"
    records, stats = acq.extract_zip_archive(
        archive,
        source="vapd_v5",
        label_source="vapd_v5_path_provenance",
        pdfs_root=out_dir / "pdfs",
        metadata_root=out_dir / "metadata",
        work_dir=tmp_path / "work",
    )
    assert stats["pdfs"] == 2
    assert stats["skipped_unsafe"] == 1
    assert stats["metadata_saved"] == 1
    assert not (out_dir / "metadata/vapd_v5/models/vapd_weights.pkl").exists()

    repo_root = tmp_path / "repo"
    cic_manifest = repo_root / acq.CIC_MANIFEST_REL
    cic_manifest.parent.mkdir(parents=True)
    sha_a = hashlib.sha256(pdf_a).hexdigest()
    sha_b = hashlib.sha256(pdf_b).hexdigest()
    with cic_manifest.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source", "source", "bytes", "magic_verified", "related_group_id"])
        w.writerow(["cic:a", "0", "data/raw/cic_pdf/a.pdf", sha_a, "", "", "", "", ""])

    with (out_dir / "manifest.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "source", "filename", "bytes", "label_source", "magic_offset0", "stored_relpath"])
        for r in records:
            w.writerow([r["sha256"], r["source"], r["filename"], r["bytes"], r["label_source"], r["magic_offset0"], r["stored_relpath"]])

    summary = acq.summarize_manifest(out_dir, repo_root, {"hard_cap_bytes": 20_000_000_000, "total_queued_bytes": 100, "skipped": []})
    assert summary["unique_new_batch_sha256"] == 2
    assert summary["overlap_with_cic_1452"] == 1
    assert summary["net_new_unique_vs_cic_1452"] == 1
    assert sha_b in {r["sha256"] for r in records}


def test_extract_zip_skips_matplotlib_and_doc_pdfs(tmp_path: Path) -> None:
    pdf_ok = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"
    archive = tmp_path / "vapd_non_dataset.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("vapd_src/data/PDFs/D1 dataset/train/ben/ok.pdf", pdf_ok)
        zf.writestr("vapd_src/Artifact_Documentation__USENIX_Security_25.pdf", pdf_ok)
        zf.writestr("vapd_src/env/lib/python3.11/site-packages/matplotlib/mpl-data/images/home.pdf", pdf_ok)

    out_dir = tmp_path / "out"
    records, stats = acq.extract_zip_archive(
        archive,
        source="vapd_v5",
        label_source="vapd_v5_path_provenance",
        pdfs_root=out_dir / "pdfs",
        metadata_root=out_dir / "metadata",
        work_dir=tmp_path / "work",
    )
    assert stats["pdfs"] == 1
    assert stats["skipped_non_pdf"] == 2
    assert len(records) == 1
    assert records[0]["filename"].endswith("ok.pdf")


def test_is_non_dataset_member_and_skip_json() -> None:
    assert acq.is_non_dataset_member("vapd_v5", "vapd_src/Artifact_Documentation__USENIX_Security_25.pdf")
    assert acq.is_non_dataset_member("vapd_v5", "vapd_src/env/lib/python3.11/site-packages/matplotlib/mpl-data/images/back.pdf")
    assert not acq.is_non_dataset_member("vapd_v5", "vapd_src/data/PDFs/D1 dataset/train/mal/sample.pdf")
    assert ".json" in acq.METADATA_SUFFIXES
