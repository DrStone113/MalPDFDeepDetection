"""Offline preparation tests using synthetic tables and inert PDF-like bytes."""

import hashlib
import json
from pathlib import Path
import runpy
import stat
import zipfile

import pandas as pd
import pytest

from malpdf.data import source_preparation as preparation
from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.experiments import protocol_g_benchmark as protocol_g
from malpdf.static.schema import RIT_FEATURES


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_zip(path, name, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)


@pytest.fixture
def sources(tmp_path, monkeypatch):
    root = tmp_path
    rows = []
    for label in (0, 1):
        for value in range(12):
            row = {column: label * 1000 + value + index for index, column in enumerate(RIT_FEATURES)}
            row["Label"] = label
            rows.extend([row.copy(), row.copy()])
    raw = pd.DataFrame(rows).to_csv(index=False).encode()
    rit_root = root / preparation.SOURCE_DIRECTORIES["rit_pdfmal_2026"]
    rit_archive = rit_root / "rit-pdfmal-2026.csv.zip"
    _write_zip(rit_archive, "rit-pdfmal-2026.csv", raw)
    csv_fixture = root / "fixture.csv"
    csv_fixture.write_bytes(raw)
    frame = load_rit_pdfmal(csv_fixture)
    manifest, split = create_rit_pdfmal_split(frame, seed=42)
    locked_bytes = manifest.to_csv(index=False, lineterminator="\r\n").encode()
    dataset_sha = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(protocol_g, "VERIFIED_DATASET_SHA256", dataset_sha)
    expected_partitions = {
        name: {"rows": item["row_count"], "groups": item["unique_group_count"], "label_0": item["benign"]["count"], "label_1": item["malicious"]["count"]}
        for name, item in split["split_statistics"].items()
    }
    monkeypatch.setattr(protocol_g, "EXPECTED_G_SPLIT", {**expected_partitions, "total_rows": len(frame), "total_groups": manifest.duplicate_group_id.nunique()})
    _write_json(root / "reports/experiments/protocol_g/seed42/split_summary.json", {"seed": 42, "dataset_sha256": dataset_sha, "split_manifest_sha256": hashlib.sha256(locked_bytes).hexdigest()})
    _write_json(root / "reports/rit-pdfmal-2026_split_report.json", {"seed": 42, "dataset": {"sha256": dataset_sha}})
    log = root / "reports/research_log.md"
    log.write_text("# Research log\n\nHistorical entry must survive.\n", encoding="utf-8")

    cic_root = root / preparation.SOURCE_DIRECTORIES["cic_evasive_kaggle"]
    cic_root.mkdir(parents=True)
    cic_path = cic_root / "PDFMalware2022.parquet"
    pd.DataFrame({"FileName": ["a" * 64, "b" * 64], "PdfSize": [1, 2], "Class": ["Benign", "Malicious"]}).to_parquet(cic_path, index=False)
    cic_archive = cic_root / "cic-evasive-pdfmal2022-v2.zip"
    _write_zip(cic_archive, cic_path.name, cic_path.read_bytes())
    cve_root = root / preparation.SOURCE_DIRECTORIES["cve_t4pdf"]
    cve_root.mkdir(parents=True)
    for index in range(3):
        (cve_root / f"synthetic_{index}.pdf").write_bytes(f"%PDF-1.4\n% synthetic {index}\n%%EOF\n".encode())
    for category, paths in {
        "rit_pdfmal_2026": [rit_archive],
        "cic_evasive_kaggle": [cic_path, cic_archive],
        "cve_t4pdf": sorted(cve_root.glob("*.pdf")),
    }.items():
        _write_json(root / "artifacts/dataset_acquisition" / category / "run_fixture/download_manifest.json", {"status": "completed", "destination": preparation.SOURCE_DIRECTORIES[category], "files": [{"path": path.name, "sha256": sha256_file(path)} for path in paths]})
    return root, frame, locked_bytes


def test_pipeline_restores_exact_lock_preserves_sources_and_keeps_cohorts_separate(sources):
    root, frame, expected = sources
    before = {path: sha256_file(path) for path in (root / "data/raw").rglob("*") if path.is_file()}
    historical_report = (root / "reports/rit-pdfmal-2026_split_report.json").read_bytes()
    log_before = (root / "reports/research_log.md").read_bytes()
    report = preparation.prepare_source_datasets(root, create_missing_manifest=True, run_id="run_one")
    assert report["status"] == "completed"
    saved = root / "data/processed/rit-pdfmal-2026_split_manifest.csv"
    assert saved.read_bytes() == expected
    g = report["datasets"]["rit"]["protocol_g"]
    assert g["match_fraction"] == 1.0 and g["manifest_created"]
    assert set(g["sample_id_overlap"].values()) == {0}
    assert all(item["is_valid"] for item in g["hard_validation"].values())
    assert report["datasets"]["rit"]["sample_count"] == len(frame)
    assert report["datasets"]["cic"]["protocol_g"]["status"] == "not_applicable"
    assert report["datasets"]["cve"]["labels"] == {"unlabeled": 3}
    assert report["datasets"]["cve"]["schema_status"] == "no_tabular_schema"
    assert all(sha256_file(path) == digest for path, digest in before.items())
    assert (root / "reports/rit-pdfmal-2026_split_report.json").read_bytes() == historical_report
    assert (root / "reports/research_log.md").read_bytes().startswith(log_before)
    assert (root / report["report_path"]).is_file()
    second = preparation.prepare_source_datasets(root, create_missing_manifest=True, run_id="run_two")
    assert not second["datasets"]["rit"]["protocol_g"]["manifest_created"]
    assert saved.read_bytes() == expected
    with pytest.raises(preparation.SourcePreparationError, match="Run path exists"):
        preparation.prepare_source_datasets(root, run_id="run_one")


def test_missing_manifest_is_reported_without_silently_creating_a_split(sources):
    root, _, _ = sources
    report = preparation.prepare_source_datasets(root, run_id="missing_manifest")
    assert report["status"] == "prepared_protocol_g_unverified"
    assert report["datasets"]["rit"]["protocol_g"]["match_fraction"] is None
    assert not (root / "data/processed/rit-pdfmal-2026_split_manifest.csv").exists()
    assert set(report["datasets"]) == {"rit", "cic", "cve"}


def test_requested_cve_labels_have_manifest_provenance_and_preserve_previous_runs(sources):
    root, _, expected = sources
    previous = preparation.prepare_source_datasets(root, create_missing_manifest=True, run_id="unlabeled_cve")
    preserved = {
        path: sha256_file(path)
        for directory in (root / "data/raw", root / previous["output_directory"], root / "artifacts/source_preparation/unlabeled_cve")
        for path in directory.rglob("*") if path.is_file()
    }
    log_before = (root / "reports/research_log.md").read_bytes()
    report = preparation.prepare_source_datasets(root, label_cve_malicious=True, run_id="labeled_cve")
    cve = report["datasets"]["cve"]
    manifest = pd.read_csv(root / cve["manifest_path"])
    assert report["status"] == "completed"
    assert list(manifest.columns) == ["sample_id", "Label", "pdf_relative_path", "pdf_sha256", "label_source"]
    assert len(manifest) == 3 and manifest.sample_id.is_unique
    assert manifest.Label.tolist() == [1, 1, 1]
    assert set(manifest.label_source) == {"user_requested_malicious"}
    assert cve["labels"] == {"malicious": 3}
    assert cve["label_distribution"] == {"malicious": {"count": 3, "fraction": 1.0}}
    assert cve["protocol_g"]["status"] == "not_applicable"
    assert sha256_file(root / cve["manifest_path"]) == cve["manifest_sha256"]
    for row in manifest.itertuples(index=False):
        assert sha256_file(root / row.pdf_relative_path) == row.pdf_sha256
        source = root / preparation.SOURCE_DIRECTORIES["cve_t4pdf"] / row.sample_id.removeprefix("cve_t4pdf:")
        assert sha256_file(source) == row.pdf_sha256
    inventory = json.loads((root / "artifacts/source_preparation/labeled_cve/cve_pdf_inventory.json").read_text())
    assert all(item["label"] == 1 and item["label_source"] == "user_requested_malicious" for item in inventory)
    methodology = json.loads((root / "artifacts/source_preparation/labeled_cve/locked_methodology.json").read_text())
    assert methodology["cve_label_assignment"] == cve["label_assignment"]
    assert all(sha256_file(path) == digest for path, digest in preserved.items())
    assert pd.read_csv(root / previous["datasets"]["cve"]["manifest_path"]).Label.isna().all()
    assert (root / "data/processed/rit-pdfmal-2026_split_manifest.csv").read_bytes() == expected
    log = (root / "reports/research_log.md").read_bytes()
    assert log.startswith(log_before) and b"user_requested_malicious" in log[len(log_before):]
    assert cve["manifest_path"].encode() in log[len(log_before):]


def test_cli_supports_explicit_malicious_cve_assignment(sources, monkeypatch, capsys):
    root, _, _ = sources
    config = root / "source_preparation.yaml"
    config.write_text("seed: 42\nlimits: {}\n", encoding="utf-8")
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/prepare_source_datasets.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    assert main(["--config", str(config), "--create-missing-manifest", "--label-cve-malicious", "--run-id", "cli_labeled"]) == 0
    stdout = capsys.readouterr().out
    assert "labels {'malicious': 3}" in stdout and "CVE manifest:" in stdout
    manifest = pd.read_csv(root / "data/processed/source_preparation/cli_labeled/cve_t4pdf/source_pdf_manifest.csv")
    assert manifest.Label.eq(1).all()


def test_cve_labeling_rejects_pdfs_outside_acquisition_inventory(sources):
    root, _, _ = sources
    unexpected = root / preparation.SOURCE_DIRECTORIES["cve_t4pdf"] / "unreviewed.pdf"
    unexpected.write_bytes(b"%PDF-1.4\n% inert synthetic fixture\n%%EOF\n")
    with pytest.raises(preparation.SourcePreparationError, match="CVE PDF inventory differs"):
        preparation.prepare_source_datasets(root, label_cve_malicious=True, run_id="unexpected_cve")
    assert not (root / "data/processed/source_preparation/unexpected_cve/cve_t4pdf").exists()
    report = json.loads((root / "artifacts/source_preparation/unexpected_cve/preparation_report.json").read_text())
    assert report["status"] == "failed"


def test_existing_tampered_manifest_is_never_overwritten_and_failure_is_logged(sources):
    root, _, _ = sources
    path = root / "data/processed/rit-pdfmal-2026_split_manifest.csv"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"tampered manifest\n")
    with pytest.raises(preparation.SourcePreparationError, match="historical checksum"):
        preparation.prepare_source_datasets(root, create_missing_manifest=True, run_id="bad_manifest")
    assert path.read_bytes() == b"tampered manifest\n"
    report = json.loads((root / "artifacts/source_preparation/bad_manifest/preparation_report.json").read_text())
    assert report["status"] == "failed"
    assert "preparation / failed" in (root / "reports/research_log.md").read_text()


def test_acquired_source_tampering_is_rejected_before_decompression(sources):
    root, _, _ = sources
    source = root / preparation.SOURCE_DIRECTORIES["rit_pdfmal_2026"] / "rit-pdfmal-2026.csv.zip"
    with source.open("ab") as output:
        output.write(b"source changed")
    with pytest.raises(preparation.SourcePreparationError, match="acquisition manifest"):
        preparation.prepare_source_datasets(root, run_id="tampered_source")
    assert not (root / "data/processed/source_preparation/tampered_source/rit").exists()


@pytest.mark.parametrize("member", ["../escape.csv", "/absolute.csv", "nested\\escape.csv", "unexpected.pdf"])
def test_archive_paths_and_unreviewed_members_are_rejected(tmp_path, member):
    archive = tmp_path / "source.zip"
    _write_zip(archive, member, b"feature,Label\n1,0\n")
    output = tmp_path / "processed/table.csv"
    with pytest.raises(preparation.SourcePreparationError):
        preparation.extract_table_archive(archive, output, expected_member="table.csv", limits=preparation.PreparationLimits())
    assert not output.exists()
    assert not (tmp_path.parent / "escape.csv").exists()


def test_symlink_and_high_ratio_archive_members_are_rejected(tmp_path):
    archive = tmp_path / "source.zip"
    member = zipfile.ZipInfo("table.csv")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(member, "../outside")
    target = tmp_path / "processed/table.csv"
    with pytest.raises(preparation.SourcePreparationError, match="Unsafe archive"):
        preparation.extract_table_archive(archive, target, expected_member="table.csv", limits=preparation.PreparationLimits())
    _write_zip(archive, "table.csv", b"0" * 100_000)
    with pytest.raises(preparation.SourcePreparationError, match="Unsafe archive"):
        preparation.extract_table_archive(archive, target, expected_member="table.csv", limits=preparation.PreparationLimits(max_compression_ratio=2))
    assert not target.exists()


def test_resource_caps_and_source_symlinks_fail_closed(sources):
    root, _, _ = sources
    with pytest.raises(preparation.SourcePreparationError, match="resource limit"):
        preparation.prepare_source_datasets(root, run_id="small_budget", limits=preparation.PreparationLimits(max_total_output_bytes=1))
    archive = root / preparation.SOURCE_DIRECTORIES["rit_pdfmal_2026"] / "rit-pdfmal-2026.csv.zip"
    moved = archive.with_name("saved.zip")
    archive.rename(moved)
    archive.symlink_to(moved)
    with pytest.raises(preparation.SourcePreparationError, match="Symbolic links"):
        preparation.prepare_source_datasets(root, run_id="symlink_source")


def test_seed_and_run_path_are_validated_before_output_creation(sources):
    root, _, _ = sources
    with pytest.raises(preparation.SourcePreparationError, match="seed"):
        preparation.prepare_source_datasets(root, seed=43)
    with pytest.raises(preparation.SourcePreparationError, match="Unsafe run"):
        preparation.prepare_source_datasets(root, run_id="../escape")
    with pytest.raises(preparation.SourcePreparationError, match="positive integers"):
        preparation.PreparationLimits(max_file_bytes=True)
    with pytest.raises(preparation.SourcePreparationError, match="explicit boolean"):
        preparation.prepare_source_datasets(root, label_cve_malicious=1)
    assert not (root / "data/processed").exists()


def test_wrong_csv_schema_is_rejected_before_manifest_publication(sources):
    root, _, _ = sources
    archive = root / preparation.SOURCE_DIRECTORIES["rit_pdfmal_2026"] / "rit-pdfmal-2026.csv.zip"
    _write_zip(archive, "rit-pdfmal-2026.csv", b"wrong,Label\n1,0\n2,1\n")
    reference = root / "artifacts/dataset_acquisition/rit_pdfmal_2026/run_fixture/download_manifest.json"
    data = json.loads(reference.read_text())
    data["files"][0]["sha256"] = sha256_file(archive)
    _write_json(reference, data)
    with pytest.raises(preparation.SourcePreparationError, match="header differs"):
        preparation.prepare_source_datasets(root, create_missing_manifest=True, run_id="bad_schema")
    assert not (root / "data/processed/rit-pdfmal-2026_split_manifest.csv").exists()


def test_parquet_extension_alone_does_not_establish_valid_format(sources):
    root, _, _ = sources
    cic_root = root / preparation.SOURCE_DIRECTORIES["cic_evasive_kaggle"]
    path = cic_root / "PDFMalware2022.parquet"
    path.write_bytes(b"This is ordinary synthetic text, not Parquet.")
    archive = cic_root / "cic-evasive-pdfmal2022-v2.zip"
    _write_zip(archive, path.name, path.read_bytes())
    reference = root / "artifacts/dataset_acquisition/cic_evasive_kaggle/run_fixture/download_manifest.json"
    data = json.loads(reference.read_text())
    data["files"] = [{"path": item.name, "sha256": sha256_file(item)} for item in (path, archive)]
    _write_json(reference, data)
    with pytest.raises(preparation.SourcePreparationError, match="Parquet signatures"):
        preparation.prepare_source_datasets(root, run_id="fake_parquet")
