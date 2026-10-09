"""Offline acquisition checks use synthetic PDF-like bytes and mocked HTTP."""

import copy
import base64
import hashlib
import io
import json
from pathlib import Path
import runpy
import socket
import stat
from types import SimpleNamespace
from urllib.request import Request
import zipfile
import zlib

import pytest

from malpdf.data import raw_downloads as raw

PDF = b"%PDF-1.4\n% synthetic inert fixture\n%%EOF\n"
# Fixed ZipCrypto archive of the inert PDF above; password is synthetic. Tests
# neither invoke archive utilities nor access an external corpus.
ENCRYPTED = base64.b64decode("UEsDBAoACQAAADJjQl1e9ybsNQAAACkAAAALABwAZml4dHVyZS5wZGZVVAkAA8Civ2rAor9qdXgLAAEE6AMAAAToAwAAROoA5PmYcCsq1lzlJfgSNE3F3vSc0errm0EFwDVhsKf9nEC65LRVmOFljHBw48XqXcRJmJBQSwcIXvcm7DUAAAApAAAAUEsBAh4DCgAJAAAAMmNCXV73Juw1AAAAKQAAAAsAGAAAAAAAAQAAAKaBAAAAAGZpeHR1cmUucGRmVVQFAAPAor9qdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEAUQAAAIoAAAAAAA==")
SOURCE = {"name": "fixture", "url": "https://example.org/fixture.pdf", "kind": "pdf",
          "reference": "synthetic fixture", "label": None, "label_source": "synthetic_unlabeled"}


class Response(io.BytesIO):
    def __init__(self, data, *, headers=None, status=200, url=SOURCE["url"]):
        super().__init__(data)
        self.headers = headers if headers is not None else {"Content-Length": str(len(data))}
        self.status = status
        self.url = url

    def geturl(self):
        return self.url


@pytest.fixture
def network(monkeypatch):
    monkeypatch.setattr(raw.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    response_factory = {"make": lambda: Response(PDF)}
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            return response_factory["make"]()

    monkeypatch.setattr(raw, "build_opener", lambda *a: Opener())
    return response_factory, calls


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports/research_log.md").write_text("Historical entry.\n")
    monkeypatch.setattr(raw.subprocess, "check_output", lambda *a, **k: "a" * 40)
    monkeypatch.setattr(raw.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(raw, "repository_git_state", lambda *a: {"status": "dirty", "porcelain_entries": [" M fixture"]})
    monkeypatch.setattr(raw.importlib.metadata, "version", lambda *a: "test")
    return tmp_path


def config(*sources, **limits):
    return {"allowed_hosts": ["example.org"], "sources": list(sources or [copy.deepcopy(SOURCE)]), "limits": limits}


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)


@pytest.mark.parametrize("url", ["http://example.org/a", "file:///a.pdf", "https://evil.org/a", "https://user:secret@example.org/a", "https://example.org:444/a", "https://example.org/a?token=secret", "https://127.0.0.1/a", "https://localhost/a"])
def test_unreviewed_local_insecure_or_credential_urls_are_refused(url):
    with pytest.raises(ValueError):
        raw.validate_url(url, ["example.org", "127.0.0.1", "localhost"])


def test_private_dns_and_redirect_are_refused(monkeypatch):
    monkeypatch.setattr(raw.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))])
    with pytest.raises(ValueError, match="nonpublic"):
        raw.validate_url(SOURCE["url"], ["example.org"], resolve=True)
    with pytest.raises(ValueError):
        raw._ReviewedRedirects(["example.org"]).redirect_request(Request(SOURCE["url"]), None, 302, "", {}, "https://evil.org/a")


def test_download_matches_publisher_size_and_hashes(tmp_path, network):
    source = {**SOURCE, "expected_bytes": len(PDF), "expected_sha256": hashlib.sha256(PDF).hexdigest(), "expected_md5": hashlib.md5(PDF).hexdigest()}
    destination = tmp_path / "payload.download"
    result = raw.download_file(source, destination, ["example.org"], raw.DownloadLimits(), remaining_bytes=1000)
    assert destination.read_bytes() == PDF
    assert result["sha256"] == source["expected_sha256"] and result["publisher_sha256_available"]
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="overwrite"):
        raw.download_file(source, destination, ["example.org"], raw.DownloadLimits(), remaining_bytes=1000)


@pytest.mark.parametrize("case", ["false_length", "oversize", "truncated", "checksum", "partial_http", "encoded"])
def test_bad_transfer_never_publishes_verified_payload(case, tmp_path, network):
    factory, _ = network
    source = SOURCE.copy()
    if case == "false_length":
        factory["make"] = lambda: Response(PDF, headers={"Content-Length": "1"})
    elif case == "oversize":
        factory["make"] = lambda: Response(PDF * 20, headers={})
    elif case == "truncated":
        factory["make"] = lambda: Response(PDF, headers={"Content-Length": "100"})
    elif case == "checksum":
        source["expected_sha256"] = "0" * 64
    elif case == "partial_http":
        factory["make"] = lambda: Response(PDF, status=206)
    else:
        factory["make"] = lambda: Response(PDF, headers={"Content-Encoding": "gzip"})
    output = tmp_path / "payload.download"
    with pytest.raises(ValueError):
        raw.download_file(source, output, ["example.org"], raw.DownloadLimits(max_pdf_bytes=100), remaining_bytes=1000)
    assert not output.exists()


def test_archive_magic_is_checked_without_trusting_filename(tmp_path):
    archive = tmp_path / "source.zip"
    make_zip(archive, [("corpus/", b""), ("corpus/opaque_hash", PDF), ("corpus/fake.pdf", b"<html>Error</html>"), ("corpus/duplicate.pdf", PDF)])
    records = []
    result = raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000, record=records.append)
    assert result == {"members": 3, "accepted": 2, "rejected": 1, "duplicates": 1, "pdf_bytes": len(PDF)}
    outputs = list((tmp_path / "pdfs").glob("*.pdf"))
    assert len(outputs) == 1 and outputs[0].name == hashlib.sha256(PDF).hexdigest() + ".pdf"
    assert outputs[0].read_bytes() == PDF
    assert records[1]["status"] == "rejected"


@pytest.mark.parametrize("name", ["../escape.pdf", "/escape.pdf", "folder\\escape.pdf", "C:escape.pdf"])
def test_entire_unsafe_directory_is_rejected_before_extraction(name, tmp_path):
    archive = tmp_path / "source.zip"
    make_zip(archive, [("good.pdf", PDF), (name, PDF)])
    with pytest.raises(ValueError, match="Unsafe"):
        raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000)
    assert not (tmp_path / "pdfs").exists()


def test_symlink_members_and_encrypted_members_fail_closed(tmp_path):
    archive = tmp_path / "source.zip"
    member = zipfile.ZipInfo("link.pdf")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(member, PDF)
    with pytest.raises(ValueError, match="Unsafe"):
        raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000)
    make_zip(archive, [("test.pdf", PDF)])
    data = bytearray(archive.read_bytes())
    directory = data.index(b"PK\x01\x02")
    data[directory + 8] |= 1
    archive.write_bytes(data)
    with pytest.raises(ValueError, match="password"):
        raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000)


def test_archive_member_and_output_caps_before_decompression(tmp_path):
    archive = tmp_path / "source.zip"
    make_zip(archive, [("one.pdf", PDF), ("two.pdf", PDF)])
    for limits, budget in [(raw.DownloadLimits(max_archive_members=1), 10000), (raw.DownloadLimits(), 1)]:
        with pytest.raises(ValueError):
            raw.extract_pdf_archive(archive, tmp_path / "pdfs", limits, remaining_bytes=budget)
    assert not (tmp_path / "pdfs").exists()


@pytest.mark.parametrize("password", [b"synthetic", b"wrong"])
def test_real_zipcrypto_password_and_crc_validation(password, tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(ENCRYPTED)
    if password == b"wrong":
        with pytest.raises(ValueError, match="decryption failed"):
            raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000, password=password)
        assert not list((tmp_path / "pdfs").glob("*.pdf"))
    else:
        result = raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000, password=password)
        assert result["accepted"] == 1
        assert list((tmp_path / "pdfs").glob("*.pdf"))[0].read_bytes() == PDF


def test_pdf_cap_compression_cap_and_leading_magic_rejections(tmp_path):
    archive = tmp_path / "source.zip"
    make_zip(archive, [("huge.pdf", b"%PDF-" + b"A" * 10000), ("leading.pdf", b" " + PDF)])
    result = raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(max_compression_ratio=2), remaining_bytes=100000)
    assert result["accepted"] == 0 and result["rejected"] == 2
    assert not list((tmp_path / "pdfs").glob("*.pdf"))
    with pytest.raises(ValueError):
        raw._publish_pdf(io.BytesIO(PDF), tmp_path / "pdfs", max_bytes=4)


def test_authorization_required_before_network_or_artifacts(project, network):
    with pytest.raises(ValueError, match="authorization"):
        raw.acquire_raw_datasets(project, config())
    assert network[1] == []
    assert not (project / "data").exists()


def test_pipeline_preserves_history_and_keeps_sample_hashes_ignored(project, network):
    split = project / "data/processed/rit-pdfmal-2026_split_manifest.csv"
    split.parent.mkdir(parents=True)
    split.write_bytes(b"locked split bytes")
    result = raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_fixture")
    assert result["status"] == "completed" and result["unique_pdfs"] == 1
    assert split.read_bytes() == b"locked split bytes"
    assert (project / "reports/research_log.md").read_text().startswith("Historical entry.\n")
    report = project / result["report_path"]
    assert (report.parent / "locked_methodology.json").exists()
    assert (report.parent / "model_comparison.csv").exists()
    assert hashlib.sha256(PDF).hexdigest() not in report.read_text()
    assert hashlib.sha256(PDF).hexdigest() in (project / result["manifest_path"]).read_text()
    with pytest.raises(ValueError, match="collision"):
        raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_fixture")


def test_missing_password_is_logged_and_other_sources_continue(project, network, monkeypatch):
    monkeypatch.delenv("MALPDF_SYNTHETIC_ARCHIVE_PASSWORD", raising=False)
    encrypted = {**SOURCE, "name": "encrypted", "kind": "zip", "password_env": "MALPDF_SYNTHETIC_ARCHIVE_PASSWORD"}
    result = raw.acquire_raw_datasets(project, config(encrypted, SOURCE), authorized=True, run_id="run_partial")
    assert result["status"] == "partial" and result["unique_pdfs"] == 1
    assert result["sources"][0]["status"] == "blocked_missing_password"
    assert len(network[1]) == 1
    assert "blocked_missing_password" in (project / "reports/research_log.md").read_text()


def test_archive_password_stays_out_of_evidence(project, network, monkeypatch):
    monkeypatch.setenv("MALPDF_SYNTHETIC_ARCHIVE_PASSWORD", "synthetic")
    network[0]["make"] = lambda: Response(ENCRYPTED)
    source = {**SOURCE, "kind": "zip", "password_env": "MALPDF_SYNTHETIC_ARCHIVE_PASSWORD", "label": 1, "label_source": "fixture_publisher"}
    result = raw.acquire_raw_datasets(project, config(source), authorized=True, run_id="run_encrypted")
    assert result["status"] == "completed" and result["unique_pdfs"] == 1
    for path in (project / "reports/experiments/raw_downloads/run_encrypted").glob("*.json"):
        assert '"synthetic"' not in path.read_text()
    manifest = (project / result["manifest_path"]).read_text()
    assert ",1,data/raw/" in manifest


def test_conflicting_source_labels_are_reported(project, network):
    first = {**SOURCE, "label": 1}
    second = {**SOURCE, "name": "conflict", "label": 0}
    result = raw.acquire_raw_datasets(project, config(first, second), authorized=True, run_id="run_conflict")
    assert result["status"] == "partial" and result["unique_pdfs"] == 1
    assert result["sources"][1]["status"] == "failed"


def test_interruption_preserves_evidence_and_log(project, network):
    network[0]["make"] = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_interrupt")
    report = project / "reports/experiments/raw_downloads/run_interrupt/run_summary.json"
    assert json.loads(report.read_text())["status"] == "interrupted"
    assert (report.parent / "model_comparison.csv").exists()
    assert "acquisition / interrupted" in (project / "reports/research_log.md").read_text()


def test_failure_payload_is_charged_to_global_budget(project, network):
    network[0]["make"] = lambda: Response(PDF * 20, headers={})
    second = {**SOURCE, "name": "second"}
    result = raw.acquire_raw_datasets(project, config(SOURCE, second, max_download_bytes=10, max_pdf_bytes=10, max_total_download_bytes=10), authorized=True, run_id="run_budget")
    assert result["status"] == "failed" and result["downloaded_bytes"] == 10
    assert len(network[1]) == 1


def test_ignore_coverage_and_symlink_outputs_are_required(project, network, monkeypatch):
    monkeypatch.setattr(raw.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match="gitignored"):
        raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_unignored")
    monkeypatch.setattr(raw.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    (project / "data").symlink_to(project / "reports", target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_symlink")
    assert network[1] == []


def test_cli_without_authorization_refuses_before_calls(project, network, monkeypatch):
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/download_raw_datasets.py"))
    configuration = project / "configs/fixture.yaml"
    configuration.parent.mkdir()
    configuration.write_text(json.dumps(config()))
    module["main"].__globals__["ROOT"] = project
    assert module["main"](["--config", str(configuration)]) == 1
    assert network[1] == []


def test_authorized_cli_preflight_failure_has_immutable_evidence(project, network):
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/download_raw_datasets.py"))
    configuration = project / "configs/fixture.yaml"
    configuration.parent.mkdir()
    configuration.write_text(json.dumps(config({**SOURCE, "name": "INVALID"})))
    module["main"].__globals__["ROOT"] = project
    assert module["main"](["--config", str(configuration), "--execute-authorized", "--run-id", "run_refused"]) == 1
    evidence = project / "reports/experiments/raw_downloads/run_refused"
    assert json.loads((evidence / "run_summary.json").read_text())["status"] == "refused"
    assert (evidence / "locked_methodology.json").exists()
    assert (evidence / "model_comparison.csv").exists()
    assert "acquisition / refused" in (project / "reports/research_log.md").read_text()
    assert network[1] == []


def test_candidates_probe_crc_before_publication_and_select_second(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(ENCRYPTED)
    events = []
    result = raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000,
            password_candidates=(b"wrong", b"synthetic"), progress=events.append)
    assert result["password_selection"] == {"candidate_count": 2, "attempts": 2, "selected_index": 2, "probe_crc_verified": True}
    assert [e["event"] for e in events] == ["password_probe_rejected", "password_selected"]
    assert list((tmp_path / "pdfs").glob("*.pdf"))[0].read_bytes() == PDF
    assert "synthetic" not in json.dumps(events)


def test_all_candidates_fail_before_creating_pdf_directory(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(ENCRYPTED)
    with pytest.raises(ValueError, match="all explicitly supplied candidates"):
        raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000,
                password_candidates=(b"wrong", b"also wrong"))
    assert not (tmp_path / "pdfs").exists()


@pytest.mark.parametrize("error_type", [EOFError, zlib.error])
def test_wrong_candidate_with_valid_encryption_header_retries_corrupt_stream(error_type, tmp_path, monkeypatch):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(ENCRYPTED)
    original_open = zipfile.ZipFile.open

    class InvalidPlaintext(io.BytesIO):
        def read(self, size=-1):
            # ZipCrypto checks only one header byte. A wrong password can pass
            # that check and subsequently fail during deflate decoding/EOF.
            raise error_type("invalid decrypted stream")

    def open_member(self, member, *args, **kwargs):
        if kwargs.get("pwd") == b"wrong":
            return InvalidPlaintext()
        return original_open(self, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", open_member)
    result = raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000,
            password_candidates=(b"wrong", b"synthetic"))
    assert result["password_selection"]["selected_index"] == 2
    assert list((tmp_path / "pdfs").glob("*.pdf"))[0].read_bytes() == PDF


def test_password_candidates_do_not_bypass_unsafe_archive_directory(tmp_path):
    archive = tmp_path / "source.zip"
    make_zip(archive, [("../escape.pdf", PDF)])
    with pytest.raises(ValueError, match="Unsafe"):
        raw.extract_pdf_archive(archive, tmp_path / "pdfs", raw.DownloadLimits(), remaining_bytes=10000,
                password_candidates=(b"wrong", b"synthetic"))
    assert not (tmp_path / "pdfs").exists()


@pytest.mark.parametrize("value", ['"password"', '[1]', '[]', '["", "valid"]', '["same", "same"]', '{"secret":1}', 'not json', json.dumps([str(i) for i in range(9)]), json.dumps(["x" * 257])])
def test_invalid_password_candidate_environment_fails_without_leaking_value(value, monkeypatch):
    source = {**SOURCE, "kind": "zip", "password_candidates_env": "MALPDF_TEST_CANDIDATES"}
    monkeypatch.setenv("MALPDF_TEST_CANDIDATES", value)
    with pytest.raises(ValueError) as caught:
        raw._password_candidates(source)
    assert value not in str(caught.value)


def test_candidate_and_single_environment_are_mutually_exclusive():
    source = {**SOURCE, "kind": "zip", "password_env": "MALPDF_TEST_PASSWORD", "password_candidates_env": "MALPDF_TEST_CANDIDATES"}
    with pytest.raises(ValueError, match="one password environment"):
        raw.validate_configuration(config(source))


def test_reuse_checks_original_payload_without_network_or_mutating_old_run(project, network):
    original = raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_original")
    old_files = list((project / "data/raw/public_pdf_sources/run_original").rglob("*"))
    old_files += list((project / "artifacts/raw_downloads/run_original").rglob("*"))
    old_files += list((project / "reports/experiments/raw_downloads/run_original").rglob("*"))
    protected = {p: p.read_bytes() for p in old_files if p.is_file()}
    result = raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_reused", reuse_run="run_original")
    assert result["status"] == "completed" and result["unique_pdfs"] == 1
    assert result["reused_bytes"] == len(PDF) and result["downloaded_bytes"] == 0
    assert len(network[1]) == 1
    assert all(p.read_bytes() == data for p, data in protected.items())
    assert result["manifest_path"] != original["manifest_path"]


def test_retry_encrypted_archive_reuses_prior_bytes_with_new_candidates(project, network, monkeypatch):
    network[0]["make"] = lambda: Response(ENCRYPTED)
    source = {**SOURCE, "kind": "zip", "password_env": "MALPDF_TEST_PASSWORD"}
    monkeypatch.setenv("MALPDF_TEST_PASSWORD", "wrong")
    first = raw.acquire_raw_datasets(project, config(source), authorized=True, run_id="run_wrong_password")
    assert first["status"] == "failed"
    source.pop("password_env")
    source["password_candidates_env"] = "MALPDF_TEST_CANDIDATES"
    monkeypatch.setenv("MALPDF_TEST_CANDIDATES", '["wrong", "synthetic"]')
    second = raw.acquire_raw_datasets(project, config(source), authorized=True, run_id="run_retry", reuse_run="run_wrong_password")
    assert second["status"] == "completed" and second["sources"][0]["password_selection"]["selected_index"] == 2
    assert second["reused_bytes"] == len(ENCRYPTED) and second["downloaded_bytes"] == 0
    assert len(network[1]) == 1
    for path in (project / "reports/experiments/raw_downloads/run_retry").glob("*.json"):
        assert '"synthetic"' not in path.read_text()


@pytest.mark.parametrize("change", ["same_size_bytes", "size", "publisher_lock", "source_label", "symlink", "checksum_evidence"])
def test_reuse_mismatch_fails_closed_without_http_fallback(change, project, network):
    raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_original")
    source = SOURCE.copy()
    path = project / "data/raw/public_pdf_sources/run_original/fixture/payload.download"
    if change == "same_size_bytes":
        path.write_bytes(PDF[:-1] + b"!")
    elif change == "size":
        path.write_bytes(PDF + b"!")
    elif change == "publisher_lock":
        source["expected_md5"] = "0" * 32
    elif change == "source_label":
        source["label"] = 1
    elif change == "symlink":
        other = project / "other"
        other.write_bytes(PDF)
        path.unlink()
        path.symlink_to(other)
    else:
        evidence = project / "artifacts/raw_downloads/run_original/fixture_download.json"
        value = json.loads(evidence.read_text())
        value["sha256"] = "0" * 64
        evidence.write_text(json.dumps(value))
    result = raw.acquire_raw_datasets(project, config(source), authorized=True, run_id="run_mismatch", reuse_run="run_original")
    assert result["status"] == "failed" and result["unique_pdfs"] == 0
    assert result["downloaded_bytes"] == 0 and result["reused_bytes"] == 0
    assert len(network[1]) == 1


@pytest.mark.parametrize("identifier", ["../run_original", "/run_original", "run_new"])
def test_reuse_identifier_cannot_escape_or_collide(identifier, project, network):
    with pytest.raises(ValueError, match="reuse run identifier"):
        raw.acquire_raw_datasets(project, config(), authorized=True, run_id="run_new", reuse_run=identifier)
    assert network[1] == []
