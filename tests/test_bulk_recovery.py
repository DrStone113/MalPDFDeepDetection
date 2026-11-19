import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from malpdf.extraction import bulk_pipeline


def test_empty_checkpoint_cannot_be_adopted(tmp_path):
    (tmp_path / "chunk_done.json").write_text(json.dumps({"files": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint"):
        bulk_pipeline._chunk_is_complete(tmp_path)


def test_checked_in_baseline_covers_eight_chunks():
    path = Path(__file__).resolve().parents[1] / "plans/bulk-extractor-recovery/baseline.json"
    if not path.is_file():
        pytest.skip("Windows planning evidence is outside the LAB release allowlist")
    baseline = json.loads(path.read_text(encoding="utf-8"))
    assert [row["id"] for row in baseline["chunks"]] == list(range(8))
    assert sum(row["graphs"] + row["unavailable"] for row in baseline["chunks"]) == 4000


def test_catalog_snapshot_restores_tuple_fields_and_checks_hash(tmp_path):
    from malpdf.extraction.arlington_model import Catalog, ModelUnavailable, read_catalog_snapshot, write_catalog_snapshot

    original = Catalog({"Catalog": ({"Key": "Pages", "loader_notes": ("omitted_optional_note_cell",)},)}, {"commit": "a" * 40})
    path = tmp_path / "arlington.json"
    digest = write_catalog_snapshot(path, original)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert read_catalog_snapshot(path, digest) == original
    with pytest.raises(ModelUnavailable):
        read_catalog_snapshot(path, "0" * 64)


def test_comparison_checks_each_saved_artifact():
    from malpdf.extraction.bulk_checkpoint import different_artifacts

    baseline = {"tabular": {"features": [None, 1]}, "graph": {"edge_src": [1, 2]},
                "unavailable": {"status": "partial"}, "markov": bytes([1, 2])}
    assert different_artifacts(baseline, dict(baseline)) == []
    for name, value in (
        ("tabular", {"features": [None, 2]}), ("graph", {"edge_src": [2, 1]}),
        ("unavailable", {"status": "observed"}), ("markov", bytes([2, 1])),
    ):
        assert different_artifacts(baseline, dict(baseline, **{name: value})) == [name]


def test_over_cap_document_stays_in_manifest_without_graph_or_markov(tmp_path):
    fixture = Path(__file__).parent / "fixtures/real_benign_document.pdf"
    sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
    entry = bulk_pipeline.CleanCorpusEntry(0, sha, fixture, fixture.name, "reviewed", None, "test")

    def extract(entries, **_):
        assert not entries
        return iter(())

    summary = bulk_pipeline.run_hybrid_bulk_extraction(
        [entry], base_dir=fixture.parent, output_dir=tmp_path / "bulk", device="cpu",
        limits=bulk_pipeline.CodeInspectionLimits(max_file_bytes=64), extractor_fn=extract,
    )
    assert summary["planned_denominator"] == 1
    assert summary["gnn_exported_graphs"] == 0
    assert summary["unavailable_empty_graphs"] == 1
    path = tmp_path / "bulk/chunks/chunk_00000/markov_shas.json"
    assert json.loads(path.read_bytes()) == []


@pytest.mark.skipif(sys.platform != "linux", reason="Bulk profile subprocess is a Linux LAB path")
def test_bulk_profile_with_reviewed_fixture_uses_limits_and_reaps_worker(tmp_path):
    from malpdf.extraction.arlington_model import Catalog, write_catalog_snapshot
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.profile_worker import profile_pdf

    path = Path(__file__).parent / "fixtures/real_benign_document.pdf"
    registry = tmp_path / "workers"
    registry.mkdir()
    catalog = Catalog({}, {})
    snapshot = tmp_path / "arlington.json"
    digest = write_catalog_snapshot(snapshot, catalog)
    before_fd = len(list(Path("/proc/self/fd").iterdir()))
    result = profile_pdf(
        path, boundary=path.parent, digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        limits=CodeInspectionLimits(wall_seconds=45, cpu_seconds=35, memory_bytes=1536 * 1024**2),
        analysis_version="v9", extraction_profile="deep-static", include_byte_images=False,
        coalesce_checkpoints=True, arlington_catalog=catalog, bulk_worker=((str(snapshot), digest), registry),
    )
    assert result["worker_cleanup_complete"] is True
    assert result.get("static") is not None, result["diagnostic"]
    assert result["resource_limits"]["address_space_bytes"] == [1536 * 1024**2] * 2
    assert result["resource_limits"]["disposable_process_group"] is True
    assert list(registry.iterdir()) == []
    assert len(list(Path("/proc/self/fd").iterdir())) == before_fd


@pytest.mark.skipif(sys.platform != "linux", reason="Uses Linux pipe descriptors")
def test_frame_is_ready_only_after_payload_is_complete():
    from multiprocessing.connection import Connection
    from malpdf.extraction.profile_transport import FramedReader

    reader, writer = os.pipe()
    handle = FramedReader(Connection(reader, writable=False), 128)
    try:
        os.write(writer, b"\x00\x00")
        assert not handle.poll()
        os.write(writer, b"\x00\x03a")
        assert not handle.poll()
        os.write(writer, b"bc")
        assert handle.poll()
        assert handle.recv_bytes() == b"abc"
    finally:
        os.close(writer)
        handle.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Uses Linux socket descriptors")
def test_frame_drains_large_payload_already_written_before_eof():
    from multiprocessing.connection import Connection
    import socket
    import struct
    from malpdf.extraction.profile_transport import FramedReader

    left, right = socket.socketpair()
    payload = b"x" * (257 * 1024)
    handle = FramedReader(Connection(left.detach(), writable=False), len(payload))
    try:
        right.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(payload) * 2)
        right.settimeout(2)
        right.sendall(struct.pack("!i", len(payload)) + payload)
        right.close()
        assert handle.poll()
        assert handle.recv_bytes() == payload
        assert not handle.poll()
    finally:
        right.close()
        handle.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Uses Linux process and pipe descriptors")
@pytest.mark.parametrize(("mode", "expected"), [
    ("exit", "worker_exit"), ("signal", "worker_signal_9"),
    ("oversize", "invalid_worker_response"), ("truncated", "invalid_worker_response"),
])
def test_bulk_worker_termination_keeps_verified_prefix(tmp_path, monkeypatch, mode, expected):
    import subprocess
    from malpdf.extraction.profile_transport import BulkWorker
    from malpdf.static import profile_worker

    child = """
import json, os, signal, struct, sys
fd, mode = int(sys.argv[1]), sys.argv[2]
if mode in ('oversize', 'truncated'):
    checkpoint = json.dumps({'event': 'checkpoint', 'profile': {
        'status': 'partial', 'errors': [], 'static': {'test_prefix': True}, 'code': None,
    }}).encode()
    delta = json.dumps({'event': 'evidence_delta', 'delta': {
        'observations': [{'id': 'safe-observation'}],
    }}).encode()
    os.write(fd, struct.pack('!i', len(checkpoint)) + checkpoint)
    os.write(fd, struct.pack('!i', len(delta)) + delta)
    os.write(fd, struct.pack('!i', 7 * 1024**2 if mode == 'oversize' else 40) + b'x')
elif mode == 'signal':
    os.kill(os.getpid(), signal.SIGKILL)
"""

    def start(self):
        fd = self.config["result_fd"]
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-c", child, str(fd), mode], pass_fds=(fd,), start_new_session=True,
        )
        self.process.wait(timeout=5)

    monkeypatch.setattr(BulkWorker, "start", start)
    result = profile_worker.profile_pdf(
        tmp_path / "untouched.pdf", boundary=tmp_path, digest="b" * 64,
        analysis_version="v9", extraction_profile="deep-static", bulk_worker=(None, tmp_path),
    )
    assert result["errors"] == [expected]
    assert result["worker_cleanup_complete"] is True
    if mode in ("oversize", "truncated"):
        assert result["static"] == {"test_prefix": True}
        assert result["analysis_v9"]["observations"] == [{"id": "safe-observation"}]


@pytest.mark.parametrize("interrupted", [False, True])
def test_replace_keeps_original_and_resumes_after_publication_interruption(tmp_path, interrupted):
    from malpdf.extraction.bulk_checkpoint import file_sha256, replacement_archive

    fixture = Path(__file__).parent / "fixtures/real_benign_document.pdf"
    sha = file_sha256(fixture)
    entry = bulk_pipeline.CleanCorpusEntry(0, sha, fixture, fixture.name, "reviewed", None, "test")
    options = dict(
        base_dir=fixture.parent, output_dir=tmp_path / "bulk", device="cpu",
        limits=bulk_pipeline.CodeInspectionLimits(max_file_bytes=64), extractor_fn=lambda *a, **k: iter(()),
    )
    bulk_pipeline.run_hybrid_bulk_extraction([entry], **options)
    current = options["output_dir"] / "chunks/chunk_00000"
    compare = {name.name: file_sha256(name) for name in current.iterdir()}
    original = compare["chunk_done.json"]
    archived = replacement_archive(current, original)
    if interrupted:
        current.rename(archived)
    producer = {"commit": "c" * 40}
    bulk_pipeline.run_hybrid_bulk_extraction([entry], producer=producer, replaced_checkpoints={0: original}, **options)
    assert {name.name: file_sha256(name) for name in archived.iterdir()} == compare
    assert json.loads((current / "chunk_done.json").read_bytes())["producer"] == producer
    current_hash = file_sha256(current / "chunk_done.json")
    bulk_pipeline.run_hybrid_bulk_extraction([entry], producer=producer, replaced_checkpoints={0: original}, **options)
    assert file_sha256(current / "chunk_done.json") == current_hash


@pytest.mark.skipif(sys.platform != "linux", reason="Bulk runner uses Linux sessions")
@pytest.mark.parametrize("exit_code", [75, None])
def test_bulk_session_timeout_records_attempt_without_job_result(tmp_path, monkeypatch, exit_code):
    import time

    lab_source = Path(__file__).resolve().parents[1] / "scripts/lab"
    monkeypatch.syspath_prepend(str(lab_source))
    import lab_jobs

    monkeypatch.setattr(lab_jobs, "__file__", str(tmp_path / "lab_jobs.py"))
    body = "time.sleep(60)" if exit_code is None else "sys.exit(75)"
    (tmp_path / "lab_runner.py").write_text(
        "import sys, time\n"
        "assert sys.stdin.buffer.read(1) == b'1'\n" + body + "\n", encoding="ascii",
    )
    job = {"job_id": "e" * 64, "limits": {"wall_seconds": 2}}
    with pytest.raises(lab_jobs.BulkInterrupted, match="worker_timeout"):
        lab_jobs._bulk_task(job, tmp_path, {"python": sys.executable}, time.monotonic())
    assert not (tmp_path / "result.json").exists()
    result, = (tmp_path / "bulk_attempts").glob("*/result.json")
    assert json.loads(result.read_bytes()) == {"status": "interrupted", "cleanup_verified": True}
    lab_jobs.ensure_bulk_sessions_stopped(tmp_path)
