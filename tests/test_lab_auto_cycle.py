import gzip
import importlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts/lab"))
    return tuple(
        importlib.import_module(name)
        for name in ("lab_auto_cycle", "lab_oneshot_adm", "lab_offline_oneshot", "lab_jobs")
    )


def test_prompt_requires_exact_selection(modules):
    _, _, offline, _ = modules
    job_id = "a" * 64
    for selected, answer in [(job_id, b"y\n"), ("b" * 64, b"n\n")]:
        stream = io.BytesIO(f"Job: {selected} | kind: pdf-static\r\nChay job da duyet? [y/N]: ".encode())
        answers = []
        confirmed = offline.confirm_lab_run_prompt(lambda _: stream.read(11), answers.append, job_id, "pdf-static")
        assert answers == [answer]
        assert confirmed is (selected == job_id)


def test_ssh_rejected_before_checks(modules, monkeypatch):
    _, admin, offline, _ = modules
    for name in [key for key in os.environ if key.startswith("SSH_")]:
        monkeypatch.delenv(name, raising=False)
    for key, value in (("SSH_CONNECTION", "present"), ("SSH_CONNECTION", ""), ("SSH_AUTH_SOCK", "/tmp/agent")):
        monkeypatch.setenv(key, value)
        with pytest.raises(ValueError, match="ssh_launch_forbidden"):
            offline.precheck("a" * 64, "pdf-static")
        with pytest.raises(ValueError, match="ssh_launch_forbidden"):
            admin.boot_exec()
        monkeypatch.delenv(key, raising=False)


def test_proposal_alone_cannot_authorize_and_bulk_keeps_state(modules):
    auto, _, _, jobs = modules
    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder)
        archive, manifest = source / "source.tar", source / "source.json"
        archive.write_bytes(b"sealed archive")
        manifest.write_bytes(jobs.encoded({"commit": "a" * 40, "archive_sha256": jobs.sha(archive.read_bytes())}))
        job = jobs.make_job(
            "a" * 40,
            jobs.sha(archive.read_bytes()),
            jobs.sha(manifest.read_bytes()),
            mode="offline",
            kind="pdf-static-bulk",
        )
        proposal = source / "proposal.json"
        proposal.write_bytes(
            jobs.encoded({"job": job, "source_archive": str(archive), "source_manifest": str(manifest)})
        )
        with pytest.raises(ValueError, match="authorization_required"):
            auto.authorize(proposal)
        with pytest.raises(ValueError, match="bulk_requires_keep_lab_state"):
            auto.authorize(proposal, authorize_job=job["job_id"], recovery_mode="revert_pre_job")
        state = auto.authorize(proposal, auto_authorize_standing=True)
        assert state["job_id"] == job["job_id"]
        assert state["recovery_mode"] == "keep_lab_state"
        assert state["standing_rule_authorization"] is True


VMX = (
    b'ethernet0.present = "TRUE"\r\n'
    b'ethernet0.connectionType = "nat"\r\n'
    b'ethernet0.startConnected = "FALSE"\r\n'
    b'ethernet1.present = "TRUE"\r\n'
    b'ethernet1.connectionType = "hostonly"\r\n'
    b'ethernet1.vnet = "vmnet1"\r\n'
    b'ethernet1.startConnected = "TRUE"\r\n'
)


def make_job(jobs, kind):
    return jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind=kind)


def cycle_state(auto, job, stage):
    cycle_id = "d" * 32
    return {
        **{key: job[key] for key in ("kind", "job_id", "commit", "archive_sha256", "manifest_sha256")},
        "job": job,
        "stage": stage,
        "cycle_id": cycle_id,
        "vmx_path": auto.VMX.as_posix(),
        "snapshot_name": f"pre-job-{job['job_id'][:12]}-{cycle_id[:8]}",
        "export_profile": job["kind"],
        "recovery_mode": "keep_lab_state" if job["kind"] == "pdf-static-bulk" else "revert_pre_job",
    }


def test_vmx_rewrite_disconnects_all_adapters_and_restores_only_hostonly(modules):
    auto, _, _, _ = modules
    offline = auto.rewrite_vmx_network(VMX, "offline")
    assert auto.verify_vmx_offline_config(offline)
    assert b"\n" not in offline.replace(b"\r\n", b"")
    restored = auto.rewrite_vmx_network(offline, "host-only")
    assert auto.baseline_hostonly(restored) == "ethernet1"
    with pytest.raises(ValueError, match="vmware_nic_connected"):
        auto.verify_vmx_offline_config(restored)
    with pytest.raises(ValueError, match="vmware_configuration_invalid"):
        auto.rewrite_vmx_network(VMX + b'ETHERNET0.present = "FALSE"\r\n')
    with pytest.raises(ValueError, match="vmware_sharing_enabled"):
        auto.rewrite_vmx_network(VMX + b'sharedFolder0.enabled = "TRUE"\r\n')


def test_vmware_boot_log_counts_connections_and_disallows_stale_sessions(modules):
    auto, _, _, jobs = modules
    config = auto.rewrite_vmx_network(VMX)
    header = (
        b"2026-11-28T00:00:00.100Z In(05) vmx Log for VMware Workstation pid=9488 version=17.5.2 build=build-23775571\n"
    )
    tail = (
        b"".join(b"2026-11-28T00:00:00.200Z In(05) vmx DICT   " + line + b"\n" for line in config.splitlines())
        + b"2026-11-28T00:00:00.500Z In(05) vmx "
        + auto.BOOT_MARKER
        + b"\n2026-11-28T00:00:01.000Z In(05) vmx "
        + auto.P9FS_DISABLED
        + b"\n2026-11-28T00:00:02.000Z In(05) vmx "
        + auto.OFF_MARKER
        + b"\n"
    )
    log = (
        header
        + b"2026-11-28T00:00:00.100Z In(05) vmx Host offset from UTC is -07:00.\n"
        + b'2026-11-28T00:00:00.059Z In(05) vmx VTHREAD 18060 "vmx"\n'
        + b"2026-11-28T00:00:00.150Z In(05) vmx "
        + auto.OFF_MARKER
        + b"\n"
        + tail
    )
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "vmware.log"
        path.write_bytes(log)
        assert auto.verify_vmware_offline_session_log(path) == jobs.sha(log)
        with pytest.raises(ValueError, match="stale_vmware_log"):
            auto.verify_vmware_offline_session_log(path, previous_size=len(log), previous_digest=jobs.sha(log))
        prior = b"2026-11-28T00:00:00.010Z In(05) vmx prior session\n"
        path.write_bytes(prior + log)
        assert auto.verify_vmware_offline_session_log(
            path, previous_size=len(prior), previous_digest=jobs.sha(prior)
        ) == jobs.sha(log)
        path.write_bytes(prior + tail)
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(path, previous_size=len(prior), previous_digest=jobs.sha(prior))
        path.write_bytes(tail)
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(path)
        bad_pre_dict = (
            header
            + b"2026-11-28T00:00:00.100Z In(05) vmx ordinary startup line\n"
            + b"2026-11-28T00:00:00.050Z In(05) vmx another startup line\n"
            + tail
        )
        path.write_bytes(bad_pre_dict)
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(path)
        path.write_bytes(log.replace(b"2026-11-28T00:00:02.000Z", b"2026-11-28T00:00:00.900Z"))
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(path)
        path.write_bytes(
            log.replace(
                auto.P9FS_DISABLED,
                auto.CONNECT_EVENT + b"\n2026-11-28T00:00:01.100Z In(05) vmx " + auto.P9FS_DISABLED,
            )
        )
        with pytest.raises(ValueError, match="vmware_session_isolation_failed"):
            auto.verify_vmware_offline_session_log(path)
        path.write_bytes(log)
        assert auto.verify_vmware_offline_session_log(
            path, not_before="2026-11-28T00:00:00.000Z", not_after="2026-11-28T00:00:03.000Z"
        ) == jobs.sha(log)
        path.write_bytes(log.replace(b"2026-11-28T", b"2025-01-01T"))
        with pytest.raises(ValueError, match="stale_vmware_log"):
            auto.verify_vmware_offline_session_log(path, not_before="2026-11-28T00:00:00.000Z")
        ended_early = (
            log.replace(b"2026-11-28T00:00:00.", b"2026-11-28T00:00:10.")
            .replace(b"2026-11-28T00:00:01.", b"2026-11-28T00:00:13.")
            .replace(b"2026-11-28T00:00:02.", b"2026-11-28T00:00:14.")
        )
        path.write_bytes(ended_early)
        with pytest.raises(ValueError, match="stale_vmware_log"):
            auto.verify_vmware_offline_session_log(
                path, not_before="2026-11-28T00:00:15.000Z", not_after="2026-11-28T00:00:20.000Z"
            )
        path.write_bytes(log.replace(b"2026-11-28T00:00:02.000Z", b"2026-11-28T00:00:09.000Z"))
        with pytest.raises(ValueError, match="stale_vmware_log"):
            auto.verify_vmware_offline_session_log(
                path, not_before="2026-11-28T00:00:00.000Z", not_after="2026-11-28T00:00:03.000Z"
            )
        cycle = auto.Cycle(Path(temp))
        cycle.write_state(
            {
                "pre_boot_log_size": 0,
                "pre_boot_log_sha256": None,
                "offline_adapters": ["ethernet0"],
                "boot_started_utc": "2026-11-28T00:00:00.000Z",
            }
        )
        with pytest.raises(ValueError, match="vmware_boot_timestamp_missing"):
            cycle.log_proof()


@pytest.mark.parametrize("running,locked", [(True, False), (False, True)])
def test_vmx_mutation_gate_refuses_running_or_locked_vm(modules, monkeypatch, running, locked):
    auto, _, _, _ = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(VMX)
        if locked:
            (root / "Lab.vmx.lck").mkdir()
        monkeypatch.setattr(auto, "VMX", vmx)
        cycle = auto.Cycle(root)
        monkeypatch.setattr(cycle, "running", lambda: running)
        with pytest.raises(ValueError, match="vmware_must_be_stopped_and_unlocked"):
            cycle.require_stopped()
        assert vmx.read_bytes() == VMX


def test_second_cycle_cannot_acquire_lock_or_replace_active_pause(modules):
    auto, _, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp, auto.cycle_lock(Path(temp)):
        with pytest.raises(ValueError, match="cycle_lock_busy"):
            with auto.cycle_lock(Path(temp)):
                pytest.fail("second writer acquired the lock")
        cycle = auto.Cycle(Path(temp))
        state = cycle_state(auto, make_job(jobs, "pdf-static-bulk"), "BULK_PAUSED_SAVED")
        cycle.save(**state)
        with pytest.raises(ValueError, match="active_cycle_unfinished"):
            auto.require_new_cycle(cycle.state)
        with pytest.raises(ValueError, match="exact_abandon_active_cycle_required"):
            cycle.reset_clean_lab()
        with pytest.raises(ValueError, match="exact_abandon_active_cycle_required"):
            cycle.reset_clean_lab("e" * 32)
        assert auto.Cycle(Path(temp)).state == state


@pytest.mark.parametrize("remove", [True, False])
def test_revert_refuses_missing_or_corrupted_evidence(modules, monkeypatch, remove):
    auto, _, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        evidence_root = root / "runs"
        cycle = auto.Cycle(root, evidence_root)
        job = make_job(jobs, "pdf-static")
        folder = evidence_root / f"run_20261128T120000000000Z_{job['commit'][:12]}"
        folder.mkdir(parents=True)
        raw = b"{}\n"
        hashes = dict.fromkeys(auto.ARTIFACT_LIMITS, jobs.sha(raw))
        for name in hashes:
            (folder / name).write_bytes(raw)
        cycle.save(**cycle_state(auto, job, "EVIDENCE_SAVED"), evidence_dir=str(folder), artifact_sha256s=hashes)
        monkeypatch.setattr(cycle, "vmrun", lambda *args, **kwargs: pytest.fail("snapshot command called"))
        damaged = folder / "profile_export.json"
        if remove:
            damaged.unlink()
        else:
            damaged.write_bytes(b'{"modified":true}\n')
        with pytest.raises((ValueError, FileNotFoundError)):
            cycle.revert_snapshot()
        assert cycle.state["stage"] == "EVIDENCE_SAVED"


def test_boot_keeps_ticket_when_pending_queue_is_not_exclusive(modules, monkeypatch):
    _, admin, _, jobs = modules
    for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
        monkeypatch.delenv(name, raising=False)
    job = make_job(jobs, "pdf-static")
    with tempfile.TemporaryDirectory() as temp:
        ticket = Path(temp) / "ticket.json"
        ticket.write_bytes(admin.json_bytes({"job_id": job["job_id"], "kind": job["kind"]}))
        monkeypatch.setattr(admin, "require_root", lambda: None)
        monkeypatch.setattr(admin, "verify_auto_manifest", lambda: None)
        monkeypatch.setattr(admin, "ticket_value", lambda: admin.read_json(ticket, 65536))
        monkeypatch.setattr(admin, "admin_lock", lambda: tempfile.TemporaryDirectory())
        monkeypatch.setattr(admin, "remove_arm", ticket.unlink)
        monkeypatch.setattr(jobs, "load_job", lambda _: job)
        monkeypatch.setattr(jobs, "pending", lambda: [job, make_job(jobs, "pdf-static")])
        with pytest.raises(ValueError, match="queue_not_exclusive"):
            admin.boot_exec()
        assert ticket.is_file()


@pytest.mark.parametrize(
    "text",
    [
        "Job: {id} | kind: pdf-static-cve\n",
        "prefix Job: {id} | kind: pdf-static\n",
        "Job: {id} | kind: pdf-static\nJob: other\n",
        "",
    ],
)
def test_prompt_aborts_on_ambiguous_or_missing_job(modules, text):
    _, _, offline, _ = modules
    job_id = "a" * 64
    chunks = iter([(text.format(id=job_id) + "Chay job da duyet? [y/N]: ").encode(), b""])
    answers = []
    assert offline.confirm_lab_run_prompt(lambda _: next(chunks), answers.append, job_id, "pdf-static") is False
    assert answers == [b"n\n"]


def test_bulk_outcome_requires_new_attempt_with_verified_cleanup(modules, monkeypatch):
    _, admin, _, jobs = modules
    job = make_job(jobs, "pdf-static-bulk")
    result = jobs.result(job, "interrupted", reason="already_claimed")
    monkeypatch.setattr(jobs, "read_result", lambda _: result)
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        (directory / "claim.json").write_bytes(b"{}")
        assert admin.classify_job_outcome(job, directory, 0) == ("unexpected_incomplete", None)
        attempt = directory / "bulk_attempts" / ("b" * 32)
        attempt.mkdir(parents=True)
        result_path = attempt / "result.json"
        result_path.write_bytes(admin.json_bytes({"status": "interrupted", "cleanup_verified": False}))
        assert admin.classify_job_outcome(job, directory, 0) == ("unexpected_incomplete", None)
        result_path.write_bytes(admin.json_bytes({"status": "interrupted", "cleanup_verified": True}))
        assert admin.classify_job_outcome(job, directory, 0) == ("unexpected_incomplete", None)
        (attempt / "writer.json").write_bytes(admin.json_bytes({"pid": 4321, "pgid": 4321, "start_ticks": 99}))
        (attempt / "workers").mkdir()
        assert admin.classify_job_outcome(job, directory, 0) == ("bulk_paused_resumable", result)
        assert admin.classify_job_outcome(job, directory, 1) == ("unexpected_incomplete", None)
        assert admin.classify_job_outcome(job, directory, 0, previous_attempts={attempt.name}) == (
            "unexpected_incomplete",
            None,
        )


def setup_export(modules, monkeypatch, root, kind, *, samples=None):
    _, admin, _, jobs = modules
    job = make_job(jobs, kind)
    if samples is not None:
        monkeypatch.setattr(jobs, "policy", lambda _: {**job["limits"], "samples": samples})
        job = make_job(jobs, kind)
    directory = root / job["job_id"]
    directory.mkdir()
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(jobs, "JOBS", root)
    monkeypatch.setattr(jobs, "config", lambda: {"data_root": str(root)})
    monkeypatch.setattr(jobs.side, "RELEASES", root)
    monkeypatch.setattr(jobs.side, "verify_release", lambda commit, manifest: {"files": []})
    monkeypatch.setattr(jobs, "verify_helpers", lambda _: None)
    (directory / "job.json").write_bytes(admin.json_bytes(job))
    return job, directory


def test_cve_export_handles_selection_without_split(modules, monkeypatch):
    _, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        job, directory = setup_export(modules, monkeypatch, Path(temp), "pdf-static-cve")
        rows = [
            {
                "sample_id": f"cve_t4pdf:{admin.CVE_NAMES[index]}",
                "Label": "1",
                "pdf_relative_path": f"data/raw/cve_t4pdf/{admin.CVE_NAMES[index]}",
                "pdf_sha256": f"{index:064x}",
                "label_source": "reviewed manifest",
            }
            for index in range(job["limits"]["samples"])
        ]
        selection = {"job_id": job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))}
        (directory / "selection.json").write_bytes(admin.json_bytes(selection))
        (directory / "result.json").write_bytes(admin.json_bytes(jobs.result(job, "failed", reason="worker_failed")))
        export = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert export["availability"] == {"missing": 5}
        assert export["selection_sha256"] == selection["selection_sha256"]
        assert export["rows"][0]["sample_id"] == rows[0]["sample_id"]
        assert "split" not in export["rows"][0]
        assert "pdf_relative_path" not in export["rows"][0]
        assert "label_source" not in export["rows"][0]
        bad_url = json.loads(admin.json_bytes(export))
        bad_url["rows"][0]["sample_id"] = "https://example.invalid/bad"
        with pytest.raises(ValueError, match="cve_selection_invalid"):
            admin.validate_export(admin.json_bytes(bad_url), job)
        bad_field = json.loads(admin.json_bytes(export))
        bad_field["rows"][0]["pdf_relative_path"] = "/etc/passwd"
        with pytest.raises(ValueError, match="export_row_invalid"):
            admin.validate_export(admin.json_bytes(bad_field), job)


def test_static_export_unpacks_gzip_and_checks_numeric_projection(modules, monkeypatch):
    _, admin, _, _ = modules
    with tempfile.TemporaryDirectory() as temp:
        job, _ = setup_export(modules, monkeypatch, Path(temp), "pdf-static", samples=1)
        record = {
            "index": 0,
            "sha256": "a" * 64,
            "split": "train",
            "label": 1,
            "source_bundle_sha256": None,
            "availability": "missing",
            "numeric": None,
        }
        extra_summary = {}

        def write_export(job_id, *, job_root, export_root):
            output = export_root / "output"
            output.mkdir()
            summary = {
                "schema_version": 1,
                "job_id": job_id,
                "planned": 1,
                "availability": {record["availability"]: 1},
                "status_counts": {record["availability"]: 1},
                "partition_coverage": {f"{record['split']}/{record['availability']}": 1},
                "missing_indices": [0],
                "invalid_indices": [],
                "cleanup_incomplete_indices": [],
                "graphs_with_observed_nodes": 0,
                "observed_graph_nodes": 0,
                "graphs_with_unknown_node_sizes": 0,
                "features_present": {},
                "features_nonnull": {},
                "source_bundle_bytes": 0,
                "uncompressed_export_bytes": 128,
                "elapsed_seconds": 0.1,
                "model_input_ready": False,
                "raw_pdf_processing": False,
                "classifier_inference_executed": False,
                **extra_summary,
            }
            (output / "coverage.json").write_bytes(admin.json_bytes(summary))
            with gzip.open(output / "numeric.jsonl.gz", "wb") as stream:
                stream.write(admin.json_bytes(record))
            return {"output": str(output)}

        monkeypatch.setitem(sys.modules, "export_numeric_postrun", SimpleNamespace(export_job=write_export))
        raw = admin.export_job(job["job_id"])
        assert admin.text_failure(raw, "export.json") is None
        assert admin.parse_json(raw.decode("utf-8"))["rows"] == [record]
        extra_summary["partition_coverage"] = {"train": 1}
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.export_job(job["job_id"])
        extra_summary["partition_coverage"] = {"train/missing": True}
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.export_job(job["job_id"])
        extra_summary.clear()
        extra_summary["internal_path"] = {"host": "lab"}
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.export_job(job["job_id"])
        extra_summary.clear()
        record.update(availability="present", numeric={}, source_bundle_sha256="b" * 64)
        with pytest.raises(ValueError, match="numeric_export_shape"):
            admin.export_job(job["job_id"])


def test_safedocs_uri_export_dispatches_and_rejects_raw_targets(modules, monkeypatch):
    _, admin, _, jobs = modules
    roster = json.loads(
        (Path(__file__).resolve().parents[1] / "configs/uri_safedocs_review_20261127.json").read_text(encoding="utf-8")
    )
    safedocs_shas = [entry["sha256"] for entry in roster]
    with tempfile.TemporaryDirectory() as temp:
        job, _ = setup_export(modules, monkeypatch, Path(temp), "pdf-uri-safedocs-review")
        records = [
            {
                "sha256": safedocs_shas[0],
                "status": "observed_targets",
                "actions_observed": 1,
                "actions_without_target": 0,
                "targets_clipped": False,
                "targets": [{"action": "/URI", "target_sha256": "b" * 64, "placement_observed": True}],
            },
            *[
                {
                    "sha256": safedocs_shas[idx],
                    "status": "missing",
                    "actions_observed": None,
                    "actions_without_target": None,
                    "targets_clipped": False,
                    "targets": [],
                }
                for idx in range(1, 10)
            ],
            {
                "sha256": safedocs_shas[10],
                "status": "unresolved",
                "actions_observed": 2,
                "actions_without_target": 2,
                "targets_clipped": False,
                "targets": [],
            },
        ]
        doc = {
            "schema_version": 1,
            "job_id": job["job_id"],
            "cohort": dict(admin.URI_COHORTS[jobs.URI_SAFEDOCS_REVIEW_KIND]),
            "selection_sha256": admin.URI_SEALS[jobs.URI_SAFEDOCS_REVIEW_KIND]["selection_sha256"],
            "records": records,
            "status_counts": {"missing": 9, "observed_targets": 1, "unresolved": 1},
        }
        current = {"doc": doc}

        def export_review(job_id):
            assert job_id == job["job_id"]
            return current["doc"]

        monkeypatch.setitem(sys.modules, "export_uri_review", SimpleNamespace(export_review=export_review))
        export = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert export["kind"] == "pdf-uri-safedocs-review"
        assert export["records"] == records

        bad_mutations = [
            lambda d: d["cohort"].__setitem__("extra_untyped", "https://example.invalid/raw"),
            lambda d: d["cohort"].__setitem__("model_evaluation_in_lab", 0),
            lambda d: d.__setitem__("selection_sha256", "0" * 64),
            lambda d: d["records"][5].__setitem__("sha256", "f" * 64),
            lambda d: d["records"][0]["targets"][0].__setitem__("target_sha256", "https://example.invalid/"),
            lambda d: d["records"][1]["targets"].append(dict(records[0]["targets"][0])),
            lambda d: d["records"][1].__setitem__("actions_observed", 1),
            lambda d: d["records"][10].__setitem__("actions_without_target", 1),
            lambda d: d["records"][0].__setitem__("targets_clipped", True),
            lambda d: d["records"][0]["targets"].clear(),
        ]
        for mutate in bad_mutations:
            current["doc"] = json.loads(admin.json_bytes(doc))
            mutate(current["doc"])
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.export_job(job["job_id"])


def test_bulk_export_only_reads_checkpoint_metadata(modules, monkeypatch):
    _, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        job, directory = setup_export(modules, monkeypatch, root, "pdf-static-bulk")
        producer = {"commit": job["commit"], "job_id": job["job_id"], "selection_sha256": "e" * 64}
        chunk0 = root / admin.BULK_OUTPUT / "chunks/chunk_00000"
        chunk1 = root / admin.BULK_OUTPUT / "chunks/chunk_00001"
        chunk0.mkdir(parents=True)
        chunk1.mkdir(parents=True)
        adopted_manifest = admin.json_bytes(
            {"schema_version": 1, "chunk_id": 0, "count": 500, "files": {"private": "f" * 64}}
        )
        unadopted_manifest = admin.json_bytes(
            {
                "schema_version": 1,
                "chunk_id": 1,
                "count": 250,
                "files": {"private": "d" * 64},
                "producer": {**producer, "job_id": "9" * 64},
            }
        )
        (chunk0 / "chunk_done.json").write_bytes(adopted_manifest)
        (chunk1 / "chunk_done.json").write_bytes(unadopted_manifest)
        plan_bytes = admin.json_bytes(
            {
                "job_id": job["job_id"],
                "output_root": admin.BULK_OUTPUT,
                "planned_denominator": 750,
                "selection_sha256": "e" * 64,
                "baseline": {
                    "checkpoint_sha256": [jobs.sha(adopted_manifest), jobs.sha(unadopted_manifest)],
                    "adopted_checkpoint_count": 1,
                    "replaced_checkpoints": {"1": jobs.sha(unadopted_manifest)},
                },
                "internal": "private metadata",
            }
        )
        (directory / "bulk_plan.json").write_bytes(plan_bytes)
        (directory / "result.json").write_bytes(admin.json_bytes(jobs.result(job, "failed", reason="worker_failed")))
        attempt = directory / "bulk_attempts" / ("b" * 32)
        attempt.mkdir(parents=True)
        (attempt / "result.json").write_bytes(admin.json_bytes({"status": "failed", "cleanup_verified": True}))
        pre_pilot = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert pre_pilot["chunks"] == []
        report_bytes = admin.json_bytes(
            {"commit": job["commit"], "plan_sha256": jobs.sha(plan_bytes), "counts": {"unexplained": 0}}
        )
        (directory / "bulk_pilot_report.json").write_bytes(report_bytes)
        (directory / "bulk_pilot_passed.json").write_bytes(
            admin.json_bytes(
                {
                    "commit": job["commit"],
                    "plan_sha256": jobs.sha(plan_bytes),
                    "report_sha256": jobs.sha(report_bytes),
                }
            )
        )
        post_pilot = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert post_pilot["chunks"] == [
            {
                "chunk_id": 0,
                "count": 500,
                "sha256": jobs.sha(adopted_manifest),
                "provenance": "adopted_baseline",
            }
        ]
        bad_report = admin.json_bytes(
            {"commit": job["commit"], "plan_sha256": jobs.sha(plan_bytes), "counts": {"unexplained": 1}}
        )
        (directory / "bulk_pilot_report.json").write_bytes(bad_report)
        (directory / "bulk_pilot_passed.json").write_bytes(
            admin.json_bytes(
                {
                    "commit": job["commit"],
                    "plan_sha256": jobs.sha(plan_bytes),
                    "report_sha256": jobs.sha(bad_report),
                }
            )
        )
        with pytest.raises(ValueError, match="bulk_pilot_report_invalid"):
            admin.export_job(job["job_id"])
        (directory / "bulk_pilot_report.json").write_bytes(report_bytes)
        (directory / "bulk_pilot_passed.json").write_bytes(
            admin.json_bytes(
                {
                    "commit": job["commit"],
                    "plan_sha256": jobs.sha(plan_bytes),
                    "report_sha256": jobs.sha(report_bytes),
                }
            )
        )
        rebuilt_manifest = admin.json_bytes(
            {
                "schema_version": 1,
                "chunk_id": 1,
                "count": 250,
                "files": {"private": "c" * 64},
                "producer": producer,
            }
        )
        (chunk1 / "chunk_done.json").write_bytes(rebuilt_manifest)
        raw = admin.export_job(job["job_id"])
        export = admin.validate_export(raw, job)
        assert b"private" not in raw
        assert export["chunks"] == [
            {
                "chunk_id": 0,
                "count": 500,
                "sha256": jobs.sha(adopted_manifest),
                "provenance": "adopted_baseline",
            },
            {
                "chunk_id": 1,
                "count": 250,
                "sha256": jobs.sha(rebuilt_manifest),
                "provenance": "produced_by_job",
            },
        ]
        assert export["attempts"][0]["cleanup_verified"] is True
        bad_count = json.loads(raw.decode("utf-8"))
        bad_count["plan"]["planned_denominator"] = 1
        bad_count["chunks"] = [{**export["chunks"][0], "count": 2}]
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(bad_count), job)
        for bad_key, bad_val in (("attempts", {}), ("chunks", "")):
            bad_bulk = json.loads(raw.decode("utf-8"))
            bad_bulk[bad_key] = bad_val
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.validate_export(admin.json_bytes(bad_bulk), job)


def test_cve_export_marks_corrupt_bundle_invalid(modules, monkeypatch):
    _, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        job, directory = setup_export(modules, monkeypatch, Path(temp), "pdf-static-cve")
        rows = [
            {
                "sample_id": f"cve_t4pdf:{admin.CVE_NAMES[index]}",
                "Label": "1",
                "pdf_relative_path": f"data/raw/cve_t4pdf/{admin.CVE_NAMES[index]}",
                "pdf_sha256": f"{index:064x}",
                "label_source": "reviewed manifest",
            }
            for index in range(job["limits"]["samples"])
        ]
        selection = {"job_id": job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))}
        (directory / "selection.json").write_bytes(admin.json_bytes(selection))
        (directory / "result.json").write_bytes(admin.json_bytes(jobs.result(job, "failed", reason="worker_failed")))
        bundles = directory / "private_bundles"
        bundles.mkdir()
        (bundles / "0000.json").write_bytes(b"{not-valid-bundle")
        (bundles / "0001.json").write_bytes(b" " * (jobs.pdf_bundle_limit("pdf-static-cve") + 2048))
        export = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert export["availability"] == {"invalid": 2, "missing": 3}
        assert export["rows"][0]["availability"] == "invalid"
        assert export["rows"][0]["source_bundle_sha256"] is not None
        assert export["rows"][1]["availability"] == "invalid"
        assert export["rows"][1]["source_bundle_sha256"] is None


def test_provision_auto_helpers_verifies_real_pinned_hashes_and_manifest(modules, monkeypatch):
    import json
    import shlex
    import stat as pystat

    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pinned = root / "malpdf"
        dest = root / "malpdf-auto"
        manifest = root / "auto_manifest.json"
        pinned.mkdir()
        for name, rel in auto.PINNED_HELPERS:
            (pinned / name).write_bytes((auto.ctl.REPO / rel).read_bytes().replace(b"\r\n", b"\n"))
        real_lstat = Path.lstat
        real_open = os.open
        real_close = os.close
        real_fsync = os.fsync
        stat_overrides = {}
        recorded_ops = {"chown": [], "chmod": [], "fchown": [], "fchmod": []}
        dir_flag = 1 << 30

        def fake_lstat(path_obj):
            info = real_lstat(path_obj)
            mode, uid = stat_overrides.get(Path(str(path_obj)), (None, 0))
            if mode is None:
                mode = pystat.S_IFDIR | 0o755 if pystat.S_ISDIR(info.st_mode) else pystat.S_IFREG | 0o644
            values = list(info)
            values[0] = mode
            values[4] = uid
            values[5] = 0
            return os.stat_result(values)

        def run_real_install(command, *, timeout=30, limit=auto.RECEIPT_LIMIT, payload=None):
            assert payload is not None
            assert command.startswith("sudo -n /usr/bin/python3 -I -B -c ")
            assert (
                auto.ADMIN_COMMAND == "sudo -n /usr/bin/python3 -I -B /usr/local/libexec/malpdf-auto/lab_oneshot_adm.py"
            )
            snippet = shlex.split(command)[-1]
            fake_out = io.StringIO()
            with monkeypatch.context() as patch:
                patch.setattr(sys, "argv", ["-"])
                patch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
                patch.setattr(sys, "stdout", fake_out)
                patch.setattr(Path, "lstat", fake_lstat)
                patch.setattr(os, "O_RDONLY", 0, raising=False)
                patch.setattr(os, "O_DIRECTORY", dir_flag, raising=False)
                patch.setattr(
                    os,
                    "chown",
                    lambda p, uid, gid: recorded_ops["chown"].append((Path(str(p)), uid, gid)),
                    raising=False,
                )
                patch.setattr(os, "chmod", lambda p, mode: recorded_ops["chmod"].append((Path(str(p)), mode)))
                patch.setattr(
                    os, "fchown", lambda fd, uid, gid: recorded_ops["fchown"].append((uid, gid)), raising=False
                )
                patch.setattr(os, "fchmod", lambda fd, mode: recorded_ops["fchmod"].append(mode), raising=False)
                patch.setattr(
                    os, "open", lambda p, flags, *a, **kw: -999 if flags & dir_flag else real_open(p, flags, *a, **kw)
                )
                patch.setattr(os, "close", lambda fd: None if fd == -999 else real_close(fd))
                patch.setattr(os, "fsync", lambda fd: None if fd == -999 else real_fsync(fd))
                exec(compile(snippet, "install_wrapper", "exec"), {"__name__": "__main__"})
            reply_raw = fake_out.getvalue().encode("utf-8")
            return json.loads(reply_raw), reply_raw

        monkeypatch.setattr(auto, "PINNED_LIB", pinned)
        monkeypatch.setattr(auto, "ADMIN_PATH", dest / "lab_oneshot_adm.py")
        monkeypatch.setattr(auto, "MANIFEST_PATH", manifest)
        monkeypatch.setattr(auto, "remote_json", run_real_install)
        monkeypatch.setattr(admin, "_stdlib_trusted_root_file", lambda path, mode=None: Path(path))
        cycle = auto.Cycle(root)
        reply = cycle.provision_auto_helpers()
        assert reply["installed"] is True
        assert set(reply["hashes"]) == {"lab_oneshot_adm.py", "lab_offline_oneshot.py"}
        assert set(recorded_ops["fchmod"]) >= {0o755, 0o600}
        assert all(pair == (0, 0) for pair in recorded_ops["fchown"])
        assert not (pinned / "lab_oneshot_adm.py").exists()
        admin.verify_auto_manifest(manifest, pinned, dest)
        stat_overrides[pinned.parent] = (pystat.S_IFDIR | 0o755, 1000)
        with pytest.raises(SystemExit, match="unsafe_install_parent"):
            cycle.provision_auto_helpers()
        stat_overrides.clear()
        stat_overrides[pinned / "lab_jobs.py"] = (pystat.S_IFREG | 0o664, 0)
        with pytest.raises(SystemExit, match="unsafe_pinned_helper"):
            cycle.provision_auto_helpers()
        stat_overrides.clear()
        (pinned / "lab_jobs.py").write_bytes(b"# tampered\n")
        with pytest.raises(SystemExit, match="pinned_helper_mismatch:lab_jobs.py"):
            cycle.provision_auto_helpers()
        with pytest.raises(ValueError, match="pinned_helper_mismatch:lab_jobs.py"):
            admin.verify_auto_manifest(manifest, pinned, dest)


def test_export_and_save_rolls_back_offline_on_receipt_or_firewall_failure(modules, monkeypatch):
    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(auto, "VMX", vmx)
        job = make_job(jobs, "pdf-static")
        state = {
            **cycle_state(auto, job, "SSH_RESTORED"),
            "hostonly_adapter_id": "ethernet1",
            "hostonly_vnet": "vmnet1",
            "offline_session_verified": True,
            "offline_log_sha256": "f" * 64,
            "verified_receipt_sha256": "e" * 64,
        }
        cycle = auto.Cycle(root, root / "runs")
        running = {"flag": True}
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def fake_vmrun(action, *args, **kwargs):
            if action == "stop":
                running["flag"] = False
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        cycle.write_state(state)
        monkeypatch.setattr(
            cycle,
            "verify_connected",
            lambda **_: (_ for _ in ()).throw(ValueError("hostonly_firewall_or_boot_unverified")),
        )
        with pytest.raises(ValueError, match="hostonly_firewall_or_boot_unverified"):
            cycle.export_and_save()
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle.write_state(state)
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: {"schema_version": 1})
        monkeypatch.setattr(auto, "remote_json", lambda *a, **kw: (_ for _ in ()).throw(ValueError("command_failed")))
        with pytest.raises(ValueError, match="command_failed"):
            cycle.export_and_save()
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED


def test_restore_ssh_rolls_back_offline_on_missing_or_incomplete_receipt(modules, monkeypatch):
    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        offline_vmx = auto.rewrite_vmx_network(VMX, "offline")
        vmx.write_bytes(offline_vmx)
        monkeypatch.setattr(auto, "VMX", vmx)
        job = make_job(jobs, "pdf-static")
        state = {
            **cycle_state(auto, job, "OFFLINE_COMPLETED"),
            "hostonly_adapter_id": "ethernet1",
            "hostonly_vnet": "vmnet1",
            "offline_session_verified": True,
            "offline_log_sha256": "f" * 64,
            "armed_utc": "2026-11-28T00:00:00+00:00",
        }
        cycle = auto.Cycle(root)
        cycle.write_state(state)
        monkeypatch.setattr(cycle, "log_proof", lambda: "f" * 64)
        monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: {})
        running = {"flag": False}
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def fake_vmrun(action, *args, **kwargs):
            if action == "start":
                running["flag"] = True
            elif action == "stop":
                running["flag"] = False
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        bad_receipt = {
            "schema_version": 1,
            "cycle_id": state["cycle_id"],
            "job_id": state["job_id"],
            "kind": state["kind"],
            "commit": state["commit"],
            "outcome": "unexpected_incomplete",
            "runner_status": None,
            "reason": None,
            "pty_confirmed": True,
            "pty_exit_code": 0,
            "workers_remaining": 0,
            "completed_utc": "2026-11-28T00:01:00+00:00",
        }
        monkeypatch.setattr(auto, "remote_json", lambda *a, **kw: (bad_receipt, admin.json_bytes(bad_receipt)))
        with pytest.raises(ValueError, match="unexpected_incomplete"):
            cycle.restore_ssh()
        assert cycle.state["stage"] == auto.BLOCKED
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        cycle.write_state(state)
        monkeypatch.setattr(auto, "remote_json", lambda *a, **kw: (_ for _ in ()).throw(ValueError("command_failed")))
        with pytest.raises(ValueError, match="command_failed"):
            cycle.restore_ssh()
        assert cycle.state["stage"] == auto.BLOCKED
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True


def test_revert_fails_if_evidence_removed_during_shutdown(modules, monkeypatch):
    auto, _, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        evidence_root = root / "runs"
        cycle = auto.Cycle(root, evidence_root)
        job = make_job(jobs, "pdf-static")
        folder = evidence_root / f"run_20261128T120000000000Z_{job['commit'][:12]}"
        folder.mkdir(parents=True)
        raw = b"{}\n"
        hashes = dict.fromkeys(auto.ARTIFACT_LIMITS, jobs.sha(raw))
        for name in hashes:
            (folder / name).write_bytes(raw)
        cycle.save(**cycle_state(auto, job, "EVIDENCE_SAVED"), evidence_dir=str(folder), artifact_sha256s=hashes)
        monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, cycle.state["snapshot_name"]])
        monkeypatch.setattr(cycle, "ensure_vm_stopped", lambda: (folder / "profile_export.json").unlink())
        monkeypatch.setattr(cycle, "require_stopped", lambda: None)
        monkeypatch.setattr(cycle, "vmrun", lambda *a, **kw: pytest.fail("revertToSnapshot called without evidence"))
        with pytest.raises(ValueError, match="evidence_missing_or_unreadable"):
            cycle.revert_snapshot()
        assert cycle.state["stage"] == "EVIDENCE_SAVED"


def test_boot_exec_success_order_and_disarm_before_run(modules, monkeypatch):
    _, admin, _, jobs = modules
    for name in [key for key in os.environ if key.startswith("SSH_")]:
        monkeypatch.delenv(name, raising=False)
    job = make_job(jobs, "pdf-static")
    cycle_id = "c" * 32
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        job_dir = root / job["job_id"]
        job_dir.mkdir()
        receipts_dir = root / "receipts"
        ticket = {
            "schema_version": 1,
            "cycle_id": cycle_id,
            "job_id": job["job_id"],
            "kind": job["kind"],
            "commit": job["commit"],
            "manifest_sha256": job["manifest_sha256"],
            "poweroff_on_finish": True,
            "armed_utc": "2026-11-28T00:00:00+00:00",
        }
        result = jobs.result(
            job,
            "passed",
            summary={
                "planned": 64,
                "completed": 64,
                "observed": 64,
                "partial": 0,
                "failed": 0,
                "primary_available": 64,
                "timeout": 0,
                "elapsed_ms": 100,
                "peak_rss_bytes": 1024,
                "status_counts": {"observed": 64},
            },
            environment={
                "mode": "offline",
                "guest_network_checked": True,
                "stdlib_dependencies_checked": True,
                "hypervisor_controls_attested": True,
            },
        )
        (job_dir / "result.json").write_bytes(admin.json_bytes(result))
        events = []
        monkeypatch.setattr(admin, "require_root", lambda: events.append("require_root"))
        monkeypatch.setattr(admin, "verify_auto_manifest", lambda: events.append("verify_auto_manifest"))
        monkeypatch.setattr(admin, "admin_lock", lambda: tempfile.TemporaryDirectory())
        monkeypatch.setattr(admin, "ticket_value", lambda: (events.append("ticket_value"), ticket)[1])
        monkeypatch.setattr(admin, "exclusive_job", lambda jid, k: (events.append("exclusive_job"), job)[1])
        monkeypatch.setattr(admin, "remove_arm", lambda: events.append("remove_arm"))
        monkeypatch.setattr(
            jobs,
            "guard_module",
            lambda: SimpleNamespace(
                lab_state=lambda: (
                    events.append("lab_state"),
                    {
                        "connected_interfaces": [],
                        "unknown_interfaces": [],
                        "shared_mounts": [],
                        "ssh_session": False,
                    },
                )[1]
            ),
        )
        monkeypatch.setattr(
            admin,
            "runner_account",
            lambda: ({}, SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir=str(root), pw_name="remnux")),
        )
        monkeypatch.setattr(jobs, "job_directory", lambda _: job_dir)
        monkeypatch.setattr(admin, "RECEIPTS_DIR", receipts_dir)
        monkeypatch.setattr(admin, "_ensure_receipt_dir", lambda path: (Path(path).mkdir(exist_ok=True), Path(path))[1])
        monkeypatch.setattr(admin, "atomic_write", lambda path, payload, mode: Path(path).write_bytes(payload))
        monkeypatch.setattr(admin, "worker_count", lambda _: (events.append("worker_count"), 0)[1])
        monkeypatch.setattr(admin.os, "sync", lambda: events.append("sync"), raising=False)

        def fake_as_runner(cmd, account, *, timeout, check=True):
            assert "remove_arm" in events
            events.append("as_runner")
            return 0, admin.json_bytes(
                {"confirmed": True, "exit_code": 0, "job_id": job["job_id"], "kind": job["kind"]}
            )

        def fake_bounded(cmd, limit, *, timeout, check=True):
            events.append(("poweroff", tuple(cmd)))
            return 0, b""

        monkeypatch.setattr(admin, "as_runner", fake_as_runner)
        monkeypatch.setattr(admin, "bounded_command", fake_bounded)
        receipt = admin.boot_exec()
        assert receipt["outcome"] == "terminal_result"
        assert (receipts_dir / f"{job['job_id']}.json").is_file()
        assert events.index("verify_auto_manifest") < events.index("remove_arm") < events.index("as_runner")
        assert events[-2:] == ["sync", ("poweroff", (admin.SYSTEMCTL, "poweroff"))]


def test_rotated_vmware_log_and_crash_reconciliation_and_resume_cycle_id(modules, monkeypatch):
    auto, _, _, jobs = modules
    config = auto.rewrite_vmx_network(VMX, "offline")
    header = (
        b"2026-11-28T00:00:00.100Z In(05) vmx Log for VMware Workstation pid=9488 version=17.5.2 build=build-23775571\n"
    )
    cont_header = (
        b"2026-11-28T00:00:02.000Z In(05) vmx Log for VMware Workstation pid=9488 version=17.5.2 build=build-23775571\n"
    )
    dict_lines = b"".join(b"2026-11-28T00:00:00.200Z In(05) vmx DICT   " + line + b"\n" for line in config.splitlines())
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        log = root / "vmware.log"
        rotated = root / "vmware-0.log"
        rotated_ok = (
            header
            + dict_lines
            + b"2026-11-28T00:00:00.500Z In(05) vmx "
            + auto.BOOT_MARKER
            + b"\n2026-11-28T00:00:01.000Z In(05) vmx "
            + auto.P9FS_DISABLED
            + b"\n"
        )
        rotated.write_bytes(rotated_ok)
        log.write_bytes(cont_header + b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        assert auto.verify_vmware_offline_session_log(log)
        log.write_bytes(b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        log.write_bytes(
            cont_header.replace(b" build=build-23775571", b"")
            + b"2026-11-28T00:00:02.500Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
        )
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        log.write_bytes(
            cont_header.replace(b"pid=9488", b"pid=9999")
            + b"2026-11-28T00:00:02.500Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
        )
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        log.write_bytes(
            cont_header.replace(b"00:00:02.000Z", b"00:00:00.500Z")
            + b"2026-11-28T00:00:02.500Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
        )
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        log.write_bytes(cont_header + b"2026-11-28T00:00:01.900Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        rotated.write_bytes(
            header
            + dict_lines
            + b"2026-11-28T00:00:00.800Z In(05) vmx "
            + auto.BOOT_MARKER
            + b"\n2026-11-28T00:00:00.600Z In(05) vmx "
            + auto.P9FS_DISABLED
            + b"\n"
        )
        log.write_bytes(cont_header + b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        rotated.write_bytes(header + dict_lines + b"2026-11-28T00:00:00.500Z In(05) vmx " + auto.BOOT_MARKER + b"\n")
        log.write_bytes(
            cont_header.replace(b"00:00:02.000Z", b"00:00:01.000Z")
            + b"2026-11-28T00:00:01.200Z In(05) vmx "
            + auto.P9FS_DISABLED
            + b"\n2026-11-28T00:00:02.500Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
        )
        assert auto.verify_vmware_offline_session_log(log)
        rotated.write_bytes(rotated_ok)
        log.write_bytes(
            cont_header.replace(b"00:00:02.000Z", b"00:00:00.900Z")
            + b"2026-11-28T00:00:02.500Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
        )
        with pytest.raises(ValueError, match="vmware_session_incomplete"):
            auto.verify_vmware_offline_session_log(log)
        log.write_bytes(cont_header + b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        assert auto.verify_vmware_offline_session_log(log, not_before="2026-11-28T00:00:00.000Z")
        rotated.write_bytes(rotated_ok.replace(b"2026-11-28T", b"2025-01-01T"))
        log.write_bytes(
            (cont_header + b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n").replace(
                b"2026-11-28T", b"2025-01-01T"
            )
        )
        with pytest.raises(ValueError, match="stale_vmware_log"):
            auto.verify_vmware_offline_session_log(log, not_before="2026-11-28T00:00:00.000Z")
        monkeypatch.setattr(auto, "STATE_ROOT", root)
        cycle = auto.Cycle(root)
        job = make_job(jobs, "pdf-static-bulk")
        state = {**cycle_state(auto, job, "BULK_PAUSED_SAVED")}
        cycle.write_state(state)
        assert auto.main(["resume-bulk", "--cycle-id", "e" * 32]) == 2
        vmx = root / "Lab.vmx"
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(auto, "VMX", vmx)
        cycle2 = auto.Cycle(root)
        cycle2.write_state({**cycle_state(auto, make_job(jobs, "pdf-static"), "AUTHORIZED"), "snapshot_op": "creating"})
        monkeypatch.setattr(cycle2, "ensure_vm_stopped", lambda: None)
        monkeypatch.setattr(cycle2, "require_stopped", lambda: None)
        monkeypatch.setattr(cycle2, "snapshots", lambda: [auto.CLEAN, cycle2.state["snapshot_name"]])
        cycle2.snapshot_create()
        assert cycle2.state["stage"] == "SNAPSHOTTED"
        assert cycle2.state["snapshot_op"] is None


def test_status_reports_live_vmware_metadata(modules, monkeypatch):
    auto, _, _, _ = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(auto, "VMX", vmx)
        monkeypatch.setattr(auto, "STATE_ROOT", root)
        monkeypatch.setattr(auto.Cycle, "running", lambda self: False)
        monkeypatch.setattr(auto.Cycle, "snapshots", lambda self: [auto.CLEAN])
        out = io.BytesIO()
        monkeypatch.setattr(auto.sys, "stdout", SimpleNamespace(buffer=out))
        assert auto.main(["status"]) == 0
        payload = auto.parse_json(out.getvalue())
        assert payload["active_cycle"] is None
        assert payload["vmware"]["snapshots"] == [auto.CLEAN]
        assert payload["vmware"]["vm_running"] is False
        assert payload["vmware"]["vmx_isolation"]["network_configuration"] == "host_only_nat_disconnected"


def test_as_runner_drops_groups_and_atomic_write_locks_mode(modules, monkeypatch):
    _, admin, offline, _ = modules
    account = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir="/home/remnux", pw_name="remnux")
    captured = {}

    def fake_bounded(cmd, limit, **kwargs):
        captured["cmd"] = cmd
        captured["limit"] = limit
        captured["kwargs"] = kwargs
        return 0, b"{}\n"

    monkeypatch.setattr(admin, "bounded_command", fake_bounded)
    code, out = admin.as_runner([admin.PYTHON, "-Es", "-B", str(admin.RUNNER_PATH)], account, timeout=30)
    assert (code, out) == (0, b"{}\n")
    assert captured["kwargs"]["user"] == 1001
    assert captured["kwargs"]["group"] == 1001
    assert captured["kwargs"]["extra_groups"] == []
    assert captured["kwargs"]["umask"] == 0o077
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["kwargs"]["env"]["HOME"] == "/home/remnux"
    assert not any(key.startswith("SSH_") for key in captured["kwargs"]["env"])

    ops = {"fchmod": [], "fchown": [], "fsync_dir": []}
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / f"{'a' * 64}.json"
        monkeypatch.setattr(admin.jobs, "trusted_path", lambda path: Path(path))
        monkeypatch.setattr(admin.os, "fchmod", lambda fd, mode: ops["fchmod"].append(mode), raising=False)
        monkeypatch.setattr(admin.os, "fchown", lambda fd, uid, gid: ops["fchown"].append((uid, gid)), raising=False)
        monkeypatch.setattr(admin.os, "fsync", lambda fd: None, raising=False)
        monkeypatch.setattr(admin, "fsync_dir", lambda path: ops["fsync_dir"].append(Path(path)))
        admin.atomic_write(target, b'{"ok":true}\n', 0o600)
        assert target.read_bytes() == b'{"ok":true}\n'
        assert ops["fchmod"] == [0o600]
        assert ops["fchown"] == [(0, 0)]
        assert ops["fsync_dir"] == [Path(temp)]
        assert offline.runner_env(account)["USER"] == "remnux"
        assert (
            b"ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/malpdf-auto/lab_oneshot_adm.py boot-exec"
            in admin.unit_contents()
        )


def test_export_and_save_local_write_failure_and_hard_stop_rollback(modules, monkeypatch):
    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(auto, "VMX", vmx)
        job = make_job(jobs, "pdf-static-cve")
        state = {
            **cycle_state(auto, job, "SSH_RESTORED"),
            "attempt": 1,
            "standing_rule_authorization": True,
            "hostonly_adapter_id": "ethernet1",
            "hostonly_vnet": "vmnet1",
            "offline_session_verified": True,
            "offline_log_sha256": "f" * 64,
            "armed_utc": "2026-11-28T00:00:00+00:00",
            "evidence_dir": None,
        }
        runner_res = jobs.result(job, "failed", reason="worker_failed")
        receipt = {
            "schema_version": 1,
            "cycle_id": state["cycle_id"],
            "job_id": job["job_id"],
            "kind": job["kind"],
            "commit": job["commit"],
            "outcome": "terminal_result",
            "runner_status": runner_res["status"],
            "reason": runner_res["reason"],
            "pty_confirmed": True,
            "pty_exit_code": 0,
            "workers_remaining": 0,
            "completed_utc": "2026-11-28T00:01:00+00:00",
        }
        receipt_raw = admin.json_bytes(receipt)
        state["verified_receipt_sha256"] = jobs.sha(receipt_raw)
        cve_rows = [
            {
                "index": index,
                "sha256": f"{index:064x}",
                "label": 1,
                "sample_id": f"cve_t4pdf:{admin.CVE_NAMES[index]}",
                "availability": "missing",
                "source_bundle_sha256": None,
                "numeric": None,
            }
            for index in range(job["limits"]["samples"])
        ]
        export_raw = admin.json_bytes(
            {
                "schema_version": 1,
                "job_id": job["job_id"],
                "kind": job["kind"],
                "selection_sha256": "d" * 64,
                "rows": cve_rows,
                "availability": {"missing": job["limits"]["samples"]},
            }
        )
        cycle = auto.Cycle(root, root / "runs")
        running = {"flag": True}
        stops = []
        stop_mode = {"soft_fails": False, "hard_fails": False}
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def fake_vmrun(action, *args, **kwargs):
            if action == "stop":
                stops.append(args[-1])
                if args[-1] == "soft" and stop_mode["soft_fails"]:
                    raise ValueError("soft_stop_failed")
                if args[-1] == "hard" and stop_mode["hard_fails"]:
                    raise ValueError("hard_stop_failed")
                running["flag"] = False
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: {"schema_version": 1})
        monkeypatch.setattr(
            auto,
            "remote_json",
            lambda command, **_: (
                (receipt, receipt_raw) if "read-receipt" in command else (runner_res, admin.json_bytes(runner_res))
            ),
        )
        monkeypatch.setattr(auto, "ssh", lambda *a, **kw: export_raw)

        real_atomic_write = auto.atomic_write

        def fail_staging_write(path, payload):
            if ".lab-evidence-" in str(path):
                raise PermissionError("staging_write_denied")
            return real_atomic_write(path, payload)

        monkeypatch.setattr(auto, "atomic_write", fail_staging_write)
        cycle.write_state(state)
        with pytest.raises(PermissionError, match="staging_write_denied"):
            cycle.export_and_save()
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED
        assert cycle.state["evidence_dir"] is None

        monkeypatch.setattr(auto, "atomic_write", real_atomic_write)
        running["flag"] = True
        stop_mode["soft_fails"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle.write_state(state)
        monkeypatch.setattr(
            cycle, "verify_connected", lambda **_: (_ for _ in ()).throw(ValueError("firewall_drifted"))
        )
        with pytest.raises(ValueError, match="firewall_drifted"):
            cycle.export_and_save()
        assert stops[-2:] == ["soft", "hard"]
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED

        saved_stages = []
        orig_save = cycle.save

        def record_save(**changes):
            if "stage" in changes:
                saved_stages.append(changes["stage"])
            return orig_save(**changes)

        monkeypatch.setattr(cycle, "save", record_save)
        running["flag"] = True
        stop_mode["hard_fails"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle.write_state(state)
        with pytest.raises(ValueError, match="hard_stop_failed"):
            cycle.export_and_save()
        assert saved_stages[0] == auto.BLOCKED
        assert cycle.state["stage"] == auto.BLOCKED
        assert "rollback_failed:hard_stop_failed" in cycle.state["blocked_reason"]


def test_classify_job_outcome_requires_verified_worker_cleanup(modules, monkeypatch):
    _, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        proc = root / "proc"
        pid_dir = proc / "1234"
        pid_dir.mkdir(parents=True)
        (pid_dir / "status").write_bytes(b"Uid:\t1000\t1000\t1000\t1000\n")
        (pid_dir / "cmdline").write_bytes(b"/usr/bin/python3\0-Es\0-B\0/opt/malpdf/profile_bootstrap.py\0")
        assert admin.worker_count(1000, proc) == 1

        bulk_job = make_job(jobs, "pdf-static-bulk")
        bulk_dir = root / "bulk_job"
        bulk_dir.mkdir()
        bulk_res = jobs.result(bulk_job, "failed", reason="worker_failed")
        (bulk_dir / "result.json").write_bytes(admin.json_bytes(bulk_res))
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        attempt = bulk_dir / "bulk_attempts" / ("b" * 32)
        attempt.mkdir(parents=True)
        (attempt / "result.json").write_bytes(admin.json_bytes({"status": "failed", "cleanup_verified": True}))
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        (attempt / "writer.json").write_bytes(admin.json_bytes({"pid": 4321, "pgid": 4321, "start_ticks": 99}))
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        (attempt / "workers").mkdir()
        (attempt / "result.json").write_bytes(admin.json_bytes({"cleanup_verified": True}))
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        (attempt / "result.json").write_bytes(admin.json_bytes({"status": "failed", "cleanup_verified": False}))
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        (attempt / "result.json").write_bytes(admin.json_bytes({"status": "failed", "cleanup_verified": True}))
        (attempt / "workers/987.json").write_bytes(admin.json_bytes({"pid": 987, "pgid": 987, "start_ticks": 555}))
        monkeypatch.setattr(admin, "_bulk_process_alive", lambda pid, ticks: pid == 987)
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("unexpected_incomplete", None)
        monkeypatch.setattr(admin, "_bulk_process_alive", lambda pid, ticks: False)
        assert admin.classify_job_outcome(bulk_job, bulk_dir, 0) == ("terminal_result", bulk_res)

        pdf_job = make_job(jobs, "pdf-static")
        pdf_dir = root / "pdf_job"
        pdf_dir.mkdir()
        pdf_res = jobs.result(
            pdf_job,
            "partial",
            summary={
                "planned": 64,
                "completed": 10,
                "observed": 10,
                "partial": 0,
                "failed": 0,
                "primary_available": 10,
                "timeout": 0,
                "elapsed_ms": 10,
                "peak_rss_bytes": 1024,
                "status_counts": {"observed": 10},
            },
            environment={
                "mode": "offline",
                "guest_network_checked": True,
                "stdlib_dependencies_checked": True,
                "hypervisor_controls_attested": True,
            },
        )
        (pdf_dir / "result.json").write_bytes(admin.json_bytes(pdf_res))
        assert admin.classify_job_outcome(pdf_job, pdf_dir, 0) == ("terminal_result", pdf_res)
        (pdf_dir / "pdf_halt.0.json").write_bytes(
            admin.json_bytes(
                {
                    "schema_version": 1,
                    "job_id": pdf_job["job_id"],
                    "shard": 0,
                    "index": 0,
                    "reason": "worker_cleanup_incomplete",
                }
            )
        )
        assert admin.classify_job_outcome(pdf_job, pdf_dir, 0) == ("unexpected_incomplete", None)

        diag_job = make_job(jobs, "pdf-diagnostic-replay")
        diag_dir = root / "diag_job"
        diag_dir.mkdir()
        diag_res = jobs.result(
            diag_job,
            "partial",
            summary={
                "planned": diag_job["limits"]["samples"],
                "completed": 1,
                "observed": 1,
                "partial": 0,
                "failed": 0,
                "primary_available": 1,
                "timeout": 0,
                "elapsed_ms": 10,
                "peak_rss_bytes": 1024,
                "status_counts": {"observed": 1},
            },
            environment={
                "mode": "offline",
                "guest_network_checked": True,
                "stdlib_dependencies_checked": True,
                "hypervisor_controls_attested": True,
            },
        )
        (diag_dir / "result.json").write_bytes(admin.json_bytes(diag_res))
        assert admin.classify_job_outcome(diag_job, diag_dir, 0) == ("unexpected_incomplete", None)
        outer_dir = diag_dir / "private_outer"
        outer_dir.mkdir()
        (outer_dir / "cleanup.json").write_bytes(
            admin.json_bytes({"run_id": "9" * 64, "exit_codes": [0] * diag_job["limits"]["workers"]})
        )
        assert admin.classify_job_outcome(diag_job, diag_dir, 0) == ("unexpected_incomplete", None)
        (outer_dir / "cleanup.json").write_bytes(
            admin.json_bytes({"run_id": diag_job["job_id"], "exit_codes": [0] * diag_job["limits"]["workers"]})
        )
        assert admin.classify_job_outcome(diag_job, diag_dir, 0) == ("terminal_result", diag_res)


def test_rollback_resists_state_write_failure_restore_save_and_recursion_error(modules, monkeypatch):
    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(auto, "VMX", vmx)
        job = make_job(jobs, "pdf-static")
        state = {
            **cycle_state(auto, job, "SSH_RESTORED"),
            "attempt": 1,
            "standing_rule_authorization": True,
            "hostonly_adapter_id": "ethernet1",
            "hostonly_vnet": "vmnet1",
            "offline_session_verified": True,
            "offline_log_sha256": "f" * 64,
            "armed_utc": "2026-11-28T00:00:00+00:00",
            "evidence_dir": None,
        }
        cycle = auto.Cycle(root, root / "runs")
        running = {"flag": True}
        stops = []
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def fake_vmrun(action, *args, **kwargs):
            if action == "stop":
                stops.append(args[-1])
                running["flag"] = False
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        cycle.write_state(state)
        monkeypatch.setattr(cycle, "save", lambda **_: (_ for _ in ()).throw(OSError("disk_readonly")))
        with pytest.raises(OSError, match="disk_readonly"):
            cycle.rollback_to_offline("boom")
        assert stops == ["soft"]
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        monkeypatch.undo()
        monkeypatch.setattr(auto, "VMX", vmx)
        running["flag"] = False
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "offline"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "OFFLINE_COMPLETED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        monkeypatch.setattr(cycle, "log_proof", lambda: "f" * 64)
        monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: {})
        good_receipt = {
            "schema_version": 1,
            "cycle_id": state["cycle_id"],
            "job_id": job["job_id"],
            "kind": job["kind"],
            "commit": job["commit"],
            "outcome": "terminal_result",
            "runner_status": "passed",
            "reason": None,
            "pty_confirmed": True,
            "pty_exit_code": 0,
            "workers_remaining": 0,
            "completed_utc": "2026-11-28T00:01:00+00:00",
        }
        monkeypatch.setattr(auto, "remote_json", lambda *a, **kw: (good_receipt, admin.json_bytes(good_receipt)))

        def fail_restore_save(**changes):
            if changes.get("stage") == "SSH_RESTORED":
                raise OSError("restore_save_denied")
            return auto.Cycle.save(cycle, **changes)

        monkeypatch.setattr(cycle, "save", fail_restore_save)
        with pytest.raises(OSError, match="restore_save_denied"):
            cycle.restore_ssh()
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED

        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state(state)
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", fake_vmrun)
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: (_ for _ in ()).throw(RecursionError("deep_json")))
        with pytest.raises(RecursionError):
            cycle.export_and_save()
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED

        stops.clear()
        running["flag"] = False
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "QUEUED_ARMED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])
        monkeypatch.setattr(auto, "VMX", vmx)

        def reachable_vmrun(action, *args, **kwargs):
            if action == "start":
                running["flag"] = True
                return 0, b""
            if action == "stop":
                stops.append(args[-1])
                if args[-1] == "soft":
                    raise ValueError("soft_failed")
                running["flag"] = False
                return 0, b""
            if action == "getGuestIPAddress":
                return 0, b"192.168.217.10\n"
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
        with pytest.raises(ValueError, match="offline_guest_reachable"):
            cycle.isolate_and_run()
        assert stops == ["soft", "hard"]
        assert cycle.state["stage"] == auto.BLOCKED

        stops.clear()
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "offline"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "SSH_RESTORED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
        monkeypatch.setattr(cycle, "save", lambda **_: (_ for _ in ()).throw(ValueError("unsafe_path")))
        with pytest.raises(ValueError, match="unsafe_path"):
            cycle.rollback_to_offline("boom")
        assert stops == ["soft", "hard"]
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        for timeout_action in ("getGuestIPAddress", "start"):
            stops.clear()
            running["flag"] = False
            vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
            cycle = auto.Cycle(root, root / "runs")
            cycle.write_state({**state, "stage": "QUEUED_ARMED"})
            monkeypatch.setattr(cycle, "running", lambda: running["flag"])
            monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])

            def timeout_vmrun(action, *args, target=timeout_action, **kwargs):
                if action == "start":
                    running["flag"] = True
                    if target == "start":
                        raise subprocess.TimeoutExpired(["vmrun"], 90)
                    return 0, b""
                if action == "getGuestIPAddress" and target == "getGuestIPAddress":
                    raise subprocess.TimeoutExpired(["vmrun"], 5)
                if action == "stop":
                    stops.append(args[-1])
                    if args[-1] == "soft":
                        raise ValueError("soft_failed")
                    running["flag"] = False
                    return 0, b""
                return 0, b""

            monkeypatch.setattr(cycle, "vmrun", timeout_vmrun)
            with pytest.raises(subprocess.TimeoutExpired):
                cycle.isolate_and_run()
            assert stops == ["soft", "hard"]
            assert running["flag"] is False
            assert cycle.state["stage"] == auto.BLOCKED

        for interrupt_action in ("start", "getGuestIPAddress"):
            stops.clear()
            running["flag"] = False
            vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
            cycle = auto.Cycle(root, root / "runs")
            cycle.write_state({**state, "stage": "QUEUED_ARMED"})
            monkeypatch.setattr(cycle, "running", lambda: running["flag"])
            monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])

            def interrupt_vmrun(action, *args, target=interrupt_action, **kwargs):
                if action == "start":
                    running["flag"] = True
                    if target == "start":
                        raise KeyboardInterrupt
                    return 0, b""
                if action == "getGuestIPAddress" and target == "getGuestIPAddress":
                    raise KeyboardInterrupt
                if action == "stop":
                    stops.append(args[-1])
                    if args[-1] == "soft":
                        raise ValueError("soft_failed")
                    running["flag"] = False
                    return 0, b""
                return 0, b""

            monkeypatch.setattr(cycle, "vmrun", interrupt_vmrun)
            with pytest.raises(KeyboardInterrupt):
                cycle.isolate_and_run()
            assert stops == ["soft", "hard"]
            assert running["flag"] is False
            assert cycle.state["stage"] == auto.BLOCKED

        stops.clear()
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "offline"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "SSH_RESTORED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
        monkeypatch.setattr(cycle, "save", lambda **_: (_ for _ in ()).throw(KeyboardInterrupt))
        with pytest.raises(KeyboardInterrupt):
            cycle.rollback_to_offline("ctrl_c")
        assert stops == ["soft", "hard"]
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        stops.clear()
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "SSH_RESTORED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: (_ for _ in ()).throw(KeyboardInterrupt))
        with pytest.raises(KeyboardInterrupt):
            cycle.export_and_save()
        assert stops == ["soft", "hard"]
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert cycle.state["stage"] == auto.BLOCKED

        for first_save_exc in (OSError("readonly"), ValueError("unsafe_path"), KeyboardInterrupt()):
            stops.clear()
            running["flag"] = True
            vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
            cycle = auto.Cycle(root, root / "runs")
            cycle.write_state({**state, "stage": "QUEUED_ARMED"})
            monkeypatch.setattr(cycle, "running", lambda: running["flag"])
            monkeypatch.setattr(cycle, "snapshots", lambda: [auto.CLEAN, state["snapshot_name"]])
            monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
            monkeypatch.setattr(cycle, "save", lambda exc=first_save_exc, **_: (_ for _ in ()).throw(exc))
            with pytest.raises(type(first_save_exc)):
                cycle.isolate_and_run()
            assert stops == ["soft", "hard"]
            assert running["flag"] is False
            assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        stops.clear()
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "SSH_RESTORED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def soft_interrupt_vmrun(action, *args, **kwargs):
            if action == "stop":
                stops.append(args[-1])
                if args[-1] == "soft":
                    raise KeyboardInterrupt
                running["flag"] = False
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", soft_interrupt_vmrun)
        with pytest.raises(KeyboardInterrupt):
            cycle.rollback_to_offline("boom")
        assert stops == ["soft", "hard"]
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        stops.clear()
        running["flag"] = True
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**state, "stage": "SSH_RESTORED"})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])
        monkeypatch.setattr(cycle, "vmrun", reachable_vmrun)
        save_calls = {"count": 0}

        def sysexit_first_save(**changes):
            save_calls["count"] += 1
            if save_calls["count"] == 1:
                raise SystemExit(3)
            return auto.Cycle.save(cycle, **changes)

        monkeypatch.setattr(cycle, "save", sysexit_first_save)
        with pytest.raises(SystemExit) as exit_info:
            cycle.rollback_to_offline("boom")
        assert exit_info.value.code == 3
        assert stops == ["soft", "hard"]
        assert running["flag"] is False
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True
        assert save_calls["count"] == 2


def test_runner_account_and_as_runner_reject_root_gid(modules, monkeypatch):
    _, admin, _, _ = modules
    with tempfile.TemporaryDirectory() as temp:
        monkeypatch.setattr(admin, "root_file", lambda path, mode=None: Path(path))
        monkeypatch.setattr(
            admin,
            "read_json",
            lambda path, limit: {
                "schema_version": 1,
                "uid": 1000,
                "data_root": temp,
                "python": str(Path(temp) / "python3"),
            },
        )
        bad_gid = SimpleNamespace(pw_uid=1000, pw_gid=0, pw_dir=temp, pw_name="remnux")
        monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda uid: bad_gid))
        with pytest.raises(ValueError, match="unsafe_runner_account"):
            admin.runner_account()
        with pytest.raises(ValueError, match="unsafe_runner_account"):
            admin.as_runner([admin.PYTHON, "-V"], bad_gid, timeout=5)


def test_publisher_and_fingerprint_nested_validation(modules, monkeypatch):
    from malpdf.extraction import numeric_feature_names
    from malpdf.features import contract_v3

    _, admin, _, jobs = modules
    assert admin.PUBLISHER_FEATURES == tuple(contract_v3.FEATURES)
    assert admin.NUMERIC_FEATURE_NAMES == numeric_feature_names.FEATURE_NAMES
    with tempfile.TemporaryDirectory() as temp:
        pub_job, _ = setup_export(modules, monkeypatch, Path(temp), "pdf-benign-ood")
        pub_sources = [
            src
            for src, count in admin.PUBLISHER_CONTRACTS["pdf-benign-ood"]["source_counts"].items()
            for _ in range(count)
        ]
        pub_rows = [
            {
                "sha256": f"{idx:064x}",
                "source": src,
                "id": f"{src}-{idx + 1:03d}",
                "tlsh": None,
                "status": "observed",
                "features": [1.0] * len(admin.PUBLISHER_FEATURES),
                "graph": [[[0.0] * 23], [0], [0], [0], [0]],
            }
            for idx, src in enumerate(pub_sources)
        ]
        pub_payload = {
            "schema_version": 1,
            "job_id": pub_job["job_id"],
            "manifest_sha256": admin.PUBLISHER_CONTRACTS["pdf-benign-ood"]["manifest_sha256"],
            "feature_order": list(admin.PUBLISHER_FEATURES),
            "runner": jobs.result(
                pub_job,
                "partial",
                summary={
                    "planned": 83,
                    "completed": 83,
                    "observed": 83,
                    "partial": 0,
                    "failed": 0,
                    "primary_available": 83,
                    "timeout": 0,
                    "elapsed_ms": 5,
                    "peak_rss_bytes": 1024,
                    "status_counts": {"observed": 83},
                },
                environment={
                    "mode": "offline",
                    "guest_network_checked": True,
                    "stdlib_dependencies_checked": True,
                    "hypervisor_controls_attested": True,
                },
            ),
            "rows": pub_rows,
        }
        pub_current = {"doc": pub_payload}
        monkeypatch.setitem(sys.modules, "export_benign_ood", SimpleNamespace(export=lambda _: pub_current["doc"]))
        assert admin.validate_export(admin.export_job(pub_job["job_id"]), pub_job)["rows"] == pub_rows

        pub_mutations = [
            lambda d: d["rows"][0]["features"].__setitem__(0, "secret/path"),
            lambda d: d["rows"][0].__setitem__("source", "https://example.invalid"),
            lambda d: d["rows"][0].__setitem__("id", "/etc/passwd"),
            lambda d: d.__setitem__("manifest_sha256", "f" * 64),
            lambda d: d["rows"][-1].__setitem__("id", d["rows"][0]["id"]),
        ]
        for mutate in pub_mutations:
            pub_current["doc"] = json.loads(admin.json_bytes(pub_payload))
            mutate(pub_current["doc"])
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.export_job(pub_job["job_id"])
        pub_current["doc"] = pub_payload

        pub_rows[0]["graph"] = [
            [[0.0] * 23 for _ in range(200)],
            [0] * 200,
            [i % 200 for i in range(40000)],
            [(i + 1) % 200 for i in range(40000)],
            [0] * 40000,
        ]
        assert admin.validate_export(admin.export_job(pub_job["job_id"]), pub_job)
        pub_rows[0]["graph"] = [[[0.0] * 23 for _ in range(201)], [0] * 201, [0], [0], [0]]
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.export_job(pub_job["job_id"])
        pub_rows[0]["graph"] = [
            [[0.0] * 23 for _ in range(200)],
            [0] * 200,
            [i % 200 for i in range(40001)],
            [(i + 1) % 200 for i in range(40001)],
            [0] * 40001,
        ]
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.export_job(pub_job["job_id"])
        pub_rows[0]["graph"] = [[[0.0] * 23], [0], [0], [0], [0]]

        valid_tlsh = "T1" + "0" * 70
        fp_job, fp_dir = setup_export(modules, monkeypatch, Path(temp), "pdf-tlsh-holdout")
        total_holdout = admin.HOLDOUT_INPUTS["references"] + admin.HOLDOUT_INPUTS["candidates"]
        ref_end = admin.HOLDOUT_INPUTS["references"]
        fp_rows = [{"sha256": f"{idx:064x}", "status": "measured", "tlsh": valid_tlsh} for idx in range(total_holdout)]
        fp_rows[ref_end + 2] = {"sha256": f"{ref_end + 2:064x}", "status": "input_unavailable", "tlsh": None}
        comparison = {
            f"{idx:064x}": (
                {"disposition": "near_duplicate", "distance": 12}
                if idx == ref_end
                else {"disposition": "candidate_fingerprint_unavailable", "distance": None}
                if idx == ref_end + 2
                else {"disposition": "no_near_duplicate_in_reference", "distance": 45}
            )
            for idx in range(ref_end, total_holdout)
        }
        fp_doc = {
            "schema_version": 1,
            "job_id": fp_job["job_id"],
            "kind": fp_job["kind"],
            "inputs": dict(admin.HOLDOUT_INPUTS),
            "fingerprints": fp_rows,
            "fingerprint_status_counts": {"measured": total_holdout - 1, "input_unavailable": 1},
            "new_malware_labels": 0,
            "runner_summary": {
                "planned": total_holdout,
                "completed": total_holdout,
                "observed": total_holdout - 1,
                "partial": 0,
                "failed": 1,
                "primary_available": total_holdout - 1,
                "timeout": 0,
                "elapsed_ms": 5,
                "peak_rss_bytes": 1024,
                "status_counts": {"observed": total_holdout - 1, "not_run": 1},
            },
            "candidate_comparison": comparison,
            "publisher_sha1_matches": 1,
        }
        assert admin.validate_export(admin.json_bytes(fp_doc), fp_job)["publisher_sha1_matches"] == 1

        cand0, cand1, cand2 = f"{ref_end:064x}", f"{ref_end + 1:064x}", f"{ref_end + 2:064x}"
        invalid_holdout = [
            (
                lambda d: d["candidate_comparison"].__setitem__(
                    cand1, {"disposition": "reference_coverage_incomplete", "distance": 75}
                )
            ),
            (lambda d: d["candidate_comparison"].__setitem__(cand2, {"disposition": "near_duplicate", "distance": 0})),
            (
                lambda d: d["candidate_comparison"].__setitem__(
                    cand0, {"disposition": "candidate_fingerprint_unavailable", "distance": None}
                )
            ),
            (lambda d: d["candidate_comparison"].pop(cand0)),
            (lambda d: d["runner_summary"].__setitem__("note", "free text")),
            (
                lambda d: d["runner_summary"].update(
                    {
                        "observed": total_holdout - 2,
                        "partial": 1,
                        "status_counts": {"observed": total_holdout - 2, "partial": 1, "not_run": 1},
                    }
                )
            ),
            (lambda d: d["fingerprints"][-1].__setitem__("sha256", f"{0:064x}")),
            (lambda d: d["inputs"].__setitem__("model_evaluation", 0)),
        ]
        for mutate in invalid_holdout:
            doc = {
                **fp_doc,
                "inputs": dict(fp_doc["inputs"]),
                "fingerprints": list(fp_doc["fingerprints"]),
                "runner_summary": dict(fp_doc["runner_summary"]),
                "candidate_comparison": {k: dict(v) for k, v in fp_doc["candidate_comparison"].items()},
            }
            doc["fingerprints"][-1] = dict(doc["fingerprints"][-1])
            mutate(doc)
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.validate_export(admin.json_bytes(doc), fp_job)

        inc_doc = {
            **fp_doc,
            "fingerprints": list(fp_doc["fingerprints"]),
            "fingerprint_status_counts": {"measured": total_holdout - 2, "tlsh_unavailable": 1, "input_unavailable": 1},
            "runner_summary": {
                **fp_doc["runner_summary"],
                "observed": total_holdout - 2,
                "partial": 1,
                "status_counts": {"observed": total_holdout - 2, "partial": 1, "not_run": 1},
            },
            "candidate_comparison": {
                k: ({"disposition": "reference_coverage_incomplete", "distance": 75} if k == cand1 else dict(v))
                for k, v in fp_doc["candidate_comparison"].items()
            },
        }
        inc_doc["fingerprints"][0] = {"sha256": f"{0:064x}", "status": "tlsh_unavailable", "tlsh": None}
        for k in list(inc_doc["candidate_comparison"]):
            if k not in (cand0, cand1, cand2):
                inc_doc["candidate_comparison"][k] = {"disposition": "reference_coverage_incomplete", "distance": 45}
        assert admin.validate_export(admin.json_bytes(inc_doc), fp_job)
        inc_doc["candidate_comparison"][cand1] = {"disposition": "no_near_duplicate_in_reference", "distance": 75}
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(inc_doc), fp_job)
        inc_doc["candidate_comparison"][cand1] = {"disposition": "reference_coverage_incomplete", "distance": None}
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(inc_doc), fp_job)

        pooled_job, _ = setup_export(modules, monkeypatch, Path(temp), "pdf-tlsh-pooled")
        total_pooled = admin.POOLED_INPUTS["samples"]
        pooled_rows = [
            {"sha256": f"{idx:064x}", "status": "measured", "tlsh": valid_tlsh, "sha1": "a" * 40}
            for idx in range(total_pooled - 2)
        ] + [
            {"sha256": f"{total_pooled - 2:064x}", "status": "tlsh_unavailable", "tlsh": None, "sha1": "b" * 40},
            {"sha256": f"{total_pooled - 1:064x}", "status": "input_unavailable", "tlsh": None},
        ]
        pooled_doc = {
            "schema_version": 1,
            "job_id": pooled_job["job_id"],
            "kind": pooled_job["kind"],
            "inputs": dict(admin.POOLED_INPUTS),
            "fingerprints": pooled_rows,
            "fingerprint_status_counts": {"measured": total_pooled - 2, "tlsh_unavailable": 1, "input_unavailable": 1},
            "new_malware_labels": 0,
            "runner_summary": {
                "planned": total_pooled,
                "completed": total_pooled,
                "observed": total_pooled - 2,
                "partial": 1,
                "failed": 1,
                "primary_available": total_pooled - 1,
                "timeout": 0,
                "elapsed_ms": 5,
                "peak_rss_bytes": 1024,
                "status_counts": {"observed": total_pooled - 2, "partial": 1, "not_run": 1},
            },
        }
        assert admin.validate_export(admin.json_bytes(pooled_doc), pooled_job)
        pooled_rows[0].pop("sha1")
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(pooled_doc), pooled_job)
        pooled_rows[0]["sha1"] = "a" * 40
        pooled_rows[-1]["sha1"] = "c" * 40
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(pooled_doc), pooled_job)
        pooled_rows[-1].pop("sha1")
        pooled_doc["inputs"]["model_evaluation"] = 0
        with pytest.raises(ValueError, match="export_shape_invalid"):
            admin.validate_export(admin.json_bytes(pooled_doc), pooled_job)


def test_bulk_resume_ignores_reused_pgid_only_after_reboot(modules, monkeypatch):
    _, admin, _, jobs = modules
    for name in [key for key in os.environ if key.startswith("SSH_")]:
        monkeypatch.delenv(name, raising=False)
    job = make_job(jobs, "pdf-static-bulk")
    cycle_id = "c" * 32
    result = jobs.result(job, "interrupted", reason="already_claimed")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        job_dir = root / job["job_id"]
        receipts_dir = root / "receipts"
        etc_dir = root / "etc"
        etc_dir.mkdir()
        ticket_path = etc_dir / "oneshot_ticket.json"
        unit_path = etc_dir / "malpdf-offline-oneshot.service"
        wants_link = etc_dir / "wants" / "malpdf-offline-oneshot.service"
        (job_dir / "bulk_attempts").mkdir(parents=True)
        (job_dir / "claim.json").write_bytes(b"{}")

        attempt1 = job_dir / "bulk_attempts" / ("a" * 32)
        original_writer = admin.json_bytes({"pid": 4321, "pgid": 4321, "start_ticks": 99})

        boot_state = {"id": "11111111-1111-1111-1111-111111111111"}
        live_pids = {"alive": set()}
        ticket_state = {
            "schema_version": 1,
            "cycle_id": cycle_id,
            "job_id": job["job_id"],
            "kind": job["kind"],
            "commit": job["commit"],
            "manifest_sha256": job["manifest_sha256"],
            "poweroff_on_finish": True,
            "armed_utc": "2026-11-28T00:00:00+00:00",
        }
        ticket_path.write_bytes(admin.json_bytes(ticket_state))

        monkeypatch.setattr(admin, "current_boot_id", lambda: boot_state["id"])
        monkeypatch.setattr(admin, "_bulk_process_alive", lambda pid, ticks: pid in live_pids["alive"])
        monkeypatch.setattr(admin, "require_root", lambda: None)
        monkeypatch.setattr(admin, "verify_auto_manifest", lambda: None)
        monkeypatch.setattr(admin, "admin_lock", lambda: tempfile.TemporaryDirectory())
        monkeypatch.setattr(admin, "exclusive_job", lambda jid, k: job)
        monkeypatch.setattr(
            admin,
            "runner_account",
            lambda: ({}, SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir=str(root), pw_name="remnux")),
        )
        monkeypatch.setattr(admin, "root_file", lambda path, mode=None: Path(path))
        monkeypatch.setattr(admin, "worker_count", lambda _: 0)
        monkeypatch.setattr(admin, "_ensure_receipt_dir", lambda path: (Path(path).mkdir(exist_ok=True), Path(path))[1])
        monkeypatch.setattr(admin, "atomic_write", lambda path, payload, mode: Path(path).write_bytes(payload))
        monkeypatch.setattr(admin, "fsync_dir", lambda _: None)
        monkeypatch.setattr(admin, "bounded_command", lambda *a, **kw: (0, b""))
        monkeypatch.setattr(admin, "RECEIPTS_DIR", receipts_dir)
        monkeypatch.setattr(admin, "TICKET_PATH", ticket_path)
        monkeypatch.setattr(admin, "UNIT_PATH", unit_path)
        monkeypatch.setattr(admin, "WANTS_LINK", wants_link)
        monkeypatch.setattr(admin.os, "sync", lambda: None, raising=False)
        monkeypatch.setattr(Path, "symlink_to", lambda self, target: self.write_text(str(target), encoding="ascii"))
        monkeypatch.setattr(jobs, "job_directory", lambda _: job_dir)
        monkeypatch.setattr(jobs, "read_result", lambda _: result)
        monkeypatch.setattr(
            jobs,
            "guard_module",
            lambda: SimpleNamespace(
                lab_state=lambda: {
                    "connected_interfaces": [],
                    "unknown_interfaces": [],
                    "shared_mounts": [],
                    "ssh_session": False,
                }
            ),
        )

        def fake_as_runner(cmd, account, *, timeout, check=True):
            if cmd[-1] == "_credentials":
                return 0, b"{}"
            attempt1.mkdir()
            (attempt1 / "workers").mkdir()
            (attempt1 / "result.json").write_bytes(
                admin.json_bytes({"status": "interrupted", "cleanup_verified": True})
            )
            (attempt1 / "writer.json").write_bytes(original_writer)
            (attempt1 / "workers" / "101.json").write_bytes(
                admin.json_bytes({"pid": 101, "pgid": 101, "start_ticks": 88})
            )
            return 0, admin.json_bytes(
                {"confirmed": True, "exit_code": 0, "job_id": job["job_id"], "kind": job["kind"]}
            )

        monkeypatch.setattr(admin, "as_runner", fake_as_runner)

        boot_receipt = admin.boot_exec()
        assert boot_receipt["outcome"] == "bulk_paused_resumable"
        attempts_file = receipts_dir / f"{job['job_id']}.attempts.json"
        assert attempts_file.is_file()
        assert json.loads(attempts_file.read_text(encoding="utf-8"))["verified_attempts"][attempt1.name]["boot_id"] == (
            "11111111-1111-1111-1111-111111111111"
        )

        live_pids["alive"] = {4321}
        with pytest.raises(ValueError, match="resume_receipt_required"):
            admin.arm(job["job_id"], job["kind"], cycle_id)

        boot_state["id"] = "22222222-2222-2222-2222-222222222222"
        armed_ticket = admin.arm(job["job_id"], job["kind"], cycle_id)
        assert armed_ticket["job_id"] == job["job_id"]

        (attempt1 / "writer.json").write_bytes(admin.json_bytes({"pid": 4321, "pgid": 4321, "start_ticks": 100}))
        with pytest.raises(ValueError, match="resume_receipt_required"):
            admin.arm(job["job_id"], job["kind"], cycle_id)

        (attempt1 / "writer.json").write_bytes(original_writer)
        boot_state["id"] = "33333333-3333-3333-3333-333333333333"
        attempt2 = job_dir / "bulk_attempts" / ("b" * 32)
        attempt2.mkdir()
        (attempt2 / "workers").mkdir()
        (attempt2 / "result.json").write_bytes(admin.json_bytes({"status": "interrupted", "cleanup_verified": True}))
        (attempt2 / "writer.json").write_bytes(admin.json_bytes({"pid": 5555, "pgid": 5555, "start_ticks": 200}))
        live_pids["alive"] = {4321, 5555}
        prior = admin._prior_boot_verified_digests(job, cycle_id)
        assert list(prior) == [attempt1.name]
        assert admin.classify_job_outcome(
            job, job_dir, 0, previous_attempts={attempt1.name}, prior_boot_verified=prior
        ) == ("unexpected_incomplete", None)
        live_pids["alive"] = {4321}
        assert admin.classify_job_outcome(
            job, job_dir, 0, previous_attempts={attempt1.name}, prior_boot_verified=prior
        ) == ("bulk_paused_resumable", result)


def test_isolated_receive_report_and_no_legacy_remote(modules, monkeypatch):
    auto, admin, _, jobs = modules
    assert not hasattr(auto, "REMOTE")
    assert "lab_windows" not in Path(auto.__file__).read_text(encoding="utf-8")
    job = make_job(jobs, "pdf-static")
    queued = jobs.result(job, "queued")
    calls = []
    out = io.BytesIO()
    monkeypatch.setattr(admin, "require_root", lambda: None)
    monkeypatch.setattr(admin, "verify_auto_manifest", lambda: calls.append("verify"))
    monkeypatch.setattr(
        admin,
        "runner_account",
        lambda: ({}, SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir="/home/remnux", pw_name="remnux")),
    )
    monkeypatch.setattr(jobs, "load_job", lambda _: job)
    monkeypatch.setattr(admin.sys, "stdout", SimpleNamespace(buffer=out))
    monkeypatch.setattr(admin.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"pkt")))

    def fake_as_runner(cmd, account, *, timeout, limit=admin.RECEIPT_LIMIT, payload=None):
        calls.append((tuple(cmd), payload))
        return 0, admin.json_bytes(queued)

    monkeypatch.setattr(admin, "as_runner", fake_as_runner)
    assert admin.main(["receive", "--job-id", job["job_id"]]) == 0
    assert admin.main(["report", "--job-id", job["job_id"]]) == 0
    assert calls[1][0][:5] == (admin.PYTHON, "-I", "-B", admin.ADMIN_PATH.as_posix(), "_receive")
    assert calls[1][1] == b"pkt"
    assert calls[3][0][:5] == (admin.PYTHON, "-I", "-B", admin.ADMIN_PATH.as_posix(), "_report")


def test_parent_export_validates_schema_and_redacts_error_paths(modules, monkeypatch, capsys):
    _, admin, _, jobs = modules
    job = make_job(jobs, "pdf-static-cve")
    monkeypatch.setattr(admin, "require_root", lambda: None)
    monkeypatch.setattr(admin, "verify_auto_manifest", lambda: None)
    monkeypatch.setattr(jobs, "load_job", lambda _: job)
    monkeypatch.setattr(
        admin,
        "runner_account",
        lambda: ({"python": "/usr/bin/python3"}, SimpleNamespace(pw_uid=1000, pw_gid=1000)),
    )
    bad_child = {
        "schema_version": 1,
        "job_id": job["job_id"],
        "kind": job["kind"],
        "selection_sha256": "d" * 64,
        "rows": [],
        "availability": {"missing": 0},
        "unexpected_url": "https://example.invalid/raw",
    }
    monkeypatch.setattr(admin, "as_runner", lambda *a, **kw: (0, admin.json_bytes(bad_child)))
    assert admin.main(["export", "--job-id", job["job_id"]]) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "blocked", "reason": "export_shape_invalid"}

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        bulk_job, bulk_dir = setup_export(modules, monkeypatch, root, "pdf-static-bulk")
        adopted = admin.json_bytes({"schema_version": 1, "chunk_id": 0, "count": 500, "files": {"p": "a" * 64}})
        chunk0 = root / admin.BULK_OUTPUT / "chunks/chunk_00000"
        chunk0.mkdir(parents=True)
        (chunk0 / "chunk_done.json").write_bytes(adopted)
        plan_bytes = admin.json_bytes(
            {
                "job_id": bulk_job["job_id"],
                "output_root": admin.BULK_OUTPUT,
                "planned_denominator": 500,
                "selection_sha256": "e" * 64,
                "baseline": {
                    "checkpoint_sha256": [jobs.sha(adopted)],
                    "adopted_checkpoint_count": 1,
                    "replaced_checkpoints": {},
                },
            }
        )
        (bulk_dir / "bulk_plan.json").write_bytes(plan_bytes)
        (bulk_dir / "result.json").write_bytes(
            admin.json_bytes(jobs.result(bulk_job, "failed", reason="worker_failed"))
        )
        report_bytes = admin.json_bytes(
            {"commit": bulk_job["commit"], "plan_sha256": jobs.sha(plan_bytes), "counts": {"unexplained": 0}}
        )
        (bulk_dir / "bulk_pilot_report.json").write_bytes(report_bytes)
        (bulk_dir / "bulk_pilot_passed.json").write_bytes(
            admin.json_bytes(
                {
                    "commit": bulk_job["commit"],
                    "plan_sha256": jobs.sha(plan_bytes),
                    "report_sha256": jobs.sha(report_bytes),
                }
            )
        )
        monkeypatch.setattr(jobs, "load_job", lambda _: bulk_job)
        genuine_bulk = json.loads(admin.export_job(bulk_job["job_id"]).decode("utf-8"))
        spoofed_bulk = json.loads(json.dumps(genuine_bulk))
        spoofed_bulk["chunks"][0]["provenance"] = "produced_by_job"
        monkeypatch.setattr(
            admin,
            "runner_account",
            lambda: ({"python": "/usr/bin/python3", "data_root": str(root)}, SimpleNamespace(pw_uid=1000, pw_gid=1000)),
        )
        monkeypatch.setattr(admin, "as_runner", lambda *a, **kw: (0, admin.json_bytes(spoofed_bulk)))
        assert admin.main(["export", "--job-id", bulk_job["job_id"]]) == 2
        assert json.loads(capsys.readouterr().out) == {"status": "blocked", "reason": "export_shape_invalid"}

    monkeypatch.setattr(jobs, "load_job", lambda _: job)
    monkeypatch.setattr(
        admin,
        "runner_account",
        lambda: (_ for _ in ()).throw(FileNotFoundError(2, "No such file or directory", "/etc/malpdf/runner.json")),
    )
    assert admin.main(["export", "--job-id", job["job_id"]]) == 2
    error_out = capsys.readouterr().out
    assert "/etc/malpdf" not in error_out
    assert json.loads(error_out) == {"status": "blocked", "reason": "io_failed"}

    startup_probe = (
        "import runpy, sys\n"
        "sys.platform = 'linux'\n"
        "sys.argv = ['/usr/local/libexec/malpdf-auto/lab_oneshot_adm.py', 'export', '--job-id', 'a' * 64]\n"
        "runpy.run_path('scripts/lab/lab_oneshot_adm.py')\n"
    )
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", startup_probe], capture_output=True, text=True)
    assert proc.returncode == 2
    assert proc.stderr == ""
    assert "/etc/malpdf" not in proc.stdout
    assert json.loads(proc.stdout) == {"status": "blocked", "reason": "io_failed"}


def test_boot_exec_unexpected_incomplete_exits_2_and_powers_off_when_clean(modules, monkeypatch, capsys):
    _, admin, _, jobs = modules
    for name in [key for key in os.environ if key.startswith("SSH_")]:
        monkeypatch.delenv(name, raising=False)
    job = make_job(jobs, "pdf-static-bulk")
    cycle_id = "d" * 32
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        job_dir = root / job["job_id"]
        job_dir.mkdir()
        receipts_dir = root / "receipts"
        ticket = {
            "schema_version": 1,
            "cycle_id": cycle_id,
            "job_id": job["job_id"],
            "kind": job["kind"],
            "commit": job["commit"],
            "manifest_sha256": job["manifest_sha256"],
            "poweroff_on_finish": True,
            "armed_utc": "2026-11-28T00:00:00+00:00",
        }
        monkeypatch.setattr(admin, "require_root", lambda: None)
        monkeypatch.setattr(admin, "verify_auto_manifest", lambda: None)
        monkeypatch.setattr(admin, "admin_lock", lambda: tempfile.TemporaryDirectory())
        monkeypatch.setattr(admin, "ticket_value", lambda: ticket)
        monkeypatch.setattr(admin, "exclusive_job", lambda jid, k: job)
        monkeypatch.setattr(admin, "remove_arm", lambda: None)
        monkeypatch.setattr(
            jobs,
            "guard_module",
            lambda: SimpleNamespace(
                lab_state=lambda: {
                    "connected_interfaces": [],
                    "unknown_interfaces": [],
                    "shared_mounts": [],
                    "ssh_session": False,
                }
            ),
        )
        monkeypatch.setattr(
            admin,
            "runner_account",
            lambda: ({}, SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir=str(root), pw_name="remnux")),
        )
        monkeypatch.setattr(jobs, "job_directory", lambda _: job_dir)
        monkeypatch.setattr(admin, "RECEIPTS_DIR", receipts_dir)
        monkeypatch.setattr(admin, "_ensure_receipt_dir", lambda path: (Path(path).mkdir(exist_ok=True), Path(path))[1])
        monkeypatch.setattr(admin, "atomic_write", lambda path, payload, mode: Path(path).write_bytes(payload))
        monkeypatch.setattr(admin, "as_runner", lambda *a, **kw: (2, b"{}"))
        monkeypatch.setattr(admin.os, "sync", lambda: None, raising=False)

        poweroffs = []
        monkeypatch.setattr(
            admin, "bounded_command", lambda cmd, limit, **kw: (poweroffs.append(tuple(cmd)), (0, b""))[1]
        )
        monkeypatch.setattr(admin, "worker_count", lambda _: 0)
        assert admin.main(["boot-exec"]) == 2
        assert json.loads(capsys.readouterr().out) == {"status": "blocked", "reason": "unexpected_incomplete"}
        assert poweroffs == [(admin.SYSTEMCTL, "poweroff")]
        saved_receipt = json.loads((receipts_dir / f"{job['job_id']}.json").read_text(encoding="utf-8"))
        assert saved_receipt["outcome"] == "unexpected_incomplete"
        assert saved_receipt["workers_remaining"] == 0

        poweroffs.clear()
        monkeypatch.setattr(admin, "worker_count", lambda _: 1)
        assert admin.main(["boot-exec"]) == 2
        assert json.loads(capsys.readouterr().out) == {"status": "blocked", "reason": "unexpected_incomplete"}
        assert poweroffs == []
        assert (
            json.loads((receipts_dir / f"{job['job_id']}.json").read_text(encoding="utf-8"))["workers_remaining"] == 1
        )


def test_verify_firewall_pre_network_and_status_gate(modules, monkeypatch):
    auto, admin, _, _ = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        unit = root / "malpdf-firewall.service"
        unit.write_text(
            "[Unit]\n"
            "Description=MalPDF 1-way stateful firewall\n"
            "DefaultDependencies=no\n"
            "After=local-fs.target\n"
            "Before=network-pre.target systemd-networkd.service\n"
            "Wants=network-pre.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            "ExecStart=/usr/local/sbin/malpdf-firewall phase2\n\n"
            "[Install]\n"
            "WantedBy=network-pre.target multi-user.target\n",
            encoding="utf-8",
        )
        wants_dir = root / "network-pre.target.wants"
        wants_dir.mkdir()
        wants_link = wants_dir / "malpdf-firewall.service"
        resolved_unit = unit.resolve()
        resolved_wants_dir = wants_dir.resolve()

        monkeypatch.setattr(admin, "_stdlib_trusted_root_file", lambda path, mode=None: Path(path).resolve())
        real_stat = Path.stat
        monkeypatch.setattr(
            Path,
            "stat",
            lambda self, *a, **kw: (
                SimpleNamespace(st_mode=0o040755, st_uid=0, st_gid=0)
                if self in (wants_dir, resolved_wants_dir)
                else real_stat(self, *a, **kw)
            ),
        )
        orig_is_symlink = Path.is_symlink
        orig_resolve = Path.resolve
        symlink_ok = {"flag": True}
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda self: symlink_ok["flag"] if self == wants_link else orig_is_symlink(self),
        )
        monkeypatch.setattr(
            Path,
            "resolve",
            lambda self, strict=False: resolved_unit if self == wants_link else orig_resolve(self, strict=strict),
        )
        assert admin.verify_firewall_pre_network(unit, wants_link) is True

        symlink_ok["flag"] = False
        with pytest.raises(ValueError, match="firewall_unit_invalid"):
            admin.verify_firewall_pre_network(unit, wants_link)
        symlink_ok["flag"] = True

        unit.write_text(unit.read_text(encoding="utf-8").replace("network-pre.target ", ""), encoding="utf-8")
        with pytest.raises(ValueError, match="firewall_unit_invalid"):
            admin.verify_firewall_pre_network(unit, wants_link)

        cycle = auto.Cycle(root)
        valid_status = {
            "schema_version": 1,
            "installed": True,
            "host_only_network": True,
            "firewall": {"mode": "phase2_locked", "nat_up": False},
            "offline_boot_netplan": True,
            "ticket_present": False,
            "unit_present": False,
            "wants_present": False,
            "firewall_pre_network": True,
        }
        monkeypatch.setattr(
            auto, "remote_json", lambda *a, **kw: ({**valid_status, "firewall_pre_network": False}, b"{}")
        )
        with pytest.raises(ValueError, match="hostonly_firewall_or_boot_unverified"):
            cycle.verify_connected()
        monkeypatch.setattr(auto, "remote_json", lambda *a, **kw: (valid_status, b"{}"))
        assert cycle.verify_connected()["firewall_pre_network"] is True


def test_isolation_snapshot_failure_and_adapter_drift_rollback_and_cancel_preserved(modules, monkeypatch):
    auto, _, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        vmx = root / "Lab.vmx"
        vmx.write_bytes(VMX)
        monkeypatch.setattr(auto, "VMX", vmx)
        job = make_job(jobs, "pdf-static")

        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state(cycle_state(auto, job, "QUEUED_ARMED"))
        monkeypatch.setattr(cycle, "snapshots", lambda: (_ for _ in ()).throw(ValueError("clean_snapshot_unverified")))
        monkeypatch.setattr(cycle, "running", lambda: False)
        with pytest.raises(ValueError, match="clean_snapshot_unverified"):
            cycle.isolate_and_run()
        assert cycle.state["stage"] == auto.BLOCKED
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**cycle_state(auto, job, "SSH_RESTORED"), "hostonly_adapter_id": "ethernet99"})
        monkeypatch.setattr(cycle, "running", lambda: False)
        cycle.rollback_to_offline("adapter_changed")
        assert cycle.state["stage"] == auto.BLOCKED
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state(
            {
                **cycle_state(auto, job, "OFFLINE_COMPLETED"),
                "offline_session_verified": True,
                "offline_log_sha256": "f" * 64,
            }
        )
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        monkeypatch.setattr(cycle, "running", lambda: False)
        monkeypatch.setattr(
            cycle, "log_proof", lambda: (_ for _ in ()).throw(ValueError("offline_session_proof_changed"))
        )
        with pytest.raises(ValueError, match="offline_session_proof_changed"):
            cycle.restore_ssh()
        assert cycle.state["stage"] == auto.BLOCKED
        assert auto.verify_vmx_offline_config(vmx.read_bytes()) is True

        stops = []
        running = {"flag": True}
        vmx.write_bytes(auto.rewrite_vmx_network(VMX, "host-only"))
        cycle = auto.Cycle(root, root / "runs")
        cycle.write_state({**cycle_state(auto, job, "SSH_RESTORED"), "offline_session_verified": True})
        monkeypatch.setattr(cycle, "running", lambda: running["flag"])

        def cancel_then_hard_fail(action, *args, **kwargs):
            if action == "stop":
                stops.append(args[-1])
                if args[-1] == "soft":
                    raise KeyboardInterrupt
                raise ValueError("hard_stop_failed")
            return 0, b""

        monkeypatch.setattr(cycle, "vmrun", cancel_then_hard_fail)
        monkeypatch.setattr(cycle, "verify_connected", lambda **_: (_ for _ in ()).throw(KeyboardInterrupt))
        with pytest.raises(KeyboardInterrupt):
            cycle.export_and_save()
        assert stops == ["soft", "hard"]
        assert "rollback_failed:hard_stop_failed" in cycle.state["blocked_reason"]


def test_terminal_failure_receipt_only_export_and_rotated_preboot_off_marker(modules, monkeypatch):
    auto, admin, _, jobs = modules
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pub_job, pub_dir = setup_export(modules, monkeypatch, root, "pdf-benign-v32-cohort")
        failed_runner = jobs.result(pub_job, "failed", reason="report_invalid")
        (pub_dir / "result.json").write_bytes(admin.json_bytes(failed_runner))
        monkeypatch.setitem(
            sys.modules,
            "export_v32_benign_cohort",
            SimpleNamespace(export=lambda _: (_ for _ in ()).throw(ValueError("offline_v32_result_unavailable"))),
        )
        raw = admin.export_job(pub_job["job_id"])
        exported = admin.validate_export(raw, pub_job)
        assert exported["export_mode"] == admin.FAILURE_EXPORT_MODE
        assert exported["unavailable_reason"] == admin.FAILURE_UNAVAILABLE_REASON
        assert exported["runner"] == failed_runner

        tlsh_job, tlsh_dir = setup_export(modules, monkeypatch, root, "pdf-tlsh-holdout")
        tlsh_failed = jobs.result(tlsh_job, "failed", reason="worker_timeout")
        (tlsh_dir / "result.json").write_bytes(admin.json_bytes(tlsh_failed))
        assert admin.validate_export(admin.export_job(tlsh_job["job_id"]), tlsh_job)["runner"] == tlsh_failed

        bulk_job = make_job(jobs, "pdf-static-bulk")
        for bad_job, bad_runner in (
            (
                pub_job,
                jobs.result(
                    pub_job,
                    "passed",
                    summary={
                        "planned": pub_job["limits"]["samples"],
                        "completed": pub_job["limits"]["samples"],
                        "observed": pub_job["limits"]["samples"],
                        "partial": 0,
                        "failed": 0,
                        "primary_available": pub_job["limits"]["samples"],
                        "timeout": 0,
                        "elapsed_ms": 1,
                        "peak_rss_bytes": 1024,
                        "status_counts": {"observed": pub_job["limits"]["samples"]},
                    },
                    environment={
                        "mode": "offline",
                        "guest_network_checked": True,
                        "stdlib_dependencies_checked": True,
                        "hypervisor_controls_attested": True,
                    },
                ),
            ),
            (bulk_job, jobs.result(bulk_job, "interrupted", reason="already_claimed")),
        ):
            payload = {
                "schema_version": 1,
                "job_id": bad_job["job_id"],
                "kind": bad_job["kind"],
                "export_mode": admin.FAILURE_EXPORT_MODE,
                "runner": bad_runner,
                "unavailable_reason": admin.FAILURE_UNAVAILABLE_REASON,
            }
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.validate_export(admin.json_bytes(payload), bad_job)

        config = auto.rewrite_vmx_network(VMX, "offline")
        header = b"2026-11-28T00:00:00.100Z In(05) vmx Log for VMware Workstation pid=9488 version=17.5.2 build=build-23775571\n"
        cont_header = b"2026-11-28T00:00:02.000Z In(05) vmx Log for VMware Workstation pid=9488 version=17.5.2 build=build-23775571\n"
        dict_lines = b"".join(
            b"2026-11-28T00:00:00.200Z In(05) vmx DICT   " + line + b"\n" for line in config.splitlines()
        )
        rotated = root / "vmware-0.log"
        log = root / "vmware.log"
        rotated.write_bytes(
            header
            + b"2026-11-28T00:00:00.150Z In(05) vmx "
            + auto.OFF_MARKER
            + b"\n"
            + dict_lines
            + b"2026-11-28T00:00:00.500Z In(05) vmx "
            + auto.BOOT_MARKER
            + b"\n"
            + b"2026-11-28T00:00:01.000Z In(05) vmx "
            + auto.P9FS_DISABLED
            + b"\n"
        )
        log.write_bytes(cont_header + b"2026-11-28T00:00:02.500Z In(05) vmx " + auto.OFF_MARKER + b"\n")
        assert auto.verify_vmware_offline_session_log(log)


def test_uri_head_eval_export_contract_and_fail_closed(modules, monkeypatch):
    _, admin, _, jobs = modules
    cohort_counts = admin.URI_HEAD_EVAL_COHORT["cohort_counts"]
    with tempfile.TemporaryDirectory() as temp:
        job, _ = setup_export(modules, monkeypatch, Path(temp), jobs.URI_HEAD_EVAL_KIND)
        records = []
        cohort_summary = {}
        idx = 0
        for cohort_name, count in cohort_counts.items():
            for _ in range(count):
                records.append(
                    {
                        "index": idx,
                        "sha256": f"{idx:064x}",
                        "cohort": cohort_name,
                        "eval_status": "observed",
                        "max_prob": 0.05 if idx == 0 else 0.01,
                        "tier": "benign",
                        "scored_url_count": 1 if idx == 0 else 0,
                        "allowlisted_url_count": 0,
                        "filtered_xml_xmp_count": 0,
                        "vector_counts": {"annot_uri": 1} if idx == 0 else {},
                        "top_url_vector": "annot_uri" if idx == 0 else None,
                        "heuristic_phishing": False,
                        "password_locked": False,
                    }
                )
                idx += 1
            cohort_summary[cohort_name] = {
                "count": count,
                "observed": count,
                "password_locked": 0,
                "ingest_error": 0,
                "missing_or_invalid": 0,
                "or_gate_count": 0,
                "gated_fusion_count": 0,
                "or_gate_rate": 0.0,
                "heuristic_phishing_count": 0,
                "max_prob_p50": 0.01,
                "max_prob_p95": 0.01,
                "max_prob_p99": 0.01,
                "max_prob_max": 0.05 if cohort_name == "benign_ood_v1" else 0.01,
                "total_scored_urls": 1 if cohort_name == "benign_ood_v1" else 0,
                "total_allowlisted_urls": 0,
                "total_filtered_xml_xmp": 0,
                "vector_counts": {"annot_uri": 1} if cohort_name == "benign_ood_v1" else {},
            }
        doc = {
            "schema_version": 1,
            "job_id": job["job_id"],
            "selection_sha256": "a" * 64,
            "cohort": dict(admin.URI_HEAD_EVAL_COHORT),
            "runner_status": "passed",
            "eval_status_counts": {"observed": len(records)},
            "cohort_summary": cohort_summary,
            "records": records,
        }
        current = {"doc": doc}
        monkeypatch.setitem(
            sys.modules,
            "export_uri_head_eval",
            SimpleNamespace(export_eval=lambda job_id: current["doc"]),
        )
        exported = admin.validate_export(admin.export_job(job["job_id"]), job)
        assert exported["kind"] == jobs.URI_HEAD_EVAL_KIND
        assert len(exported["records"]) == admin.URI_HEAD_EVAL_COHORT["samples"]

        bad_mutations = [
            lambda d: d["records"][0].__setitem__("cohort", "uri_review_v1"),
            lambda d: d["records"][0].__setitem__("top_url_vector", "https://phish.example/login"),
            lambda d: d["records"][0].__setitem__("raw_url", "https://phish.example/login"),
            lambda d: d["records"][0].__setitem__("max_prob", 1.2),
            lambda d: d["records"][0]["vector_counts"].__setitem__("https://raw.url", 1),
            lambda d: d["cohort"].__setitem__("samples", 623),
        ]
        for mutate in bad_mutations:
            current["doc"] = json.loads(admin.json_bytes(doc))
            mutate(current["doc"])
            with pytest.raises(ValueError, match="export_shape_invalid"):
                admin.export_job(job["job_id"])


def test_lab_firewall_pre_network_avoids_networkctl_deadlock(modules, monkeypatch):
    _, admin, _, _ = modules
    fw_script = Path(__file__).resolve().parents[1] / "scripts" / "lab" / "lab_firewall.sh"
    raw = fw_script.read_bytes()
    assert b"\r\n" not in raw
    text = raw.decode("utf-8")
    assert 'if [ -d "/sys/class/net/$host_if" ]; then' in text
    assert "/usr/bin/systemctl is-active --quiet systemd-networkd.service" in text
    assert "TimeoutStartSec=30" in text

    unit_match = re.search(r"cat > \"\$UNIT_PATH\" <<EOF\n(.*?)\nEOF", text, flags=re.DOTALL)
    assert unit_match is not None
    rendered_unit = unit_match.group(1).replace("$INSTALL_BIN", "/usr/local/sbin/malpdf-firewall") + "\n"

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        unit = root / "malpdf-firewall.service"
        unit.write_text(rendered_unit, encoding="utf-8", newline="\n")
        wants_dir = root / "wants"
        wants_dir.mkdir()
        wants_link = wants_dir / "malpdf-firewall.service"
        resolved_wants_dir = wants_dir.resolve()
        resolved_unit = unit.resolve()
        fake_stat = SimpleNamespace(st_mode=0o040755, st_uid=0, st_gid=0)
        monkeypatch.setattr(
            admin,
            "_stdlib_trusted_root_file",
            lambda path, expected_mode: unit if path == unit else path,
        )
        orig_stat = Path.stat
        monkeypatch.setattr(
            Path,
            "stat",
            lambda self, *a, **kw: fake_stat if self == resolved_wants_dir else orig_stat(self, *a, **kw),
        )
        orig_is_symlink = Path.is_symlink
        orig_resolve = Path.resolve
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda self: True if self == wants_link else orig_is_symlink(self),
        )
        monkeypatch.setattr(
            Path,
            "resolve",
            lambda self, strict=False: resolved_unit if self == wants_link else orig_resolve(self, strict=strict),
        )
        assert admin.verify_firewall_pre_network(unit, wants_link) is True
