"""Offline, dependency-free tests for LAB archive and read-only command guards."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent


def module(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ctl = module("labctl.py", "ctl")
lab = module("lab_side.py", "lab")
gate = module("lab_readonly.py", "gate")


def write_archive(target: Path, files: dict[str, bytes]):
    members = []
    with tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as tf:
        for name, blob in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(blob)
            tf.addfile(ti, io.BytesIO(blob))
            members.append({"path": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    return members


def test():
    for bad in ("../out.py", "src/../out.py", "src\\evil.py", "/tmp/out.py", "src/.secrets.py", "src/hi.pdf", "data/raw/a.py"):
        assert not ctl.safe_path(bad), bad
        assert not lab.valid_path(bad), bad
    assert ctl.safe_path("src/malpdf/static/parser.py")
    assert not gate.PATH_RE.fullmatch("src/x.py;echo secret")
    assert not gate.REV_RE.fullmatch("a" * 40 + ";id")

    with tempfile.TemporaryDirectory(prefix="malpdf-sec-tests-") as td:
        base = Path(td)
        lab.INBOX = base / "inbox"
        lab.RELEASES = base / "releases"
        lab.REPORTS = base / "reports"
        gate.REPORTS = lab.REPORTS
        lab.INBOX.mkdir()
        rev = "a" * 40
        files = {"src/malpdf/a.py": b"def foo():\n    return 42\n", "tests/test_syntax.py": b"assert True\n"}
        tarpath = lab.INBOX / (rev + ".tar")
        manifest = lab.INBOX / (rev + ".json")
        entries = write_archive(tarpath, files)
        manifest.write_text(json.dumps({"schema_version": 1, "commit": rev, "archive_sha256": hashlib.sha256(tarpath.read_bytes()).hexdigest(), "files": entries}))
        lab.install(rev)
        assert (lab.RELEASES / rev / "src/malpdf/a.py").read_bytes() == files["src/malpdf/a.py"]
        try:
            lab.install(rev)
            raise AssertionError("Existing releases must never be overwritten")
        except ValueError:
            pass
        lab.syntax(rev)
        report = json.loads((lab.REPORTS / (rev + ".json")).read_text())
        assert report["status"] == "passed" and report["file_count"] == 2
        assert ctl.validate_report(report, rev) == report
        assert gate.check(report, rev) == report

        (lab.RELEASES / rev / "src/malpdf/a.py").write_text("def broken(\n")
        lab.syntax(rev)
        report = json.loads((lab.REPORTS / (rev + ".json")).read_text())
        assert report["failed"] == 1 and report["issues"][0]["kind"] == "SyntaxError"
        assert "broken" not in json.dumps(report)

        original = os.environ.get("SSH_ORIGINAL_COMMAND")
        try:
            os.environ["SSH_ORIGINAL_COMMAND"] = "uname -a"
            assert gate.main() == 2
            os.environ["SSH_ORIGINAL_COMMAND"] = "report " + rev + "; cat /etc/shadow"
            assert gate.main() == 2
            os.environ["SSH_ORIGINAL_COMMAND"] = "report " + rev
            assert gate.main() == 0
        finally:
            if original is None:
                os.environ.pop("SSH_ORIGINAL_COMMAND", None)
            else:
                os.environ["SSH_ORIGINAL_COMMAND"] = original

        rev2 = "b" * 40
        evil = {"../escaped.py": b"evil", "src/ok.py": b"print('safe')\n"}
        bad_tar = lab.INBOX / (rev2 + ".tar")
        bad_entries = write_archive(bad_tar, evil)
        (lab.INBOX / (rev2 + ".json")).write_text(json.dumps({"schema_version": 1, "commit": rev2, "archive_sha256": hashlib.sha256(bad_tar.read_bytes()).hexdigest(), "files": bad_entries}))
        try:
            lab.install(rev2)
            raise AssertionError("Unsafe tar path must be refused")
        except ValueError:
            pass
        assert not (base / "escaped.py").exists()

    with tempfile.TemporaryDirectory(prefix="malpdf-git-tests-") as td:
        root = Path(td)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        (root / "src").mkdir()
        (root / "data" / "raw").mkdir(parents=True)
        (root / "src" / "safe.py").write_text("x = 1\n")
        (root / "data" / "raw" / "bad.pdf").write_bytes(b"%PDF-1.7\n")
        (root / ".gitignore").write_text("data/\n")
        subprocess.run(["git", "-C", str(root), "add", "src/safe.py", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "safe source"], check=True)
        ctl.REPO = root
        ctl.OUT = root.parent / (root.name + "-pkg")
        commit, archive, manifest = ctl.prepare()
        with tarfile.open(archive, "r:") as tf:
            assert tf.getnames() == ["src/safe.py"]
        assert len(json.loads(manifest.read_text())["files"]) == 1
        import shutil
        shutil.rmtree(ctl.OUT)

    print("PASS: source package, SHA checks, new-only release, path rejection, syntax-only diagnostics, forced-command validation, untracked PDF exclusion")


if __name__ == "__main__":
    test()
