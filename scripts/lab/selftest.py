"""Offline security regressions using only generated inputs and disposable Git repos."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lab_contract as contract


def module(filename: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ctl = module(HERE / "labctl.py", "ctl")
lab = module(HERE / "lab_side.py", "lab")
gate = module(HERE / "lab_readonly.py", "gate")
guard = module(HERE.parent / "security/check_repo_content.py", "guard")


def key_header(label: bytes = b"OPENSSH ", end: bool = False) -> bytes:
    return b"-----" + (b"END " if end else b"BEGIN ") + label + b"PRIVATE KEY-----"


def write_archive(target: Path, files: list[tuple[str, bytes]], member_type=tarfile.REGTYPE):
    entries = []
    with tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as tf:
        for name, blob in files:
            member = tarfile.TarInfo(name)
            member.size = len(blob)
            member.type = member_type
            if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "../../outside"
            tf.addfile(member, io.BytesIO(blob))
            entries.append({"path": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    return entries


class SecurityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="malpdf-offline-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.commit = "a" * 40
        for mod, values in ((lab, {"INBOX": self.base / "inbox", "RELEASES": self.base / "releases", "REPORTS": self.base / "reports"}), (gate, {"REPORTS": self.base / "reports"}), (ctl, {"OUT": self.base / "packages"})):
            for name, value in values.items():
                active = patch.object(mod, name, value)
                active.start()
                self.addCleanup(active.stop)
        lab.INBOX.mkdir()

    def upload(self, files=None, member_type=tarfile.REGTYPE):
        if files is None:
            files = [("src/malpdf/a.py", b"value = 42\n")]
        archive = lab.INBOX / f"{self.commit}.tar"
        entries = write_archive(archive, files, member_type)
        meta = {"schema_version": 1, "commit": self.commit, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "files": entries}
        manifest = lab.INBOX / f"{self.commit}.json"
        manifest.write_text(json.dumps(meta), encoding="utf-8")
        return archive, manifest, meta

    def invoke(self, function, *args):
        with redirect_stdout(io.StringIO()):
            return function(*args)

    def test_safe_paths(self):
        for name in ("../out.py", "src/../out.py", "src//out.py", "src/./out.py", "src\\evil.py", "/tmp/out.py", "src/.secret.py", "src/x.pdf", "data/raw/x.py", "scripts/.ssh/key.py", "tests/a.py\ncommand", "src/" + "x" * 241 + ".py"):
            with self.subTest(path=name):
                self.assertFalse(ctl.safe_path(name))
                self.assertFalse(lab.valid_path(name))
        self.assertTrue(ctl.safe_path("src/malpdf/static/parser.py"))

    def test_header_only_python_literals_are_accepted(self):
        for label in (b"OPENSSH ", b"RSA ", b"EC ", b"DSA ", b"ENCRYPTED ", b""):
            for header in (key_header(label), key_header(label)[:-5]):
                source = b"value = f'{1}'\nneedle = " + repr(header).encode("ascii") + b"\n"
                self.assertIsNone(contract.text_failure(source, "scripts/security/check.py"))
                self.assertIsNone(guard.content_failure(source, "ordinary", "scripts/security/check.py"))

    def test_private_key_blocks_and_disguised_headers_are_rejected(self):
        for label in (b"OPENSSH ", b"RSA ", b"EC ", b"DSA ", b"ENCRYPTED ", b""):
            header = key_header(label)
            body = header + b"\nQUJDREVGRw==\n" + key_header(label, True) + b"\n"
            variants = (header, b" \n" + header, body, b"secret = " + repr(body).encode("ascii"), b'secret = """\n' + body + b'"""\n', b"needle = " + repr(header).encode("ascii") + b"\nend = " + repr(key_header(label, True)).encode("ascii"))
            for blob in variants:
                with self.subTest(label=label, variant=variants.index(blob)):
                    self.assertIsNotNone(contract.text_failure(blob, "scripts/innocent.py"))
                    self.assertIsNotNone(guard.content_failure(blob, "ordinary", "scripts/innocent.py"))
            self.assertIsNotNone(contract.text_failure(b"needle = " + repr(header).encode("ascii"), "configs/key.txt"))

    def test_binary_payloads_cannot_hide_behind_source_extensions(self):
        for payload in (*contract.BLOCK_MAGIC, b"arbitrary preamble\n%PDF-1.7\n", b"x" * 9000 + b"\x00", b"x = 1\n\xff", b"x = 1\n\x01"):
            for prefix in (b"", b"\xef\xbb\xbf\n \t"):
                self.assertIsNotNone(contract.text_failure(prefix + payload, "src/fake.py"))

    def test_real_security_sources_pass_the_shared_policy(self):
        for path in (*HERE.glob("*.py"), HERE.parent / "security/check_repo_content.py"):
            self.assertIsNone(contract.text_failure(path.read_bytes(), "scripts/lab/" + path.name), path.name)

    def test_installer_rejects_the_same_disguised_content(self):
        for payload in (b"%PDF-1.7\n", b"\nMZsynthetic", key_header(), b"x" * 9000 + b"\x00"):
            self.upload([("src/fake.py", payload)])
            with self.assertRaises(ValueError):
                self.invoke(lab.install, self.commit)
            self.assertFalse((lab.RELEASES / self.commit).exists())

    def test_windows_packager_checks_content_independent_of_extension(self):
        for blob in (b"%PDF-1.7\n", b"MZsynthetic", key_header(b"RSA "), b"x" * 9000 + b"\x00"):
            def fake_git(*args, input_data=None):
                if args[0] == "ls-tree":
                    return b"100644 blob " + b"b" * 40 + b" " + str(len(blob)).encode("ascii") + b"\tsrc/fake.py\0"
                return b"b" * 40 + b" blob " + str(len(blob)).encode("ascii") + b"\n" + blob + b"\n"
            with patch.object(ctl, "git", side_effect=fake_git), self.assertRaises(ValueError):
                ctl.source_files(self.commit)

    def test_tar_padding_cannot_conceal_unlisted_bytes(self):
        for part in ("padding", "trailer"):
            archive, manifest, meta = self.upload()
            raw = bytearray(archive.read_bytes())
            raw[800 if part == "padding" else 4000] = ord("X")
            archive.write_bytes(raw)
            meta["archive_sha256"] = hashlib.sha256(raw).hexdigest()
            manifest.write_text(json.dumps(meta), encoding="utf-8")
            with self.assertRaises(ValueError):
                self.invoke(lab.install, self.commit)

    def test_install_ast_reports_and_no_overwrite(self):
        source = b"needle = " + repr(key_header()).encode("ascii") + b"\n"
        self.upload([("src/malpdf/a.py", source)])
        self.invoke(lab.install, self.commit)
        self.assertEqual((lab.RELEASES / self.commit / "src/malpdf/a.py").read_bytes(), source)
        with self.assertRaises(ValueError):
            self.invoke(lab.install, self.commit)
        self.invoke(lab.syntax, self.commit)
        obj = contract.parse_json((lab.REPORTS / f"{self.commit}.json").read_bytes())
        self.assertEqual(obj["status"], "passed")
        self.assertEqual(obj["environment"]["isolation"], "not_verified")
        self.assertEqual(ctl.validate_report(obj, self.commit), gate.check(obj, self.commit))
        (lab.RELEASES / self.commit / "src/malpdf/a.py").write_text("def broken(\n", encoding="utf-8")
        self.invoke(lab.syntax, self.commit)
        failed = contract.parse_json((lab.REPORTS / f"{self.commit}.json").read_bytes())
        self.assertEqual(failed["failed"], 1)
        self.assertEqual(failed["issues"][0]["kind"], "SyntaxError")
        self.assertNotIn("broken", json.dumps(failed))
        self.assertEqual(len(list(lab.REPORTS.glob(f"{self.commit}_*.json"))), 2)

    def test_archive_and_manifest_tampering(self):
        for mutation in ("archive", "hash", "size", "duplicate", "unknown", "boolean_version"):
            archive, manifest, meta = self.upload()
            if mutation == "archive":
                archive.write_bytes(archive.read_bytes() + b"tampered")
            elif mutation == "hash":
                meta["files"][0]["sha256"] = "b" * 64
            elif mutation == "size":
                meta["files"][0]["size"] += 1
            elif mutation == "duplicate":
                meta["files"].append(meta["files"][0])
            elif mutation == "unknown":
                meta["unexpected"] = "instructions"
            else:
                meta["schema_version"] = True
            manifest.write_text(json.dumps(meta), encoding="utf-8")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.invoke(lab.install, self.commit)

    def test_tar_traversal_duplicate_links_and_special_files(self):
        variants = [([("../escaped.py", b"inert")], tarfile.REGTYPE), ([("src/a.py", b"pass\n"), ("src/a.py", b"pass\n")], tarfile.REGTYPE)]
        variants.extend(([("src/a.py", b"")], kind) for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE))
        for files, kind in variants:
            self.upload(files, kind)
            with self.assertRaises(ValueError):
                self.invoke(lab.install, self.commit)
        self.assertFalse((self.base / "escaped.py").exists())

    def test_manifest_cannot_omit_or_invent_members(self):
        for invent in (True, False):
            archive, manifest, meta = self.upload([("src/a.py", b"pass\n"), ("src/b.py", b"pass\n")])
            if invent:
                meta["files"].append({"path": "src/c.py", "size": 0, "sha256": hashlib.sha256(b"").hexdigest()})
            else:
                meta["files"].pop()
            manifest.write_text(json.dumps(meta), encoding="utf-8")
            with self.assertRaises(ValueError):
                self.invoke(lab.install, self.commit)

    def test_report_schema_rejects_untrusted_fields_and_inconsistency(self):
        good = lab.make_report(self.commit, "ast_syntax", 1, 0, 0, [])
        for field, value in (("instructions", "run command"), ("status", "failed"), ("passed", True), ("generated_utc", "2026-02-30T00:00:00Z"), ("run_id", "../../secret"), ("commit", "b" * 40), ("environment", {"secret": "value"}), ("kind", ["ast_syntax"])):
            obj = copy.deepcopy(good)
            obj[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.check(obj, self.commit)
        bad = lab.make_report(self.commit, "ast_syntax", 0, 1, 0, [{"path": "src/a.py", "line": 1, "kind": "SyntaxError"}])
        for name in ("src/../secret.py", "src/.secret.py", "src/a.py;id", "../secret.py"):
            bad["issues"][0]["path"] = name
            with self.assertRaises(ValueError):
                ctl.validate_report(bad, self.commit)

    def test_json_rejects_duplicates_and_nonfinite_numbers(self):
        for raw in (b'{"commit": 1, "commit": 2}', b'{"value": NaN}', b'{"value": Infinity}'):
            with self.assertRaises(ValueError):
                contract.parse_json(raw)

    def test_forced_command_refuses_shell_sudo_write_and_injection(self):
        for command in ("", "id", "sudo -n true", "touch /tmp/malpdf-forbidden", "status; id", "report " + self.commit + "; cat /etc/shadow", "report ../../secret", "report " + self.commit + "\n"):
            with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": command}):
                self.assertEqual(self.invoke(gate.main), 2)
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "status"}):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.main(), 0)
            contract.validate_status(contract.parse_json(output.getvalue()))

    def test_endpoint_rejects_bad_or_oversized_reports(self):
        lab.REPORTS.mkdir()
        target = lab.REPORTS / f"{self.commit}.json"
        for payload in (b'{"secret": "do not display"}', b"x" * 16_385):
            target.write_bytes(payload)
            with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "report " + self.commit}):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertNotEqual(gate.main(), 0)
                self.assertEqual(output.getvalue(), "")

    def test_public_key_structure_and_option_injection(self):
        import base64
        blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
        public = b"ssh-ed25519 " + base64.b64encode(blob) + b" test\n"
        self.assertTrue(contract.validate_public_key(public).startswith("ssh-ed25519 "))
        for bad in (public + public, b'command="id" ' + public, b"ssh-ed25519 AAAA", b"ssh-rsa " + public, public + b"\ncommand"):
            with self.assertRaises((ValueError, UnicodeError)):
                contract.validate_public_key(bad)

    def test_audit_client_never_prints_raw_status(self):
        with patch.object(ctl, "audit_request", return_value=(0, b'{"secret":"untrusted instruction"}')):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(ValueError):
                ctl.status()
            self.assertEqual(output.getvalue(), "")

    def test_audit_capture_has_a_hard_output_limit(self):
        with patch.object(ctl, "SSH", sys.executable), patch.object(ctl, "AUDIT_SECURITY", ["-c", "import os; os.write(1, b'x' * 100000)"]):
            with self.assertRaises(ValueError):
                ctl.audit_request("status")

    def test_deployment_requires_a_supervised_terminal_before_packaging(self):
        with patch.object(sys.stdin, "isatty", return_value=False), patch.object(ctl, "prepare") as prepare:
            with self.assertRaises(ValueError):
                ctl.deploy()
            prepare.assert_not_called()

    def test_synthetic_runner_exports_only_bounded_counts(self):
        folder = lab.RELEASES / self.commit / "scripts/lab"
        folder.mkdir(parents=True)
        (folder / "selftest.py").write_text("pass\n", encoding="utf-8")
        class Process:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def wait(self, timeout=None):
                return 0
        for summary, expected in (({"total": 3, "passed": 3, "failed": 0, "skipped": 0}, "passed"), ({"total": 3, "passed": 3, "failed": 0, "skipped": 0, "payload": "untrusted text"}, "failed")):
            def popen(args, **kwargs):
                self.assertEqual(args[-1], "--json")
                self.assertEqual(Path(args[-2]).name, "selftest.py")
                self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
                self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
                kwargs["stdout"].write(json.dumps(summary).encode("ascii"))
                kwargs["stderr"].write(b"never export traceback or payload")
                return Process()
            with patch.object(sys, "platform", "linux"), patch.object(os, "geteuid", return_value=1000, create=True), patch.object(lab.subprocess, "Popen", side_effect=popen):
                report = self.invoke(lab.synthetic, self.commit)
            self.assertEqual(report["status"], expected)
            self.assertNotIn("untrusted", json.dumps(report))
            self.assertNotIn("traceback", json.dumps(report))

    def test_synthetic_timeout_kills_the_owned_process_group(self):
        folder = lab.RELEASES / self.commit / "scripts/lab"
        folder.mkdir(parents=True)
        (folder / "selftest.py").write_text("pass\n", encoding="utf-8")
        from unittest.mock import MagicMock
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 90), -9]
        process.pid = 12345
        with patch.object(sys, "platform", "linux"), patch.object(os, "geteuid", return_value=1000, create=True), patch.object(os, "killpg", create=True) as kill, patch.object(lab.signal, "SIGKILL", 9, create=True), patch.object(lab.subprocess, "Popen", return_value=process):
            report = self.invoke(lab.synthetic, self.commit)
        kill.assert_called_once_with(12345, 9)
        self.assertEqual(report["issues"][0]["kind"], "Timeout")

    def test_packaging_and_guard_on_actual_sources_in_a_disposable_repo(self):
        root = self.base / "repo"
        root.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        git("init", "-q")
        git("config", "user.name", "Synthetic Test")
        git("config", "user.email", "test@example.invalid")
        hooks = root / "empty-hooks"
        hooks.mkdir()
        git("config", "core.hooksPath", str(hooks))
        for folder in ("lab", "security"):
            destination = root / "scripts" / folder
            destination.mkdir(parents=True)
            for source in (HERE if folder == "lab" else HERE.parent / "security").iterdir():
                if not source.is_file() or source.suffix not in (".py", ".sh"):
                    continue
                shutil.copyfile(source, destination / source.name)
        destination = root / 'src/malpdf/static/lab_guard.py'
        destination.parent.mkdir(parents=True)
        shutil.copyfile(HERE.parents[1] / 'src/malpdf/static/lab_guard.py', destination)
        (root / "scripts/security/needle.py").write_bytes(b"needle = " + repr(key_header()).encode("ascii") + b"\n")
        (root / ".gitignore").write_text("data/\n__pycache__/\n", encoding="utf-8")
        git("add", ".gitignore", "scripts", "src")
        git("commit", "-qm", "Synthetic source-only regression")
        (root / "data/raw").mkdir(parents=True)
        (root / "data/raw/inert.pdf").write_bytes(b"%PDF-1.7\n")
        with patch.object(ctl, "REPO", root):
            commit, archive, manifest = self.invoke(ctl.prepare)
            import base64
            public = self.base / "audit.pub"
            public.write_bytes(b"ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))))
            with patch.object(ctl, "PUBLIC_KEY", public):
                bundle = self.invoke(ctl.bootstrap, commit)
            self.assertEqual({path.name for path in bundle.iterdir()}, {*ctl.BOOTSTRAP_FILES, "id_ed25519_malpdf_audit.pub", "manifest.json"})
            with tarfile.open(archive, "r:") as tf:
                names = tf.getnames()
                self.assertIn("scripts/lab/lab_side.py", names)
                self.assertNotIn("data/raw/inert.pdf", names)
            shutil.copyfile(archive, lab.INBOX / archive.name)
            shutil.copyfile(manifest, lab.INBOX / manifest.name)
            self.invoke(lab.install, commit)
            self.invoke(lab.syntax, commit)
            self.assertEqual(contract.parse_json((lab.REPORTS / f"{commit}.json").read_bytes())["status"], "passed")
            self.invoke(ctl.prepare)
            (root / "scripts/lab/labctl.py").write_text("value = 1\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.invoke(ctl.prepare)
            self.invoke(ctl.prepare, commit)
            (root / "scripts/forged.py").write_bytes(key_header() + b"\n")
            rejected = subprocess.run([sys.executable, str(root / "scripts/security/check_repo_content.py"), "--worktree"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(rejected.returncode, 1)
            git("add", "scripts/forged.py")
            rejected = subprocess.run([sys.executable, str(root / "scripts/security/check_repo_content.py")], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(rejected.returncode, 1)

    def test_legacy_artifact_identity_and_placeholder_rules(self):
        baseline = {name: ("100644", "a" * 40) for name in guard.LEGACY_PARQUET | guard.LEGACY_GITKEEP}
        for name in guard.LEGACY_PARQUET:
            self.assertEqual(guard.kind_for_path(name, "100644", "a" * 40, baseline)[0], "legacy")
            self.assertEqual(guard.kind_for_path(name, "100644", "b" * 40, baseline)[0], "reject")
        self.assertEqual(guard.kind_for_path("data/raw/.gitkeep", "100644", "a" * 40, baseline)[0], "legacy-placeholder")
        self.assertIsNotNone(guard.content_failure(b"nonempty", "placeholder"))
        self.assertIsNone(guard.content_failure(b"", "placeholder"))
        self.assertIsNone(guard.content_failure(guard.PNG_SIGNATURE + b"synthetic", "figure"))
        self.assertIsNotNone(guard.content_failure(b"MZsynthetic", "figure"))
        self.assertEqual(guard.kind_for_path("src/sample.pdf", "100644", "a" * 40, baseline)[0], "reject")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit counts and fixed error descriptors only")
    args = parser.parse_args()
    stream = io.StringIO() if args.json else sys.stderr
    from selftest_workflow import WorkflowTests
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(SecurityTests), unittest.defaultTestLoader.loadTestsFromTestCase(WorkflowTests)])
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
    failed = len({getattr(test, "test_case", test).id() for test, _ in (*result.failures, *result.errors)})
    skipped = len(result.skipped)
    obj = {"total": result.testsRun, "passed": result.testsRun - failed - skipped, "failed": failed, "skipped": skipped}
    if args.json:
        print(json.dumps(obj, sort_keys=True))
    else:
        print(("PASS" if result.wasSuccessful() else "FAIL") + ": offline LAB security regressions " + json.dumps(obj, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
