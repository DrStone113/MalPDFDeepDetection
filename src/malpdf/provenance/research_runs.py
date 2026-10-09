"""Unique run directories and append-only logs for preparation and training."""

from datetime import datetime, timezone
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import subprocess

from malpdf.experiments.protocol_p import repository_git_state


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def git_revision(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


class ResearchRun:
    """Keep partial results on exceptions; never rewrite a previous run."""

    def __init__(self, root: Path, study: str, methodology: dict, *, code_root: Path | None = None, run_id=None):
        self.root, self.code_root = root.absolute(), (code_root or root).absolute()
        self.commit = git_revision(self.code_root)
        self.identifier = run_id or "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_") + self.commit[:12]
        if not re.fullmatch(r"[a-z0-9_]+", study) or not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", self.identifier):
            raise ValueError("Unsafe study/run identifier")
        self.report = self.root / "reports/experiments" / study / self.identifier
        self.artifacts = self.root / "artifacts" / study / self.identifier
        for path in (self.report, self.artifacts):
            if path.exists() or any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError("Immutable run collision or symbolic link")
        if subprocess.run(["git", "-C", str(self.root), "check-ignore", "-q", "--", str(self.artifacts / "guard.json")]).returncode:
            raise ValueError("Detailed research artifacts must be gitignored")
        code_state = repository_git_state(self.code_root)
        data_state = repository_git_state(self.root)
        self.report.mkdir(parents=True, exist_ok=False)
        self.artifacts.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.state = {"run_id": self.identifier, "study": study, "status": "started",
                      "started_at_utc": datetime.now(timezone.utc).isoformat(), "code_commit": self.commit,
                      "code_worktree": code_state,
                      "data_worktree": data_state, "seed": 42,
                      "protocol": methodology.get("protocol", "raw-cohort Protocol G"),
                      "report_path": str((self.report / "run_summary.json").relative_to(self.root)),
                      "artifact_path": str(self.artifacts.relative_to(self.root)), "metrics": {}}
        write_json(self.report / "locked_methodology.json", {**methodology, "seed": 42,
                   "code_commit": self.commit, "code_worktree": self.state["code_worktree"],
                   "label_convention": "Label=1 malicious", "ece_convention": "10 equal-width probability bins; p=1 in last bin"})
        packages = ("numpy", "pandas", "scikit-learn", "PyMuPDF", "torch", "torchvision", "xgboost", "lightgbm", "catboost")
        write_json(self.report / "environment_metadata.json", {"python": platform.python_version(),
                   "packages": {name: importlib.metadata.version(name) for name in packages},
                   "generating_commit": self.commit, "code_worktree": self.state["code_worktree"],
                   "data_worktree": self.state["data_worktree"]})
        # Dirty maintenance/preparation is reproducible without claiming HEAD
        # contains uncommitted code; identities remain under ignored artifacts.
        snapshot = self.artifacts / "generating_code"
        hashes = {}
        for folder in ("src/malpdf", "scripts", "configs"):
            for source in (self.code_root / folder).rglob("*"):
                if source.is_file() and source.suffix in {".py", ".yaml"} and not source.is_symlink():
                    relative = source.relative_to(self.code_root)
                    target = snapshot / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    content = source.read_bytes()
                    target.write_bytes(content)
                    hashes[str(relative)] = hashlib.sha256(content).hexdigest()
        write_json(self.artifacts / "generating_code_sha256.json", hashes)
        self.append("N/A", "N/A", {}, "started; metrics unavailable until evaluation")

    def append(self, model, partition, metrics, notes):
        fields = [datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), self.identifier,
                  self.state["study"] + " / " + self.state["status"], self.state["protocol"] + " / 42",
                  model, partition, *[metrics.get(k, "N/A") for k in ("f1_malicious", "mcc", "ece", "brier")],
                  self.commit, self.state["code_worktree"]["status"], self.state["report_path"],
                  notes + "; Label=1 malicious; ECE=10 equal-width bins. N/A means no applicable saved model evaluation."]
        with (self.root / "reports/research_log.md").open("a", encoding="utf-8") as handle:
            handle.write("| " + " | ".join(str(v).replace("|", "/").replace("\n", " ").replace("\r", " ") for v in fields) + " |\n")

    def progress(self, event, **counts):
        value = {"utc": datetime.now(timezone.utc).isoformat(), "event": event, **counts}
        with (self.artifacts / "progress.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, allow_nan=False) + "\n")
        print(json.dumps(value), flush=True)

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if error is not None:
            self.state["status"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed"
            self.state["error_type"] = type(error).__name__
            write_json(self.artifacts / "error.json", {"type": type(error).__name__, "message": str(error)})
        elif self.state["status"] == "started":
            self.state["status"] = "completed"
        self.state["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(self.report / "run_summary.json", self.state)
        columns = ["model", "partition", "accuracy", "f1_malicious", "mcc", "brier", "log_loss", "ece", "status"]
        with (self.report / "model_comparison.csv").open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
            writer.writeheader()
            for key, values in self.state["metrics"].items():
                model, partition = key.split("/", 1)
                writer.writerow({"model": model, "partition": partition, "status": self.state["status"], **{k: values.get(k, "N/A") for k in columns[2:-1]}})
                self.append(model, partition, values, "Saved metrics in model_comparison.csv; " + str(self.state.get("notes", "")))
            if not self.state["metrics"]:
                writer.writerow({k: self.state["status"] if k == "status" else "N/A" for k in columns})
                self.append("N/A", "N/A", {}, str(self.state.get("notes", "No model evaluation completed")))
        return False
