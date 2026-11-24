import argparse
import ast
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
WEB_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".css", ".json"}
FILE_SUFFIXES = WEB_SUFFIXES | {".py"}
EXCLUDED_ROOTS = {".agents", ".git", "graphify-out", "data", "artifacts", "checkpoints", "reports"}
RUFF_DIAGNOSTIC = re.compile(r"^(.+?:\d+:\d+): ([\w-]+):? (.+)$")
BIOME_DIAGNOSTIC = re.compile(r"^[×!ℹ] (.+?):(?:(\d+):(\d+):)? ([\w/-]+): (.+)$")


def changed_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "status", "--porcelain", "-z", "--untracked-files=all"],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    entries = iter(result.stdout.split(b"\0"))
    paths = []
    for entry in entries:
        status = entry[:2]
        if b"R" in status or b"C" in status:
            next(entries, None)
        if entry and b"D" not in status:
            paths.append(REPO / os.fsdecode(entry[3:]))
    return paths


def excluded(path: Path) -> bool:
    if path.is_relative_to(REPO):
        parts = path.relative_to(REPO).parts
        if parts and (parts[0].lower() in EXCLUDED_ROOTS or parts[0].lower().startswith(".venv")):
            return True
    name = path.name.lower()
    return name.endswith((".min.js", ".min.css")) or (name.startswith("vis-network") and name.endswith(".js"))


def is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    return stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", None) == stat.IO_REPARSE_TAG_MOUNT_POINT


def collect_paths(paths: list[Path]) -> list[Path]:
    files = set()
    for path in paths:
        path = Path(os.path.abspath(path))
        if excluded(path) or any(is_link(part) for part in (path, *path.parents)):
            continue
        if path.is_dir():
            for root, dirs, names in os.walk(path):
                folder = Path(root)
                dirs[:] = [name for name in dirs if not excluded(folder / name) and not is_link(folder / name)]
                for name in names:
                    candidate = folder / name
                    if candidate.suffix.lower() in FILE_SUFFIXES and not excluded(candidate) and not is_link(candidate):
                        if candidate.is_file():
                            files.add(candidate)
        elif path.suffix.lower() in FILE_SUFFIXES and path.is_file():
            files.add(path)
    return sorted(files)


def biome_command() -> list[str]:
    biome = shutil.which("biome")
    if not biome:
        return []
    if os.name != "nt" or Path(biome).suffix.lower() not in {".bat", ".cmd"}:
        return [biome]
    node = shutil.which("node.exe")
    modules = Path(biome).parent / "node_modules"
    if Path(biome).parent.name == ".bin":
        modules = Path(biome).parent.parent
    entrypoint = modules / "@biomejs" / "biome" / "bin" / "biome"
    if not node or not entrypoint.is_file():
        raise OSError(f"Cannot find Node.js and the Biome npm entry point for {biome}")
    return [node, str(entrypoint)]


def diagnostic(path: Path | str, code: str, message: str, line: int | str = 1, col: int | str = 1) -> str:
    return f"{path}:{line}:{col}: {code} {message}"


def tool_diagnostics(tool: str, output: str) -> list[str]:
    messages = []
    for line in output.splitlines():
        if tool == "Biome":
            if match := BIOME_DIAGNOSTIC.fullmatch(line):
                path, row, col, code, message = match.groups()
                messages.append(diagnostic(path, code, message, row or 1, col or 1))
        elif match := RUFF_DIAGNOSTIC.fullmatch(line.removeprefix("error: Failed to parse ")):
            location, code, message = match.groups()
            messages.append(f"{location}: {code} {message}")
        elif line.startswith("Would reformat: "):
            messages.append(
                diagnostic(line.removeprefix("Would reformat: "), "unformatted", "File would be reformatted")
            )
    return messages


def run_tool(tool: str, command: list[str], paths: list[Path]) -> list[str]:
    messages = []
    batch = []
    command_size = sum(len(os.fsencode(arg)) + 3 for arg in command)
    size = command_size
    for path in paths:
        arg = str(path)
        arg_size = len(os.fsencode(arg)) + 3
        if batch and size + arg_size > 28_000:
            messages.extend(run_batch(tool, command, batch))
            batch = []
            size = command_size
        batch.append(arg)
        size += arg_size
    if batch:
        messages.extend(run_batch(tool, command, batch))
    return messages


def run_batch(tool: str, command: list[str], paths: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            [*command, "--", *paths],
            cwd=REPO,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "RUFF_OUTPUT_FORMAT": "concise"},
            check=False,
        )
    except OSError as error:
        return [diagnostic(paths[0], tool, str(error))]
    if result.returncode == 0:
        return []
    output = result.stdout + "\n" + result.stderr
    messages = tool_diagnostics(tool, output)
    if messages:
        return messages
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    first_line = next((line.removeprefix("× ") for line in lines if line.startswith("× ")), lines[0] if lines else "")
    return [diagnostic(paths[0], tool, f"Exit {result.returncode}. {first_line}".rstrip())]


def check_syntax(paths: list[Path]) -> list[str]:
    messages = []
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8-sig")
            if path.suffix.lower() == ".py":
                ast.parse(source, filename=str(path))
            else:
                json.loads(source)
        except SyntaxError as error:
            messages.append(diagnostic(path, "SyntaxError", error.msg, error.lineno or 1, error.offset or 1))
        except json.JSONDecodeError as error:
            messages.append(diagnostic(path, "JSONDecodeError", error.msg, error.lineno, error.colno))
        except (OSError, ValueError, RecursionError) as error:
            messages.append(diagnostic(path, type(error).__name__, str(error)))
    return messages


def print_failures(messages: list[str]) -> int:
    concise = dict.fromkeys(" ".join(message.splitlines())[:500] for message in messages)
    for message in list(concise)[:30]:
        print(message, file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply safe lint fixes and verify file syntax.")
    parser.add_argument("paths", nargs="*", type=Path, help="Files or directories (default: changed worktree files)")
    parser.add_argument("--check-only", action="store_true", help="Check without writing fixes")
    parser.add_argument("--no-format", action="store_true", help="Skip whole-file formatting")
    parser.add_argument("--quiet", action="store_true", help="Print only failures")
    args = parser.parse_args()

    try:
        files = collect_paths(args.paths or changed_paths())
    except (OSError, subprocess.CalledProcessError) as error:
        return print_failures([diagnostic(REPO, type(error).__name__, str(error))])
    py_files = [path for path in files if path.suffix.lower() == ".py"]
    web_files = [path for path in files if path.suffix.lower() in WEB_SUFFIXES]

    messages = []
    if py_files:
        sibling = Path(sys.executable).parent / ("ruff.exe" if os.name == "nt" else "ruff")
        ruff = str(sibling) if sibling.is_file() else shutil.which("ruff")
        if ruff:
            base = [ruff, "--config", str(REPO / "pyproject.toml"), "--quiet"]
            if not args.check_only and not args.no_format:
                messages.extend(run_tool("Ruff", [*base, "format", "--no-cache"], py_files))
            lint_flags = [] if args.check_only else ["--fix"]
            messages.extend(
                run_tool("Ruff", [*base, "check", "--no-cache", "--output-format", "concise", *lint_flags], py_files)
            )
            if args.check_only and not args.no_format:
                messages.extend(run_tool("Ruff", [*base, "format", "--no-cache", "--check"], py_files))

    syntax = check_syntax([*py_files, *(path for path in web_files if path.suffix.lower() == ".json")])
    config = REPO / "configs" / "biome.json"
    if web_files and config.is_file():
        try:
            biome = biome_command()
        except OSError as error:
            messages.append(diagnostic(config, "Biome", str(error)))
        else:
            if biome:
                subcommand = "lint" if args.no_format else "check"
                flags = [] if args.check_only else ["--write"]
                messages.extend(
                    run_tool(
                        "Biome",
                        [
                            *biome,
                            subcommand,
                            "--config-path",
                            str(config),
                            "--max-diagnostics=20",
                            "--reporter=concise",
                            *flags,
                        ],
                        web_files,
                    )
                )

    if syntax or messages:
        return print_failures(syntax + messages)
    if not args.quiet:
        print(f"OK: autofix_and_check verified {len(files)} file(s) ({len(py_files)} py, {len(web_files)} web)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
