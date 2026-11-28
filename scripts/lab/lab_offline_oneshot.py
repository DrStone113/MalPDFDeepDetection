"""Drive the pinned static LAB runner from a non-root, offline PTY."""

import argparse
import errno
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

PINNED_LIB = Path("/usr/local/libexec/malpdf")
if sys.platform == "linux" and PINNED_LIB.is_dir():
    sys.path.insert(0, str(PINNED_LIB))

from lab_contract import parse_json
import lab_jobs as jobs

LAB = "/usr/local/bin/lab"
PROMPT = re.compile(rb"(?:\A|\n)Chay job da duyet\? \[y/N\]: ?\Z")
PROMPT_LIMIT = 262144


def forbid_ssh():
    if any(key.startswith("SSH_") for key in os.environ):
        raise ValueError("ssh_launch_forbidden")


def runner_env(account):
    return {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _terminate_process_tree(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    else:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def _close_pipe(pipe):
    if pipe is not None:
        try:
            pipe.close()
        except OSError:
            pass


def bounded_command(command, limit, *, timeout, payload=None, check=True, **kwargs):
    if os.name == "posix":
        kwargs.setdefault("start_new_session", True)
    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL if payload is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        **kwargs,
    ) as process:
        output = bytearray()
        errors = []
        stop_event = threading.Event()

        def receive():
            try:
                while not stop_event.is_set() and (chunk := process.stdout.read1(65536)):
                    if len(output) + len(chunk) > limit:
                        raise ValueError("command_output_limit")
                    output.extend(chunk)
            except (OSError, ValueError) as error:
                if not stop_event.is_set():
                    errors.append(error)
                _terminate_process_tree(process)

        def send():
            try:
                with process.stdin:
                    process.stdin.write(payload)
            except OSError as error:
                if not stop_event.is_set():
                    errors.append(error)
                _terminate_process_tree(process)

        threads = [threading.Thread(target=receive, daemon=True)]
        if payload is not None:
            threads.append(threading.Thread(target=send, daemon=True))
        for thread in threads:
            thread.start()
        timed_out = None
        code = 0
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = error
            stop_event.set()
        finally:
            if process.poll() is None or timed_out is not None:
                stop_event.set()
                _terminate_process_tree(process)
                try:
                    process.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    pass
                _close_pipe(process.stdout)
                _close_pipe(process.stdin)
        join_timeout = 0.5 if timed_out is not None else 2.0
        for thread in threads:
            thread.join(timeout=join_timeout)
            if thread.is_alive() and timed_out is None:
                raise ValueError("command_pipe_unavailable")
        if timed_out is not None:
            raise timed_out
        if errors:
            raise errors[0]
        if check and code:
            raise ValueError("command_failed")
        return code, bytes(output)


def exclusive_job(job_id, kind):
    if not jobs.HEX.fullmatch(job_id) or kind not in jobs.PDF_KINDS:
        raise ValueError("job_mismatch")
    job = jobs.load_job(job_id)
    if job["job_id"] != job_id or job["kind"] != kind or job["mode"] != "offline":
        raise ValueError("job_mismatch")
    if [item["job_id"] for item in jobs.pending()] != [job_id]:
        raise ValueError("queue_not_exclusive")
    return job


def precheck(job_id, kind):
    forbid_ssh()
    if sys.platform != "linux" or os.getuid() < 1000:
        raise ValueError("runner_uid_required")
    import pwd

    cfg = jobs.config()
    if cfg["uid"] != os.getuid():
        raise ValueError("runner_uid_required")
    jobs.guard_module().require_offline_lab(True)
    job = exclusive_job(job_id, kind)
    env = runner_env(pwd.getpwuid(cfg["uid"]))
    _, status = bounded_command([LAB, "status"], 65536, timeout=15, env=env)
    _, preflight = bounded_command([LAB, "preflight"], 65536, timeout=15, env=env)
    if parse_json(status)["runner"]["offline_guest_ready"] is not True or parse_json(preflight)["credentials"] != []:
        raise ValueError("offline_preflight_failed")
    return job, env


def confirm_lab_run_prompt(read_chunk_fn, write_fn, job_id, kind, *, prompt_timeout=30.0):
    expected = f"Job: {job_id} | kind: {kind}".encode("ascii")
    deadline = time.monotonic() + prompt_timeout
    output = bytearray()
    confirmed = False
    while time.monotonic() < deadline:
        chunk = read_chunk_fn(max(0, deadline - time.monotonic()))
        if not chunk or len(output) + len(chunk) > PROMPT_LIMIT or time.monotonic() > deadline:
            break
        output.extend(chunk)
        prompt = PROMPT.search(output)
        if prompt:
            selections = [line for line in output[: prompt.start()].split(b"\n") if line.startswith(b"Job:")]
            confirmed = [line.removesuffix(b"\r") for line in selections] == [expected]
            break
    try:
        write_fn(b"y\n" if confirmed else b"n\n")
    except OSError as error:
        if confirmed or error.errno not in (errno.EIO, errno.EPIPE, errno.EBADF):
            raise
    return confirmed


def linux_pty(command, env, job_id, kind, wall_seconds):
    import pty
    import select
    import signal
    import termios

    master, slave = pty.openpty()
    process = None
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        process = subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, env=env, cwd=env["HOME"]
        )
    finally:
        os.close(slave)
        if process is None:
            os.close(master)

    def receive(timeout):
        ready, _, _ = select.select([master], [], [], timeout)
        if not ready:
            return b""
        try:
            return os.read(master, 8192)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            return b""

    def finish(timeout):
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0 and receive(remaining):
            pass
        return process.wait(timeout=max(0, deadline - time.monotonic()))

    try:
        confirmed = confirm_lab_run_prompt(receive, lambda data: os.write(master, data), job_id, kind)
        try:
            code = finish(wall_seconds + 60 if confirmed else 2)
            reason = None if confirmed else "prompt_mismatch"
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait()
            reason = "pty_run_timeout" if confirmed else "prompt_mismatch"
        result = {"confirmed": confirmed, "exit_code": code}
        if confirmed:
            result.update(job_id=job_id, kind=kind)
        if reason:
            result["reason"] = reason
        return result
    finally:
        os.close(master)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def drive_lab_run(job_id, kind, wall_seconds, *, runner_cmd=(LAB, "run"), pty_driver=None):
    job, env = precheck(job_id, kind)
    if type(wall_seconds) is not int or not 0 < wall_seconds <= job["limits"]["wall_seconds"]:
        raise ValueError("invalid_wall_seconds")
    return (pty_driver or linux_pty)(runner_cmd, env, job_id, kind, wall_seconds)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--kind", required=True)
    args = parser.parse_args(argv)
    try:
        forbid_ssh()
        if args.kind not in jobs.PDF_KINDS:
            raise ValueError("job_mismatch")
        value = drive_lab_run(args.job_id, args.kind, jobs.policy(args.kind)["wall_seconds"])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        value = {"confirmed": False, "exit_code": None, "reason": str(error)}
    print(json.dumps(value, separators=(",", ":"), allow_nan=False))
    return 0 if value["confirmed"] and value["exit_code"] == 0 and "reason" not in value else 2


if __name__ == "__main__":
    raise SystemExit(main())
