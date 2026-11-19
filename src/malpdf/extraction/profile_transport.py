"""Bounded receiver and process ownership for bulk profile IPC."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time


class FramedReader:
    def __init__(self, connection, limit):
        self.connection = connection
        self.fd = connection.fileno()
        os.set_blocking(self.fd, False)
        self.limit = limit
        self.buffer = bytearray()
        self.eof = False

    def _size(self):
        if len(self.buffer) < 4:
            return None
        size = struct.unpack_from("!i", self.buffer)[0]
        if not 0 < size <= self.limit:
            raise ValueError("bulk_worker_frame_size")
        return size

    def poll(self):
        size = self._size()
        if size is not None and len(self.buffer) >= 4 + size:
            return True
        if not self.eof:
            try:
                payload = os.read(self.fd, 65536)
            except BlockingIOError:
                return False
            self.eof = not payload
            self.buffer.extend(payload)
            size = self._size()
        return self.eof or (size is not None and len(self.buffer) >= 4 + size)

    def recv_bytes(self, maxlength=None):
        size = self._size()
        if size is None or len(self.buffer) < 4 + size:
            if self.buffer:
                raise ValueError("bulk_worker_truncated_frame")
            raise EOFError
        if maxlength is not None and size > maxlength:
            raise ValueError("bulk_worker_frame_size")
        result = bytes(self.buffer[4:4 + size])
        del self.buffer[:4 + size]
        return result

    def close(self):
        self.connection.close()


class BulkWorker:
    def __init__(self, config, registry):
        self.config = config
        self.registry = registry
        self.process = None
        self.marker = None
        self.last_progress = time.monotonic()
        self.progress_key = None

    @property
    def pid(self):
        return None if self.process is None else self.process.pid

    @property
    def exitcode(self):
        return None if self.process is None else self.process.poll()

    def start(self):
        config = dict(self.config, parent_pid=os.getpid())
        payload = json.dumps(config, separators=(",", ":"), allow_nan=False)
        if len(payload.encode()) > 16384:
            raise ValueError("bulk_worker_bootstrap_limit")
        script = Path(__file__).with_name("profile_bootstrap.py").resolve()
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(script), payload],
            pass_fds=(config["result_fd"], config["diagnostic_fd"]),
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, shell=False,
        )
        try:
            stat = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()
            if int(stat[1]) != os.getpid() or int(stat[2]) != self.pid or int(stat[3]) != self.pid:
                raise ValueError("bulk_worker_identity")
            marker = self.registry / f"{self.pid}.json"
            pending = marker.with_suffix(".tmp")
            with pending.open("x", encoding="ascii") as handle:
                json.dump({"pid": self.pid, "pgid": self.pid, "start_ticks": int(stat[19])}, handle)
            os.replace(pending, marker)
            self.marker = marker
            self.process.stdin.write(b"1")
        finally:
            self.process.stdin.close()

    def join(self, timeout):
        try:
            self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            pass

    def is_alive(self):
        return self.process is not None and self.exitcode is None

    def kill(self):
        self.process.kill()

    def forget(self):
        if self.marker is not None:
            try:
                os.killpg(self.pid, 0)
            except ProcessLookupError:
                self.marker.unlink()
                return True
        return self.marker is None and not self.is_alive()

    def progress(self, key, diagnostic):
        now = time.monotonic()
        if key != self.progress_key:
            self.progress_key, self.last_progress = key, now
        elif now - self.last_progress >= 4:
            diagnostic.data["bulk_stall_observed"] = True
