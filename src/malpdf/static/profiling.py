"""Exclusive stage timings for bounded static inspection, never PDF execution."""

from contextlib import contextmanager, nullcontext
from time import perf_counter

STAGES = ("read_hash", "raw_scan", "parse_pdf", "stream_decode", "js_ast", "inference_gate", "inference")
PROFILE_VERSION = "cic-static-profile-v2"


class StageTimings:
    def __init__(self, callback=lambda *args: None):
        self.seconds = {name: None for name in STAGES}
        self.stack = []
        self.callback = callback

    @contextmanager
    def stage(self, name):
        if name not in STAGES:
            raise ValueError("Unknown timing stage")
        self.callback("started", name, dict(self.seconds))
        frame = [perf_counter(), 0.0]
        self.stack.append(frame)
        try:
            yield
        finally:
            elapsed = perf_counter() - frame[0]
            self.stack.pop()
            if self.stack:
                self.stack[-1][1] += elapsed
            self.seconds[name] = (self.seconds[name] or 0.0) + max(0.0, elapsed - frame[1])
            self.callback("finished", name, dict(self.seconds))


def stage(timings, name):
    return nullcontext() if timings is None else timings.stage(name)
