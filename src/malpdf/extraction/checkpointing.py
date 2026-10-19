"""Coalesce VM snapshots while always permitting explicit stage boundaries."""

from collections.abc import Callable
from time import perf_counter

from malpdf.static.execution import is_vm


class CheckpointScheduler:
    def __init__(self, limits: object, *, clock: Callable[[], float] = perf_counter) -> None:
        self.coalesce = is_vm(limits)
        self.clock = clock
        self.next_snapshot = 0.0
        self.started = 0.0
        self.snapshots = 0

    def due(self, *, force: bool = False) -> bool:
        now = self.clock()
        if not self.coalesce or force or now >= self.next_snapshot:
            self.started = now
            return True
        return False

    def completed(self) -> None:
        now = self.clock()
        cost = max(0.0, now - self.started)
        self.next_snapshot = now + max(0.5, cost * 10)
        self.snapshots += 1
