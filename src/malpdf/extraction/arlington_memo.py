"""Reuse completed schema results with explicit ancestor and depth contexts."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CompletedBinding:
    binding_id: str
    result: object
    dependencies: frozenset[tuple]
    height: int
    context_specific: bool = False


@dataclass
class BindingFrame:
    identity: tuple
    depth: int
    cycle_epoch: int
    ancestors: frozenset[tuple]
    dependencies: set[tuple] = field(default_factory=set)
    height: int = 0


class BindingMemo:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.completed: dict[tuple, CompletedBinding] = {}
        self.contextual: dict[tuple, CompletedBinding] = {}
        self.frames: list[BindingFrame] = []
        self.cycle_epoch = 0

    def note_cycle(self) -> None:
        self.cycle_epoch += 1

    def find(self, key: tuple, active: set[tuple], depth: int, maximum_depth: int) -> CompletedBinding | None:
        cached = self.completed.get(key) if self.enabled else None
        if cached is not None and cached.dependencies & active:
            cached = None
        if cached is None and self.enabled:
            cached = self.contextual.get((key, frozenset(active), depth))
        if cached is None or depth + cached.height > maximum_depth:
            return None
        if cached.context_specific:
            self.note_cycle()
        for frame in self.frames:
            frame.dependencies.update(cached.dependencies)
            frame.height = max(frame.height, depth - frame.depth + cached.height)
        return cached

    def begin(self, identity: tuple, depth: int) -> None:
        if self.enabled:
            for frame in self.frames:
                frame.dependencies.add(identity)
                frame.height = max(frame.height, depth - frame.depth)
            ancestors = frozenset(frame.identity for frame in self.frames)
            self.frames.append(BindingFrame(identity, depth, self.cycle_epoch, ancestors, {identity}))

    def finish(self, key: tuple, binding_id: str, result: object) -> None:
        if self.enabled:
            frame = self.frames.pop()
            if result is not None:
                contextual = frame.cycle_epoch != self.cycle_epoch
                cached = CompletedBinding(binding_id, result, frozenset(frame.dependencies), frame.height, contextual)
                if contextual:
                    self.contextual[key, frame.ancestors, frame.depth] = cached
                else:
                    self.completed[key] = cached
