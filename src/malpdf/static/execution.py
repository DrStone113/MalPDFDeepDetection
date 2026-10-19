"""Execution policy shared by static extraction stages."""

from dataclasses import fields, replace
import os
import sys
from typing import TypeVar


UNLIMITED = sys.maxsize - 1
LimitType = TypeVar("LimitType")


def is_vm(limits: object) -> bool:
    return getattr(limits, "execution_mode", "bounded") == "vm"


def capacity(limits: object, bounded: int) -> int:
    return UNLIMITED if is_vm(limits) else bounded


def valid_capacity(value: object, ceiling: int) -> bool:
    return type(value) is int and (0 < value <= ceiling or value == UNLIMITED)


def expand_limits(limits: LimitType, code_limits: object, *, preserve: tuple[str, ...] = ()) -> LimitType:
    if not is_vm(code_limits):
        return limits
    retained = {"max_depth", "max_expansion_ratio", *preserve}
    return replace(limits, **{field.name: UNLIMITED for field in fields(limits)
                              if field.name not in retained})


def available_cpus() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1
