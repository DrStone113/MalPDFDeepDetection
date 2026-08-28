"""Command-line entry point for the project."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from malpdf import __version__
from malpdf.reproducibility import DEFAULT_RANDOM_SEED, set_random_seed


def build_parser() -> argparse.ArgumentParser:
    """Build the project command-line parser."""
    parser = argparse.ArgumentParser(
        prog="malpdf",
        description="Malicious PDF detection research utilities.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help=f"random seed (default: {DEFAULT_RANDOM_SEED})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Initialize deterministic state for a future experiment command."""
    args = build_parser().parse_args(argv)
    set_random_seed(args.seed)
    print(f"malpdf ready (seed={args.seed})")
    return 0
