"""Offline-only adapters for already-produced sandbox report JSON."""

from malpdf.dynamic.adapters.base import SandboxClient, SandboxReportAdapter
from malpdf.dynamic.adapters.cape import CapeV2ReportAdapter

__all__ = ["CapeV2ReportAdapter", "SandboxClient", "SandboxReportAdapter"]
