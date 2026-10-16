"""Coverage-aware exports of bounded, non-executing PDF evidence."""

from malpdf.extraction.contracts import ObservationStatus, validate_bundle

__all__ = ["ObservationStatus", "validate_bundle", "extract_pdf", "export_bundles", "export_bundle_files"]


def extract_pdf(*args, **kwargs):
    """Lazily load the isolated extraction orchestrator."""
    from malpdf.extraction.orchestrator import extract_pdf as extract

    return extract(*args, **kwargs)


def export_bundles(*args,**kwargs):
    from malpdf.extraction.exporters import export_bundles as export
    return export(*args,**kwargs)


def export_bundle_files(*args,**kwargs):
    from malpdf.extraction.exporters import export_bundle_files as export
    return export(*args,**kwargs)
