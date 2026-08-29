"""Validation for the design-only CAPE laboratory specification; no runtime setup."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def _design() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    return yaml.safe_load((root / "configs" / "cape_lab_design.yaml").read_text(encoding="utf-8"))


def test_lab_design_is_explicitly_non_operational_and_pinned_to_a_document_revision() -> None:
    design = _design()
    assert design["lab_schema_version"] == "cape-lab-design-v1"
    assert design["design_only"] is True
    assert design["live_execution_enabled"] is False
    sources = design["official_sources"]
    assert sources["repository_url"] == "https://github.com/kevoreilly/CAPEv2"
    assert re.fullmatch(r"[0-9a-f]{40}", sources["documentation_revision_sha"])
    policy = design["cape_revision_policy"]
    assert policy["selected_revision"] is None
    assert any("full commit SHA" in step for step in policy["selection_procedure"])


def test_network_sharing_snapshot_and_api_safety_controls_are_present() -> None:
    design = _design()
    network = design["network_policy"]
    assert network["default_mode"] == "offline"
    assert set(network["supported_modes"]) == {"offline", "controlled_network_observation"}
    assert network["bridged_to_trusted_lan"] is False
    assert network["unrestricted_internet_allowed"] is False
    assert network["guest_access_to_trusted_development"] == "denied"
    assert all(value == "prohibited" for value in design["sharing_policy"].values())
    assert design["snapshot_policy"]["one_sample_per_clean_state"] is True
    assert design["snapshot_policy"]["mandatory_revert_after_each_sample"] is True
    assert design["api_policy"]["live_api_enabled"] is False
    assert design["report_egress_policy"]["primary_egress"] == "JSON_report_and_required_metadata_only"


def test_design_contains_no_credentials_or_real_network_addresses() -> None:
    text = (Path(__file__).resolve().parents[1] / "configs" / "cape_lab_design.yaml").read_text(encoding="utf-8")
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    lowered = text.lower()
    for forbidden in ("password:", "api_key", "token:", "secret:", "username:"):
        assert forbidden not in lowered
