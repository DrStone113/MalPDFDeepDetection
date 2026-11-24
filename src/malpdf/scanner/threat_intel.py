from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ThreatIntelProvider(Protocol):
    def lookup_sha256(self, sha256: str) -> dict[str, Any] | None: ...

    def lookup_domain(self, domain: str) -> dict[str, Any] | None: ...


class NullThreatIntelProvider:
    def lookup_sha256(self, sha256: str) -> None:
        return None

    def lookup_domain(self, domain: str) -> None:
        return None


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(domain))
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(domain) > 253 or any(not _DOMAIN_LABEL.fullmatch(label) for label in domain.split(".")):
        return ""
    return domain


class StaticBlocklistProvider:
    def __init__(
        self,
        sha256_blocklist: set[str] | frozenset[str] = frozenset(),
        domain_blocklist: set[str] | frozenset[str] = frozenset(),
        source: str = "local_blocklist",
    ) -> None:
        self.sha256_blocklist = frozenset(item.strip().lower() for item in sha256_blocklist)
        self.domain_blocklist = frozenset(filter(None, map(_normalize_domain, domain_blocklist)))
        self.source = source

    @classmethod
    def from_json_file(cls, path: Path | str) -> StaticBlocklistProvider:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid_threat_intel_blocklist")
        hashes, domains = (data.get(key, []) for key in ("sha256_blocklist", "domain_blocklist"))
        source = data.get("source", "local_blocklist")
        if not isinstance(source, str) or any(
            not isinstance(items, list) or not all(isinstance(item, str) for item in items)
            for items in (hashes, domains)
        ):
            raise ValueError("invalid_threat_intel_blocklist")
        return cls(set(hashes), set(domains), source)

    def lookup_sha256(self, sha256: str) -> dict[str, Any] | None:
        normalized = sha256.strip().lower()
        if normalized in self.sha256_blocklist:
            return {"type": "sha256", "sha256": normalized, "source": self.source}
        return None

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        host = _normalize_domain(domain)
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            candidates = (".".join(labels[index:]) for index in range(len(labels)))
        else:
            candidates = (host,)
        for candidate in candidates:
            if candidate in self.domain_blocklist:
                return {"type": "domain", "domain": host, "matched_domain": candidate, "source": self.source}
        return None


def inspect_threat_intel(provider: ThreatIntelProvider, ingest_data: dict[str, Any]) -> dict[str, Any]:
    matches = []
    hit = provider.lookup_sha256(ingest_data["sha256"])
    if hit is not None:
        matches.append(hit)
    seen = set()
    uris = [item["uri"] for item in ingest_data["extracted_uris"]]
    uris.extend(ingest_data["js_semantics"]["resolved_urls"])
    uris.extend(ingest_data.get("qr_analysis", {}).get("decoded_uris", []))
    for uri in uris:
        try:
            host = _normalize_domain(unquote(urlsplit(uri).hostname or ""))
        except ValueError:
            continue
        if not host or host in seen:
            continue
        seen.add(host)
        hit = provider.lookup_domain(host)
        if hit is not None:
            matches.append(hit)
    return {"hit": bool(matches), "matches": matches}
