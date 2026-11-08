"""Bounded, append-only V9 checkpoint and raw-stream transport.

Only the parent writes blobs. The isolated parser retains RLIMIT_FSIZE=0.
No payload is interpreted, rendered, or executed by this module.
"""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

CHUNK_BYTES = 64 * 1024
RAW_BYTES = 10 * 1024**2
GRAPH_BYTES = 2 * 1024**2
SECTIONS = ("observations", "edges", "capability_checks", "conflicts", "backend_results")


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()


class EvidenceAccumulator:
    """A malformed later delta cannot erase an already verified checkpoint."""

    def __init__(self, digest, *, max_bytes=GRAPH_BYTES):
        self.max_bytes = max_bytes
        self.value = {"schema_version": "pdf-evidence-v9", "document_sha256": digest,
                      "status": "partial", "complete": False,
                      "original_bytes_changed": False, "active_content_executed": False,
                      **{key: [] for key in SECTIONS}}
        self._index = {key: {} for key in SECTIONS}
        self._bytes = len(encoded(self.value))

    def merge(self, delta):
        if not isinstance(delta, dict) or delta.get("schema_version", "pdf-evidence-v9") != "pdf-evidence-v9":
            raise ValueError("invalid_evidence_delta")
        if delta.get("document_sha256", self.value["document_sha256"]) != self.value["document_sha256"]:
            raise ValueError("evidence_document_mismatch")
        additions, scalars, total = {}, {}, self._bytes
        for key, value in delta.items():
            if key not in SECTIONS:
                if key in self.value:
                    total += len(encoded(value)) - len(encoded(self.value[key]))
                else:
                    total += len(encoded(key)) + 1 + len(encoded(value)) + 1
                scalars[key] = value
                continue
            if not isinstance(value, list):
                raise ValueError("invalid_evidence_section")
            pending = {}
            for entry in value:
                if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                    raise ValueError("invalid_evidence_identity")
                identifier = entry["id"]
                old = pending.get(identifier, self._index[key].get(identifier))
                if old is not None and old != entry:
                    raise ValueError("nonmonotonic_evidence_delta")
                if old is None:
                    total += len(encoded(entry)) + int(bool(self._index[key] or pending))
                    pending[identifier] = entry
            additions[key] = pending
        if total > self.max_bytes:
            raise ValueError("evidence_metadata_limit")
        for key, pending in additions.items():
            for identifier, entry in pending.items():
                saved = deepcopy(entry)
                self._index[key][identifier] = saved
                self.value[key].append(saved)
        self.value.update(deepcopy(scalars))
        self._bytes = total

    def interrupted(self, codes):



        self.value.update(status="partial", complete=False, worker_failure_codes=list(codes))
        return self.value


class WorkerRawSink:
    def __init__(self, connection, *, max_bytes=RAW_BYTES):
        self.connection, self.max_bytes = connection, max_bytes
        self.used, self.seen = 0, set()

    def __call__(self, raw):
        if not isinstance(raw, bytes):
            raise ValueError("invalid_raw_stream")
        digest = hashlib.sha256(raw).hexdigest()
        result = {"sha256": digest, "size_bytes": len(raw)}
        if digest in self.seen:
            return {**result, "status": "retained", "reason_code": None}
        if self.used + len(raw) > self.max_bytes:
            return {**result, "status": "unavailable", "reason_code": "raw_storage_limit"}
        self.connection.send_bytes(encoded({"event": "raw_begin", **result}))
        for offset in range(0, len(raw), CHUNK_BYTES):
            self.connection.send_bytes(encoded({"event": "raw_chunk", "sha256": digest,
                "offset": offset, "data": base64.b64encode(raw[offset:offset+CHUNK_BYTES]).decode("ascii")}))
        self.connection.send_bytes(encoded({"event": "raw_end", **result}))
        self.used += len(raw)
        self.seen.add(digest)
        return {**result, "status": "retained", "reason_code": None}


class ParentRawStore:
    """Validate a sequential stream before marking its blob verified.

    Incomplete blobs remain .partial files as interrupted private evidence.
    A caller supplies a new, ignored per-file artifact directory.
    """

    def __init__(self, directory, *, max_bytes=RAW_BYTES):
        self.directory = None if directory is None else Path(directory).absolute()
        if self.directory is not None:
            if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
                raise ValueError("unsafe_raw_artifact_path")
            self.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.max_bytes, self.used = max_bytes, 0
        self.active, self.records = None, []

    def accept(self, message):
        digest = message.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid_raw_digest")
        event = message["event"]
        if event == "raw_begin":
            size = message.get("size_bytes")
            if (self.active is not None or any(record['sha256'] == digest for record in self.records)
                    or type(size) is not int or size < 0 or self.used + size > self.max_bytes):
                raise ValueError("raw_storage_limit_or_sequence")
            output = None if self.directory is None else (self.directory / (digest + ".partial")).open("xb")
            self.active = {"sha256": digest, "size": size, "received": 0,
                           "hash": hashlib.sha256(), "output": output}
        elif event == "raw_chunk":
            active = self.active
            if active is None or active["sha256"] != digest or message.get("offset") != active["received"]:
                raise ValueError("invalid_raw_sequence")
            data = message.get("data")
            if not isinstance(data, str) or len(data) > ((CHUNK_BYTES + 2)//3)*4:
                raise ValueError("raw_chunk_limit")
            chunk = base64.b64decode(data, validate=True)
            if not chunk or len(chunk) > CHUNK_BYTES or active["received"] + len(chunk) > active["size"]:
                raise ValueError("raw_chunk_limit")
            active["hash"].update(chunk)
            active["received"] += len(chunk)
            if active["output"] is not None:
                active["output"].write(chunk)
        elif event == "raw_end":
            active = self.active
            if (active is None or active["sha256"] != digest or active["received"] != active["size"]
                    or message.get("size_bytes") != active["size"] or active["hash"].hexdigest() != digest):
                raise ValueError("raw_checksum_or_size_mismatch")
            output = active["output"]
            if output is not None:
                output.close()

                (self.directory / (digest + ".partial")).rename(self.directory / (digest + ".bin"))
            self.records.append({"sha256": digest, "size_bytes": active["size"],
                                 "status": "verified" if output is not None else "verified_not_persisted"})
            self.used += active["size"]
            self.active = None
        else:
            raise ValueError("invalid_raw_event")

    def close(self):
        if self.active is not None and self.active["output"] is not None:
            self.active["output"].close()
