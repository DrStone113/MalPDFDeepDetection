"""Torch-free runtime scorer for PDFURILexicalHead v4 (ONNX Runtime and pure-NumPy NPZ)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any

import numpy as np

try:
    import onnxruntime as ort
except ImportError:  # pragma: no cover - optional on lightweight extraction-only hosts
    ort = None  # type: ignore[assignment]

from malpdf.scanner.uri_lexical import (
    URI_LEXICAL_FEATURE_NAMES,
    URI_LEXICAL_SCHEMA_VERSION,
    URI_LOG1P_INDICES,
    canonicalize_extracted_uri,
    extract_url_lexical_features,
    is_allowlisted_uri,
    is_bare_dual_use_hosted_uri,
    is_scorable_http_uri,
    is_xml_xmp_namespace_uri,
)

_HEX256 = re.compile(r"[0-9a-f]{64}\Z")
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_URI_CONTRACT_PATHS: tuple[Path, ...] = (
    REPO_ROOT / "production" / "configs" / "uri_lexical_head_v4_contract.json",
    REPO_ROOT / "configs" / "uri_lexical_head_v4_contract.json",
)
DEFAULT_URI_ONNX_PATH = REPO_ROOT / "production" / "models" / "uri_lexical_head_v4.onnx"
DEFAULT_URI_NPZ_PATH = REPO_ROOT / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz"


def _sigmoid_np(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -40.0, 40.0)))


def _silu_f32(x: np.ndarray) -> np.ndarray:
    sig = (1.0 / (1.0 + np.exp(-np.clip(x.astype(np.float64), -40.0, 40.0)))).astype(np.float32)
    return (x * sig).astype(np.float32, copy=False)


def _layer_norm_f32(x: np.ndarray, weight: np.ndarray, bias: np.ndarray, eps: float = 1e-5) -> np.ndarray:
    mean = x.mean(axis=-1, keepdims=True, dtype=np.float32)
    diff = x - mean
    var = (diff * diff).mean(axis=-1, keepdims=True, dtype=np.float32)
    normed = diff / np.sqrt(var + np.float32(eps))
    return (normed * weight + bias).astype(np.float32, copy=False)


def _linear_f32(x: np.ndarray, weight: np.ndarray, bias: np.ndarray) -> np.ndarray:
    return (x @ weight.T + bias).astype(np.float32, copy=False)


def validate_uri_lexical_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != URI_LEXICAL_SCHEMA_VERSION:
        raise ValueError("invalid_uri_lexical_schema_version")
    if contract.get("model_version") != "PDFURILexicalHead v4":
        raise ValueError("invalid_uri_lexical_model_version")
    if tuple(contract.get("feature_names") or ()) != URI_LEXICAL_FEATURE_NAMES:
        raise ValueError("invalid_uri_lexical_feature_names")
    if tuple(contract.get("log1p_indices") or ()) != URI_LOG1P_INDICES:
        raise ValueError("invalid_uri_lexical_log1p_indices")
    mcfg = contract.get("model_config")
    dropout = mcfg.get("dropout") if isinstance(mcfg, dict) else None
    if (
        not isinstance(mcfg, dict)
        or type(mcfg.get("in_dim")) is not int
        or type(mcfg.get("hidden_dim")) is not int
        or type(mcfg.get("bottleneck_dim")) is not int
        or mcfg["in_dim"] != len(URI_LEXICAL_FEATURE_NAMES)
        or mcfg["hidden_dim"] != 128
        or mcfg["bottleneck_dim"] != 64
        or not isinstance(dropout, (int, float))
        or isinstance(dropout, bool)
        or not math.isfinite(float(dropout))
        or float(dropout) != 0.15
    ):
        raise ValueError("invalid_uri_lexical_model_config")
    center = contract.get("scaler_center") or []
    scale = contract.get("scaler_scale") or []
    dim = len(URI_LEXICAL_FEATURE_NAMES)
    if len(center) != dim or len(scale) != dim:
        raise ValueError("invalid_uri_lexical_scaler_dim")
    if not all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in center):
        raise ValueError("invalid_uri_lexical_scaler_center")
    if not all(isinstance(v, (int, float)) and math.isfinite(float(v)) and float(v) > 0.0 for v in scale):
        raise ValueError("invalid_uri_lexical_scaler_scale")
    platt_a = contract.get("platt_a")
    platt_b = contract.get("platt_b")
    if (
        not isinstance(platt_a, (int, float))
        or not isinstance(platt_b, (int, float))
        or not math.isfinite(float(platt_a))
        or not math.isfinite(float(platt_b))
    ):
        raise ValueError("invalid_uri_lexical_platt_params")
    t_low = contract.get("t_low")
    t_high = contract.get("t_high")
    if (
        not isinstance(t_low, (int, float))
        or not isinstance(t_high, (int, float))
        or not (0.0 < float(t_low) < float(t_high) < 1.0)
    ):
        raise ValueError("invalid_uri_lexical_thresholds")
    npz_sha = contract.get("weights_npz_sha256")
    if not isinstance(npz_sha, str) or not _HEX256.fullmatch(npz_sha):
        raise ValueError("invalid_uri_lexical_weights_sha256")
    if not isinstance(contract.get("tld_legit_probs"), Mapping) or not isinstance(contract.get("char_probs"), Mapping):
        raise ValueError("invalid_uri_lexical_lookup_tables")


def _sha256_lf_matches(path: Path, expected: str) -> bool:
    raw = path.read_bytes()
    return (
        hashlib.sha256(raw).hexdigest() == expected
        or hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == expected
    )


class URILexicalHeadScorer:
    """Scores PDF URLs using either ONNX Runtime or pure-NumPy NPZ weights with Platt calibration."""

    def __init__(
        self,
        *,
        contract_path: Path | str | None = None,
        onnx_path: Path | str | None = None,
        npz_path: Path | str | None = None,
        manifest_path: Path | str | None = None,
        prefer_onnx: bool = True,
        intra_op_threads: int = 2,
    ) -> None:
        self.model_loaded = False
        self.backend = "unavailable"
        self.model_version = "PDFURILexicalHead v4"
        self.schema_version = URI_LEXICAL_SCHEMA_VERSION
        self.contract: dict[str, Any] = {}
        self.t_low = 0.50
        self.t_high = 0.90
        self.platt_a = 1.0
        self.platt_b = 0.0
        self.tld_legit_probs: dict[str, float] = {}
        self.char_probs: dict[str, float] = {}
        self.default_tld_prob = 1e-4
        self.default_char_prob = 1e-3
        self.scaler_center = np.zeros((1, len(URI_LEXICAL_FEATURE_NAMES)), dtype=np.float64)
        self.scaler_scale = np.ones((1, len(URI_LEXICAL_FEATURE_NAMES)), dtype=np.float64)
        self.session: Any = None
        self.npz_arrays: dict[str, np.ndarray] | None = None

        manifest_meta: dict[str, Any] = {}
        resolved_manifest = Path(manifest_path) if manifest_path is not None else None
        if resolved_manifest is not None and resolved_manifest.is_file():
            manifest_meta = json.loads(resolved_manifest.read_text(encoding="utf-8")).get("uri_lexical_model") or {}

        c_path = self._resolve_contract_path(
            contract_path, manifest_path=resolved_manifest, manifest_meta=manifest_meta
        )
        if c_path is None or not c_path.is_file():
            return

        if manifest_meta and manifest_meta.get("contract_sha256"):
            if not _sha256_lf_matches(c_path, str(manifest_meta["contract_sha256"])):
                raise ValueError("uri_lexical_contract_sha256_mismatch")

        contract = json.loads(c_path.read_text(encoding="utf-8"))
        validate_uri_lexical_contract(contract)
        self.contract = contract
        self.model_version = str(contract["model_version"])
        self.schema_version = str(contract["schema_version"])
        self.t_low = float(contract["t_low"])
        self.t_high = float(contract["t_high"])
        self.platt_a = float(contract["platt_a"])
        self.platt_b = float(contract["platt_b"])
        self.tld_legit_probs = {str(k): float(v) for k, v in contract["tld_legit_probs"].items()}
        self.char_probs = {str(k): float(v) for k, v in contract["char_probs"].items()}
        self.default_tld_prob = float(contract.get("default_tld_prob", 1e-4))
        self.default_char_prob = float(contract.get("default_char_prob", 1e-3))
        self.scaler_center = np.asarray(contract["scaler_center"], dtype=np.float64).reshape(1, -1)
        self.scaler_scale = np.asarray(contract["scaler_scale"], dtype=np.float64).reshape(1, -1)

        ox_candidate = self._resolve_onnx_path(onnx_path, manifest_meta, c_path=c_path, manifest_path=resolved_manifest)
        npz_candidate = self._resolve_npz_path(npz_path, c_path)

        if prefer_onnx and ort is not None and ox_candidate is not None and ox_candidate.is_file():
            expected_ox_sha = manifest_meta.get("sha256")
            if expected_ox_sha and hashlib.sha256(ox_candidate.read_bytes()).hexdigest() != expected_ox_sha:
                raise ValueError("uri_lexical_onnx_sha256_mismatch")
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
            opts.intra_op_num_threads = max(1, int(intra_op_threads))
            opts.inter_op_num_threads = 1
            opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
            sess = ort.InferenceSession(str(ox_candidate), sess_options=opts, providers=["CPUExecutionProvider"])
            in_names = tuple(i.name for i in sess.get_inputs())
            out_names = tuple(o.name for o in sess.get_outputs())
            if in_names != ("uri_features",) or out_names != ("logits",):
                raise ValueError("invalid_uri_lexical_onnx_io")
            self.session = sess
            self.backend = "onnx"
            self.model_loaded = True
            return

        if npz_candidate is not None and npz_candidate.is_file():
            expected_npz_sha = str(contract["weights_npz_sha256"])
            if hashlib.sha256(npz_candidate.read_bytes()).hexdigest() != expected_npz_sha:
                raise ValueError("uri_lexical_npz_sha256_mismatch")
            with np.load(npz_candidate, allow_pickle=False) as archive:
                arrays = {
                    key[4:]: np.array(archive[key], dtype=np.float32, copy=True)
                    for key in archive.files
                    if key.startswith("sd::")
                }
            required_keys = {
                "in_proj.weight",
                "in_proj.bias",
                "in_norm.weight",
                "in_norm.bias",
                "res_fc1.weight",
                "res_fc1.bias",
                "res_norm1.weight",
                "res_norm1.bias",
                "res_fc2.weight",
                "res_fc2.bias",
                "res_norm2.weight",
                "res_norm2.bias",
                "neck_proj.weight",
                "neck_proj.bias",
                "neck_norm.weight",
                "neck_norm.bias",
                "head.weight",
                "head.bias",
            }
            if not required_keys.issubset(arrays):
                raise ValueError("invalid_uri_lexical_npz_keys")
            self.npz_arrays = arrays
            self.backend = "numpy"
            self.model_loaded = True
            return

        if not prefer_onnx and ort is not None and ox_candidate is not None and ox_candidate.is_file():
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
            opts.intra_op_num_threads = max(1, int(intra_op_threads))
            opts.inter_op_num_threads = 1
            opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
            self.session = ort.InferenceSession(
                str(ox_candidate), sess_options=opts, providers=["CPUExecutionProvider"]
            )
            self.backend = "onnx"
            self.model_loaded = True

    @staticmethod
    def _resolve_contract_path(
        contract_path: Path | str | None,
        *,
        manifest_path: Path | None = None,
        manifest_meta: Mapping[str, Any] | None = None,
    ) -> Path | None:
        if contract_path is not None:
            return Path(contract_path)
        candidates: list[Path] = []
        if manifest_path is not None:
            cname = str((manifest_meta or {}).get("contract_filename") or "uri_lexical_head_v4_contract.json")
            candidates.append(manifest_path.resolve().parent / cname)
        candidates.extend(DEFAULT_URI_CONTRACT_PATHS)
        for path in candidates:
            if path.is_file():
                return path
        return None

    @staticmethod
    def _resolve_onnx_path(
        onnx_path: Path | str | None,
        manifest_meta: Mapping[str, Any],
        *,
        c_path: Path | None = None,
        manifest_path: Path | None = None,
    ) -> Path | None:
        if onnx_path is not None:
            return Path(onnx_path)
        filename = str(manifest_meta.get("filename") or DEFAULT_URI_ONNX_PATH.name)
        candidates: list[Path] = []
        if manifest_path is not None:
            candidates.append(manifest_path.resolve().parent.parent / "models" / filename)
        if c_path is not None:
            candidates.append(c_path.resolve().parent.parent / "models" / filename)
        candidates.extend(
            (
                REPO_ROOT / "production" / "models" / filename,
                REPO_ROOT / "models" / filename,
                DEFAULT_URI_ONNX_PATH,
            )
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _resolve_npz_path(npz_path: Path | str | None, c_path: Path) -> Path | None:
        if npz_path is not None:
            return Path(npz_path)
        for candidate in (
            DEFAULT_URI_NPZ_PATH,
            REPO_ROOT / "data" / "processed" / "uri_head_v4" / "uri_lexical_head_v4.npz",
            c_path.parent.parent / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz",
        ):
            if candidate.is_file():
                return candidate
        return None

    def extract_scaled_batch(self, raw_uris: Sequence[str]) -> np.ndarray:
        if not raw_uris:
            return np.zeros((0, len(URI_LEXICAL_FEATURE_NAMES)), dtype=np.float32)
        rows = [
            extract_url_lexical_features(
                uri,
                tld_legit_probs=self.tld_legit_probs,
                char_probs=self.char_probs,
                default_tld_prob=self.default_tld_prob,
                default_char_prob=self.default_char_prob,
            )
            for uri in raw_uris
        ]
        mat = np.vstack(rows).astype(np.float64, copy=False)
        for col in URI_LOG1P_INDICES:
            mat[:, col] = np.log1p(np.maximum(mat[:, col], 0.0))
        scaled = (mat - self.scaler_center) / self.scaler_scale
        return np.ascontiguousarray(scaled.astype(np.float32), dtype=np.float32)

    def predict_raw_logits(self, raw_uris: Sequence[str]) -> np.ndarray:
        if not self.model_loaded or not raw_uris:
            return np.zeros((len(raw_uris),), dtype=np.float64)
        feats = self.extract_scaled_batch(raw_uris)
        if self.session is not None:
            logits = self.session.run(["logits"], {"uri_features": feats})[0]
            return np.asarray(logits, dtype=np.float64).reshape(-1)
        assert self.npz_arrays is not None
        sd = self.npz_arrays
        x = _silu_f32(
            _layer_norm_f32(
                _linear_f32(feats, sd["in_proj.weight"], sd["in_proj.bias"]), sd["in_norm.weight"], sd["in_norm.bias"]
            )
        )
        r = _silu_f32(
            _layer_norm_f32(
                _linear_f32(x, sd["res_fc1.weight"], sd["res_fc1.bias"]), sd["res_norm1.weight"], sd["res_norm1.bias"]
            )
        )
        r = _layer_norm_f32(
            _linear_f32(r, sd["res_fc2.weight"], sd["res_fc2.bias"]), sd["res_norm2.weight"], sd["res_norm2.bias"]
        )
        x = x + r
        z = _silu_f32(
            _layer_norm_f32(
                _linear_f32(x, sd["neck_proj.weight"], sd["neck_proj.bias"]),
                sd["neck_norm.weight"],
                sd["neck_norm.bias"],
            )
        )
        logits = _linear_f32(z, sd["head.weight"], sd["head.bias"])
        return logits.astype(np.float64).reshape(-1)

    def score_urls(self, raw_uris: Sequence[str]) -> np.ndarray:
        if not raw_uris:
            return np.zeros((0,), dtype=np.float64)
        logits = self.predict_raw_logits(raw_uris)
        calibrated = _sigmoid_np(self.platt_a * logits + self.platt_b)
        return np.asarray(calibrated, dtype=np.float64)

    def _evaluate_pdf_candidates(
        self,
        extracted_uris: Sequence[dict[str, Any]],
        *,
        qr_uris: Sequence[str] = (),
        max_candidates: int = 256,
    ) -> dict[str, Any]:
        filtered_xml = 0
        allowlisted = 0
        pdf_seen: dict[str, str] = {}
        qr_seen: dict[str, str] = {}

        def collect(target: dict[str, str], raw_candidate: str, source_vec: str) -> None:
            nonlocal filtered_xml, allowlisted
            canon = canonicalize_extracted_uri(raw_candidate)
            if canon is None:
                return
            raw_clean, _ = canon
            if is_xml_xmp_namespace_uri(raw_clean):
                filtered_xml += 1
                return
            if not is_scorable_http_uri(raw_clean):
                return
            if is_allowlisted_uri(raw_clean):
                allowlisted += 1
                return
            if raw_clean not in target:
                target[raw_clean] = source_vec

        for item in extracted_uris:
            if not isinstance(item, Mapping):
                continue
            cand = str(item.get("raw_uri") or item.get("uri") or "")
            src = str(item.get("source") or "pdf_action")
            collect(pdf_seen, cand, src)

        for qr_item in qr_uris:
            collect(qr_seen, str(qr_item), "qr_image")

        unique_pool = set(pdf_seen) | set(qr_seen)
        limit = max(0, int(max_candidates))
        if limit == 0:
            candidates: list[tuple[str, str]] = []
        elif len(unique_pool) <= limit:
            candidates = list(pdf_seen.items()) + [(u, v) for u, v in qr_seen.items() if u not in pdf_seen]
        else:
            qr_cap = min(len(qr_seen), limit if limit < 2 else max(1, min(64, limit // 4)))
            qr_admitted = list(qr_seen.items())[:qr_cap]
            qr_admitted_set = {u for u, _ in qr_admitted}
            pdf_cap = max(0, limit - len(qr_admitted))
            pdf_admitted = [(u, v) for u, v in pdf_seen.items() if u not in qr_admitted_set][:pdf_cap]
            candidates = pdf_admitted + qr_admitted

        dropped_count = max(0, len(unique_pool) - len(candidates))
        vector_counts: dict[str, int] = {}
        for _, vec_name in candidates:
            vector_counts[vec_name] = vector_counts.get(vec_name, 0) + 1

        if not self.model_loaded or not candidates:
            return {
                "candidates": candidates,
                "probs": np.zeros((0,), dtype=np.float64),
                "filtered_xml": filtered_xml,
                "allowlisted": allowlisted,
                "dropped_count": dropped_count,
                "vector_counts": vector_counts,
            }

        probs = self.score_urls([pair[0] for pair in candidates])
        return {
            "candidates": candidates,
            "probs": probs,
            "filtered_xml": filtered_xml,
            "allowlisted": allowlisted,
            "dropped_count": dropped_count,
            "vector_counts": vector_counts,
        }

    def max_or_eligible_prob(self, extracted_uris: Sequence[dict[str, Any]], *, qr_uris: Sequence[str] = ()) -> float:
        """Return unrounded max probability across OR-gate-eligible URLs using exact runtime admission."""
        if not self.model_loaded:
            raise RuntimeError("uri_lexical_model_not_loaded")
        evaluated = self._evaluate_pdf_candidates(extracted_uris, qr_uris=qr_uris)
        probs = evaluated["probs"]
        eligible = [
            float(probs[i])
            for i, (cand_url, _vec) in enumerate(evaluated["candidates"])
            if not is_bare_dual_use_hosted_uri(cand_url)
        ]
        return max(eligible) if eligible else 0.0

    def score_pdf_uris(
        self,
        extracted_uris: Sequence[dict[str, Any]],
        *,
        qr_uris: Sequence[str] = (),
        max_candidates: int = 256,
    ) -> dict[str, Any]:
        evaluated = self._evaluate_pdf_candidates(extracted_uris, qr_uris=qr_uris, max_candidates=max_candidates)
        candidates = evaluated["candidates"]
        probs = evaluated["probs"]
        filtered_xml = evaluated["filtered_xml"]
        allowlisted = evaluated["allowlisted"]
        dropped_count = evaluated["dropped_count"]
        vector_counts = evaluated["vector_counts"]

        if not self.model_loaded or not candidates:
            return {
                "model_loaded": self.model_loaded,
                "backend": self.backend,
                "model_version": self.model_version,
                "schema_version": self.schema_version,
                "max_prob": 0.0,
                "t_low": self.t_low,
                "t_high": self.t_high,
                "tier": "benign",
                "gated_fusion_triggered": False,
                "scored_url_count": len(candidates) if self.model_loaded else 0,
                "allowlisted_url_count": allowlisted,
                "filtered_xml_xmp_count": filtered_xml,
                "truncated_candidate_count": dropped_count,
                "vector_counts": vector_counts,
                "top_url_vector": None,
                "top_url_prob": 0.0,
                "top_url": None,
            }

        or_gate_indices = [
            i
            for i, (cand_url, _vec) in enumerate(candidates)
            if float(probs[i]) >= self.t_high and not is_bare_dual_use_hosted_uri(cand_url)
        ]
        gated_indices = [i for i in range(len(candidates)) if float(probs[i]) >= self.t_low]
        if or_gate_indices:
            tier = "or_gate"
            best_idx = max(or_gate_indices, key=lambda i: float(probs[i]))
        elif gated_indices:
            tier = "gated_fusion"
            best_idx = max(gated_indices, key=lambda i: float(probs[i]))
        else:
            tier = "benign"
            best_idx = int(np.argmax(probs))
        max_prob = float(probs[best_idx])
        top_url, top_vec = candidates[best_idx]

        return {
            "model_loaded": True,
            "backend": self.backend,
            "model_version": self.model_version,
            "schema_version": self.schema_version,
            "max_prob": round(max_prob, 6),
            "t_low": self.t_low,
            "t_high": self.t_high,
            "tier": tier,
            "gated_fusion_triggered": False,
            "scored_url_count": len(candidates),
            "allowlisted_url_count": allowlisted,
            "filtered_xml_xmp_count": filtered_xml,
            "truncated_candidate_count": dropped_count,
            "vector_counts": vector_counts,
            "top_url_vector": top_vec,
            "top_url_prob": round(max_prob, 6),
            "top_url": top_url[:256],
        }
