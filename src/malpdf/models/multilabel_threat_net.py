from __future__ import annotations

from typing import Any

import torch
import torch.nn as nn

from malpdf.models.ast_transformer import ASTSequenceTransformer
from malpdf.models.cross_attention_fusion import CrossModalAttentionFusion
from malpdf.models.hetero_hgt import HeteroGraphTransformer
from malpdf.models.tabular_resnet import TabularResNet

LEXICAL_EXTRA_FEATURE_NAMES: list[str] = [
    "lexical_AA",
    "lexical_Acroform",
    "lexical_Launch",
    "lexical_EmbeddedFile",
    "lexical_URI",
    "lexical_ObjStm",
    "lexical_Encrypt",
    "lexical_JBIG2Decode",
    "lexical_RichMedia",
    "raw_escaped_name_candidates",
    "ast_has_loop",
    "js_has_deobf_call",
    "effective_uri_count",
    "effective_embedded_or_launch",
]

MULTILABEL_THREAT_DEFINITIONS: list[dict[str, Any]] = [
    {
        "id": "js_script_exec",
        "code_name": "JS",
        "label_vi": "Chạy mã JavaScript ngầm",
        "category_code": "trojan",
        "category_vi": "Mã kịch bản ẩn",
        "family_code": "pdfjs",
        "family_vi": "Tài liệu gắn mã JavaScript",
        "behavior_tag": "js-embedded",
        "mitre_id": "T1059.007",
        "mitre_name_vi": "Chạy mã JavaScript ẩn",
        "mitre_tactic_vi": "Thực thi mã ngầm",
        "desc_vi": "Nhúng đoạn mã kịch bản chạy ngầm bên trong tài liệu PDF",
    },
    {
        "id": "auto_open_trigger",
        "code_name": "AutoAction",
        "label_vi": "Tự động kích hoạt khi mở tệp",
        "category_code": "pdfexp",
        "category_vi": "Tự chạy khi mở tệp",
        "family_code": "autoaction",
        "family_vi": "Kích hoạt tự động khi mở",
        "behavior_tag": "autoaction",
        "mitre_id": "T1204.002",
        "mitre_name_vi": "Tự chạy khi người dùng mở tệp",
        "mitre_tactic_vi": "Kích hoạt tự động",
        "desc_vi": "Cài sẵn khóa tự chạy ngay khi người đọc vừa mở tài liệu",
    },
    {
        "id": "obfuscated_payload",
        "code_name": "ObfuscatedJS",
        "label_vi": "Làm rối mã để che giấu hành vi",
        "category_code": "obfuscated-js",
        "category_vi": "Mã ẩn bị làm rối",
        "family_code": "obfuscated-script",
        "family_vi": "Kịch bản mã hóa che giấu",
        "behavior_tag": "obfuscated",
        "mitre_id": "T1027",
        "mitre_name_vi": "Làm rối mã để che giấu",
        "mitre_tactic_vi": "Né tránh kiểm tra",
        "desc_vi": "Cố tình viết rối ký tự hoặc mã hóa chuỗi để giấu nội dung thật",
    },
    {
        "id": "buffer_loop_staging",
        "code_name": "HeapStaging",
        "label_vi": "Vòng lặp tự nạp dữ liệu vào bộ nhớ",
        "category_code": "pdfexp",
        "category_vi": "Thao túng bộ nhớ",
        "family_code": "memory-staging",
        "family_vi": "Nạp lặp dữ liệu bộ nhớ",
        "behavior_tag": "heap-staging",
        "mitre_id": "T1203",
        "mitre_name_vi": "Tác động vào phần mềm đọc PDF",
        "mitre_tactic_vi": "Khai thác ứng dụng",
        "desc_vi": "Sử dụng vòng lặp để ghép chuỗi hoặc nạp dữ liệu bất thường vào bộ nhớ",
    },
    {
        "id": "active_form_or_exploit",
        "code_name": "ReaderExploit",
        "label_vi": "Lợi dụng biểu mẫu động / lỗi trình đọc",
        "category_code": "exploit",
        "category_vi": "Khai thác trình đọc PDF",
        "family_code": "reader-exploit",
        "family_vi": "Khai thác biểu mẫu & trình đọc",
        "behavior_tag": "cve-exploit",
        "mitre_id": "T1203",
        "mitre_name_vi": "Khai thác thành phần trình đọc PDF",
        "mitre_tactic_vi": "Khai thác ứng dụng",
        "desc_vi": "Lợi dụng biểu mẫu XFA hoặc bộ giải mã đặc biệt của phần mềm đọc PDF",
    },
    {
        "id": "embedded_dropper_or_launch",
        "code_name": "DropperLaunch",
        "label_vi": "Giấu tệp lạ hoặc tự gọi lệnh máy tính",
        "category_code": "dropper",
        "category_vi": "Giấu tệp ẩn & gọi lệnh",
        "family_code": "dropper-launch",
        "family_vi": "Đính kèm tệp ẩn / gọi lệnh",
        "behavior_tag": "embedded-file",
        "mitre_id": "T1027.009",
        "mitre_name_vi": "Giấu tệp hoặc gọi lệnh ngầm",
        "mitre_tactic_vi": "Thực thi & phát tán",
        "desc_vi": "Đính kèm tệp lạ ẩn bên trong PDF hoặc chứa lệnh gọi chương trình ngoài",
    },
    {
        "id": "suspicious_uri_redirect",
        "code_name": "SuspiciousURI",
        "label_vi": "Chuyển hướng đường dẫn web đáng ngờ",
        "category_code": "phishing",
        "category_vi": "Dẫn dụ liên kết lạ",
        "family_code": "uri-redirect",
        "family_vi": "Liên kết chuyển hướng đáng ngờ",
        "behavior_tag": "uri-links",
        "mitre_id": "T1566.002",
        "mitre_name_vi": "Dẫn dụ truy cập đường dẫn lạ",
        "mitre_tactic_vi": "Dẫn dụ người đọc",
        "desc_vi": "Chứa liên kết ngoài hoặc lệnh mở trang web có dấu hiệu rủi ro",
    },
    {
        "id": "structural_parser_evasion",
        "code_name": "StructuralEvasion",
        "label_vi": "Biến dạng cấu trúc tệp để né kiểm tra",
        "category_code": "structural-evasion",
        "category_vi": "Cấu trúc PDF dị thường",
        "family_code": "structural-anomaly",
        "family_vi": "Biến đổi cấu trúc đối tượng",
        "behavior_tag": "stream-anomaly",
        "mitre_id": "T1027.006",
        "mitre_name_vi": "Biến đổi cấu trúc tài liệu",
        "mitre_tactic_vi": "Né tránh kiểm tra",
        "desc_vi": "Sắp xếp đối tượng, bảng tham chiếu hoặc luồng nén khác thường để che giấu",
    },
]


class PDFMultiLabelThreatNet(nn.Module):
    def __init__(
        self,
        node_in_dim: int = 23,
        num_node_types: int = 9,
        num_relations: int = 8,
        ast_vocab_size: int = 64,
        tabular_in_features: int = 52,
        hidden_dim: int = 128,
        num_labels: int = 8,
    ) -> None:
        super().__init__()
        self.node_in_dim = node_in_dim
        self.tabular_in_features = tabular_in_features
        self.hidden_dim = hidden_dim
        self.num_labels = num_labels

        self.graph_encoder = HeteroGraphTransformer(
            node_in_dim=node_in_dim,
            hidden_dim=hidden_dim,
            num_node_types=num_node_types,
            num_relations=num_relations,
        )
        self.ast_encoder = ASTSequenceTransformer(
            vocab_size=ast_vocab_size,
            hidden_dim=hidden_dim,
        )
        self.tabular_encoder = TabularResNet(
            in_features=tabular_in_features,
            hidden_dim=hidden_dim,
        )
        self.fusion = CrossModalAttentionFusion(hidden_dim=hidden_dim)
        self.no_graph_embedding = nn.Parameter(torch.zeros(1, hidden_dim))

        combined_dim = hidden_dim * 4
        self.trunk_proj = nn.Sequential(
            nn.Linear(combined_dim, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.SiLU(),
            nn.Dropout(0.25),
        )
        self.trunk_res = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim * 2),
            nn.LayerNorm(hidden_dim * 2),
            nn.SiLU(),
            nn.Dropout(0.20),
        )
        self.label_queries = nn.Parameter(torch.randn(num_labels, hidden_dim * 2) * 0.02)
        self.label_scale = nn.Parameter(torch.ones(num_labels))
        self.label_bias = nn.Parameter(torch.zeros(num_labels))
        self.label_linear = nn.Linear(hidden_dim * 2, num_labels)
        self.aux_mal_head = nn.Linear(hidden_dim * 2, 1)

    def forward(
        self,
        node_features: torch.Tensor | None,
        node_types: torch.Tensor | None,
        edge_index: torch.Tensor | None,
        edge_rel: torch.Tensor | None,
        batch: torch.Tensor | None,
        ast_tokens: torch.Tensor,
        tabular_features: torch.Tensor,
        graph_drop_prob: float = 0.0,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        batch_size = tabular_features.size(0)
        h_seq = self.ast_encoder(ast_tokens)
        h_tab = self.tabular_encoder(tabular_features)

        use_graph = (
            node_features is not None
            and node_types is not None
            and edge_index is not None
            and edge_rel is not None
            and batch is not None
            and node_features.numel() > 0
        )
        if use_graph and self.training and graph_drop_prob > 0.0:
            if float(torch.rand(1, device=tabular_features.device).item()) < graph_drop_prob:
                use_graph = False

        if use_graph:
            h_graph = self.graph_encoder(node_features, node_types, edge_index, edge_rel, batch)
        else:
            h_graph = self.no_graph_embedding.expand(batch_size, -1)

        z_fused, attn_weights = self.fusion(h_graph, h_seq, h_tab)
        z_cat = torch.cat([z_fused, h_tab, h_seq], dim=-1)
        h = self.trunk_proj(z_cat)
        h = h + self.trunk_res(h)

        query_scores = torch.matmul(h, self.label_queries.t()) * self.label_scale + self.label_bias
        label_logits = self.label_linear(h) + query_scores
        mal_logit = self.aux_mal_head(h).squeeze(-1)
        return label_logits, mal_logit, attn_weights
