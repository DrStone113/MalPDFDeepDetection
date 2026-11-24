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
        "label_vi": "JavaScript nhúng",
        "category_code": "trojan",
        "category_vi": "Mã kịch bản JavaScript",
        "family_code": "pdfjs",
        "family_vi": "Tài liệu có mã JavaScript",
        "behavior_tag": "js-embedded",
        "mitre_id": "T1059.007",
        "mitre_name_vi": "Thực thi mã JavaScript",
        "mitre_tactic_vi": "Thực thi mã",
        "desc_vi": "Tài liệu có nhúng mã JavaScript trong cấu trúc PDF",
    },
    {
        "id": "auto_open_trigger",
        "code_name": "AutoAction",
        "label_vi": "Hành động tự động",
        "category_code": "pdfexp",
        "category_vi": "Kích hoạt tự động",
        "family_code": "autoaction",
        "family_vi": "Tự động kích hoạt khi mở",
        "behavior_tag": "autoaction",
        "mitre_id": "T1204.002",
        "mitre_name_vi": "Tự chạy khi mở hoặc thao tác tệp",
        "mitre_tactic_vi": "Kích hoạt tự động",
        "desc_vi": "Có khóa hành động tự chạy khi mở hoặc tương tác với tài liệu",
    },
    {
        "id": "obfuscated_payload",
        "code_name": "ObfuscatedJS",
        "label_vi": "Dấu hiệu làm rối mã JavaScript",
        "category_code": "obfuscated-js",
        "category_vi": "Mã bị làm rối",
        "family_code": "obfuscated-script",
        "family_vi": "Kịch bản mã hóa hoặc làm rối",
        "behavior_tag": "obfuscated",
        "mitre_id": "T1027",
        "mitre_name_vi": "Làm rối chuỗi hoặc mã thực thi",
        "mitre_tactic_vi": "Né tránh phân tích",
        "desc_vi": "Chuỗi hoặc mã JavaScript dùng kỹ thuật mã hóa, tách ghép hay eval()",
    },
    {
        "id": "buffer_loop_staging",
        "code_name": "HeapStaging",
        "label_vi": "Vòng lặp trong JavaScript",
        "category_code": "pdfexp",
        "category_vi": "Vòng lặp xử lý dữ liệu",
        "family_code": "memory-staging",
        "family_vi": "Vòng lặp trong kịch bản",
        "behavior_tag": "heap-staging",
        "mitre_id": "T1203",
        "mitre_name_vi": "Khai thác ứng dụng trình đọc",
        "mitre_tactic_vi": "Khai thác ứng dụng",
        "desc_vi": "Chứa vòng lặp lặp lại thao tác với chuỗi hoặc bộ đệm trong JavaScript",
    },
    {
        "id": "active_form_or_exploit",
        "code_name": "ReaderExploit",
        "label_vi": "Biểu mẫu động hoặc API khai thác",
        "category_code": "exploit",
        "category_vi": "Khai thác trình đọc PDF",
        "family_code": "reader-exploit",
        "family_vi": "Biểu mẫu XFA & API trình đọc",
        "behavior_tag": "cve-exploit",
        "mitre_id": "T1203",
        "mitre_name_vi": "Khai thác thành phần trình đọc PDF",
        "mitre_tactic_vi": "Khai thác ứng dụng",
        "desc_vi": "Sử dụng biểu mẫu XFA hoặc lời gọi API từng gắn với lỗ hổng trình đọc PDF",
    },
    {
        "id": "embedded_dropper_or_launch",
        "code_name": "DropperLaunch",
        "label_vi": "Tệp đính kèm hoặc lệnh /Launch",
        "category_code": "dropper",
        "category_vi": "Đính kèm tệp & lệnh ngoài",
        "family_code": "dropper-launch",
        "family_vi": "Nhúng tệp hoặc gọi lệnh ngoài",
        "behavior_tag": "embedded-file",
        "mitre_id": "T1027.009",
        "mitre_name_vi": "Nhúng tệp hoặc khởi chạy lệnh ngoài",
        "mitre_tactic_vi": "Thực thi & truyền tải",
        "desc_vi": "Đính kèm tệp bên trong PDF hoặc chứa lệnh mở ứng dụng ngoài (/Launch)",
    },
    {
        "id": "suspicious_uri_redirect",
        "code_name": "SuspiciousURI",
        "label_vi": "Chuyển hướng URL hoặc gửi biểu mẫu",
        "category_code": "phishing",
        "category_vi": "Liên kết ngoài & gửi dữ liệu",
        "family_code": "uri-redirect",
        "family_vi": "Liên kết web hoặc gửi biểu mẫu",
        "behavior_tag": "uri-links",
        "mitre_id": "T1566.002",
        "mitre_name_vi": "Dẫn hướng tới đường dẫn ngoài",
        "mitre_tactic_vi": "Truy cập ban đầu",
        "desc_vi": "Chứa hành động gửi dữ liệu biểu mẫu (/SubmitForm) hoặc mở URL ngoài",
    },
    {
        "id": "structural_parser_evasion",
        "code_name": "StructuralEvasion",
        "label_vi": "Bất thường khi giải mã cấu trúc",
        "category_code": "structural-evasion",
        "category_vi": "Cấu trúc PDF bất thường",
        "family_code": "structural-anomaly",
        "family_vi": "Cấu trúc luồng bất thường",
        "behavior_tag": "stream-anomaly",
        "mitre_id": "T1027.006",
        "mitre_name_vi": "Biến đổi cấu trúc phân tích PDF",
        "mitre_tactic_vi": "Né tránh phân tích",
        "desc_vi": "Phát sinh lỗi giải mã luồng nén hoặc tỷ lệ giải nén vượt ngưỡng",
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
