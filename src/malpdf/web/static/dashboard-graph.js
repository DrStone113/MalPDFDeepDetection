import {
  _formatApiErrorVi,
  _formatReadableCodeSnippet,
  appState,
  loadOptionalScript,
  prefersReducedMotion,
  setIcon,
  showToast,
  syncGraphPopover,
} from "./dashboard-core.js";

let network = null;
let physicsEnabled = true;
let graphRender = null;
let graphLayoutMode = "network";
let graphThreatOnlyFilter = false;
let graphCompactPages = true;
let currentMappedGraphNodes = [];
let currentVisibleEdges = [];
let graphAnimFrameId = null;

export function _createTechnicalNodeSvgUri(nodeKind, badgeText = "") {
  const safeBadge = String(badgeText || "")
    .replace(/[<>&"']/g, "")
    .slice(0, 6);
  let bgFill = "#F8FAFC";
  let ringStroke = "#64748B";
  let innerArt = "";

  if (nodeKind === "catalog") {
    bgFill = "#EFF6FF";
    ringStroke = "#0071E3";
    innerArt = `
      <rect x="27" y="25" width="34" height="38" rx="5" fill="#FFFFFF" stroke="#0071E3" stroke-width="2.2"/>
      <path d="M27 34 H61" stroke="#BFDBFE" stroke-width="2"/>
      <circle cx="33" cy="29.5" r="1.6" fill="#0071E3"/>
      <circle cx="39" cy="29.5" r="1.6" fill="#60A5FA"/>
      <rect x="33" y="40" width="22" height="3.2" rx="1.6" fill="#0071E3"/>
      <rect x="33" y="47" width="14" height="3.2" rx="1.6" fill="#93C5FD"/>
      <path d="M44 54 H55" stroke="#CBD5E1" stroke-width="2.4" stroke-linecap="round"/>
    `;
  } else if (nodeKind === "threat_action") {
    bgFill = "#FEF2F2";
    ringStroke = "#DC2626";
    innerArt = `
      <polygon points="48,20 30,46 43,46 39,67 59,40 46,40" fill="#DC2626" stroke="#991B1B" stroke-width="1.4" stroke-linejoin="round"/>
    `;
  } else if (nodeKind === "threat_script") {
    bgFill = "#FFF1F2";
    ringStroke = "#BE123C";
    innerArt = `
      <rect x="24" y="27" width="40" height="34" rx="6" fill="#FFFFFF" stroke="#FDA4AF" stroke-width="1.8"/>
      <path d="M36 38 L29 44 L36 50" fill="none" stroke="#BE123C" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M52 38 L59 44 L52 50" fill="none" stroke="#BE123C" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>
      <line x1="47" y1="35" x2="41" y2="53" stroke="#E11D48" stroke-width="2.5" stroke-linecap="round"/>
    `;
  } else if (nodeKind === "pages") {
    bgFill = "#F1F5F9";
    ringStroke = "#334155";
    innerArt = `
      <rect x="24" y="30" width="32" height="34" rx="5" fill="#E2E8F0" stroke="#64748B" stroke-width="1.8"/>
      <rect x="29" y="25" width="32" height="34" rx="5" fill="#FFFFFF" stroke="#334155" stroke-width="2.2"/>
      <line x1="35" y1="35" x2="55" y2="35" stroke="#475569" stroke-width="2.4" stroke-linecap="round"/>
      <line x1="35" y1="42" x2="55" y2="42" stroke="#94A3B8" stroke-width="2.4" stroke-linecap="round"/>
      <line x1="35" y1="49" x2="48" y2="49" stroke="#CBD5E1" stroke-width="2.4" stroke-linecap="round"/>
    `;
  } else if (nodeKind === "page") {
    bgFill = "#ECFDF5";
    ringStroke = "#059669";
    innerArt = `
      <path d="M29 23 H50 L59 32 V63 H29 Z" fill="#FFFFFF" stroke="#059669" stroke-width="2.2" stroke-linejoin="round"/>
      <path d="M50 23 V32 H59" fill="#D1FAE5" stroke="#059669" stroke-width="2" stroke-linejoin="round"/>
      <line x1="35" y1="39" x2="53" y2="39" stroke="#6EE7B7" stroke-width="2.4" stroke-linecap="round"/>
      <text x="44" y="55" text-anchor="middle" font-family="Inter, sans-serif" font-weight="800" font-size="11" fill="#065F46">${safeBadge}</text>
    `;
  } else if (nodeKind === "stream") {
    bgFill = "#FFFBEB";
    ringStroke = "#D97706";
    innerArt = `
      <rect x="25" y="27" width="38" height="34" rx="5" fill="#FFFFFF" stroke="#D97706" stroke-width="2.1"/>
      <line x1="32" y1="36" x2="56" y2="36" stroke="#D97706" stroke-width="2.4" stroke-linecap="round"/>
      <line x1="32" y1="43" x2="52" y2="43" stroke="#F59E0B" stroke-width="2.4" stroke-linecap="round"/>
      <line x1="32" y1="50" x2="46" y2="50" stroke="#FBBF24" stroke-width="2.4" stroke-linecap="round"/>
    `;
  } else if (nodeKind === "cluster") {
    bgFill = "#F0FDFA";
    ringStroke = "#0D9488";
    innerArt = `
      <rect x="22" y="31" width="36" height="32" rx="5" fill="#CCFBF1" stroke="#0D9488" stroke-width="1.6"/>
      <rect x="27" y="26" width="36" height="32" rx="5" fill="#FFFFFF" stroke="#0D9488" stroke-width="2.2"/>
      <text x="45" y="47" text-anchor="middle" font-family="Inter, sans-serif" font-weight="800" font-size="12" fill="#0F766E">${safeBadge}</text>
    `;
  } else if (nodeKind === "ablated") {
    bgFill = "#F8FAFC";
    ringStroke = "#64748B";
    innerArt = `
      <circle cx="44" cy="44" r="18" fill="#FFFFFF" stroke="#94A3B8" stroke-width="2" stroke-dasharray="4 3"/>
      <path d="M35 44 L41 50 L53 38" fill="none" stroke="#059669" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>
    `;
  } else {
    bgFill = "#F0F9FF";
    ringStroke = "#0284C7";
    innerArt = `
      <circle cx="44" cy="44" r="18" fill="#FFFFFF" stroke="#BAE6FD" stroke-width="1.8"/>
      <path d="M39 48 L35 44 C33 42 33 38 35 36 L38 33 C40 31 44 31 46 33 L49 36" fill="none" stroke="#0284C7" stroke-width="2.5" stroke-linecap="round"/>
      <path d="M49 40 L53 44 C55 46 55 50 53 52 L50 55 C48 57 44 57 42 55 L39 52" fill="none" stroke="#0369A1" stroke-width="2.5" stroke-linecap="round"/>
      <line x1="40" y1="44" x2="48" y2="44" stroke="#0284C7" stroke-width="2.5" stroke-linecap="round"/>
    `;
  }

  const ringDash = nodeKind === "ablated" ? 'stroke-dasharray="5 4"' : "";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 88 88" width="88" height="88">
    <circle cx="44" cy="46" r="37" fill="rgba(15,23,42,0.08)"/>
    <circle cx="44" cy="44" r="37" fill="${bgFill}" stroke="${ringStroke}" stroke-width="2.8" ${ringDash}/>
    ${innerArt}
  </svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}

export function _describeGraphNodeVi(n) {
  const id = String(n.id || "");
  const kind = String(n.kind || "").toLowerCase();
  const snippet = String(n.snippet || "");
  const rawLabel = String(n.label || "");
  const isAnnotKind =
    kind === "annot" || kind === "annotation" || id.startsWith("annot:") || id.startsWith("annotation:");
  const isUriLink = !n.is_threat_trigger && !n.is_threat && snippet.includes("/URI");
  const isThreat = Boolean(n.is_threat_trigger ?? n.is_threat);

  let title = "Thành phần PDF";
  let subtitle = id;
  let shortLabel = "Thành phần PDF";
  let badgeText = "PDF";
  let roleVi = "Thành phần cấu trúc PDF";
  let plainExplain = "Thành phần cấu trúc bên trong tệp PDF.";
  let nodeKind = "uri_link";
  let borderHex = "#0284C7";
  let nodeSize = 24;
  let pageIndex = null;

  if (kind === "catalog" || id === "catalog:root") {
    title = "Đối tượng gốc tài liệu";
    subtitle = "/Catalog • Điểm bắt đầu";
    shortLabel = "Gốc PDF\n(/Catalog)";
    badgeText = "GỐC";
    roleVi = "Đối tượng gốc tài liệu (/Catalog)";
    plainExplain =
      "Điểm xuất phát khi trình đọc mở tệp PDF: từ đây dẫn tới danh sách trang và các khóa hành động nếu có.";
    nodeKind = "catalog";
    borderHex = "#0071E3";
    nodeSize = 35;
  } else if (kind === "pages" || id === "pages:root") {
    title = "Danh sách các trang";
    subtitle = "/Pages • Quản lý bố cục";
    shortLabel = "Danh sách trang\n(/Pages)";
    badgeText = "TRANG";
    roleVi = "Cây danh mục trang (/Pages)";
    plainExplain = "Thành phần chuẩn quản lý danh sách và thứ tự các trang trong tệp PDF.";
    nodeKind = "pages";
    borderHex = "#334155";
    nodeSize = 30;
  } else if (kind === "page" || id.startsWith("page:")) {
    const pageIdxMatch = id.match(/page:(\d+)/i) || rawLabel.match(/\((\d+)\)/);
    const pIdx = pageIdxMatch ? parseInt(pageIdxMatch[1], 10) : 0;
    const pageNum = pIdx + 1;
    pageIndex = pIdx;
    title = `Trang văn bản số ${pageNum}`;
    subtitle = `/Page ${pageNum} • Trang hiển thị`;
    shortLabel = `Trang ${pageNum}`;
    badgeText = `T${pageNum}`;
    roleVi = `Trang tài liệu số ${pageNum}`;
    plainExplain = `Trang hiển thị số ${pageNum} của tài liệu PDF, nơi chứa chữ viết, hình ảnh và các chú thích hoặc liên kết.`;
    nodeKind = "page";
    borderHex = "#059669";
    nodeSize = 25;
  } else if (kind === "stream" || id.startsWith("stream:")) {
    const streamPageMatch = id.match(/page_(\d+)/i) || rawLabel.match(/page_(\d+)/i);
    const pIdx = streamPageMatch ? parseInt(streamPageMatch[1], 10) : null;
    const pageNum = pIdx !== null ? pIdx + 1 : null;
    pageIndex = pIdx;
    title = pageNum ? `Nội dung chữ & hình (Trang ${pageNum})` : "Luồng nội dung hiển thị";
    subtitle = "/Contents";
    shortLabel = pageNum ? `Chữ & Hình\n(Trang ${pageNum})` : "Luồng chữ & hình";
    badgeText = "CHỮ";
    roleVi = "Luồng nội dung văn bản & hình ảnh (/Contents)";
    plainExplain =
      "Luồng dữ liệu chứa văn bản, phông chữ và hình ảnh hiển thị trên trang. Khi làm sạch tệp (CDR), phần nội dung này được giữ nguyên.";
    nodeKind = "stream";
    borderHex = "#D97706";
    nodeSize = 22;
  } else if (isAnnotKind) {
    const annotMatch = id.match(/(?:annot|annotation):(\d+)_(\d+)/i);
    const pIdx = annotMatch ? parseInt(annotMatch[1], 10) : 0;
    const pageNum = pIdx + 1;
    const annotNum = annotMatch ? parseInt(annotMatch[2], 10) + 1 : 1;
    pageIndex = pIdx;
    title = `Chú thích / Liên kết #${annotNum}`;
    subtitle = `Trên Trang ${pageNum} (/Annot)`;
    shortLabel = `Chú thích #${annotNum}\n(Trang ${pageNum})`;
    badgeText = "CH.THÍCH";
    roleVi = "Vùng chú thích / Liên kết trên trang (/Annot)";
    plainExplain = `Vùng chú thích số ${annotNum} đặt trên Trang ${pageNum}. Bản thân đối tượng chú thích này không tự thực thi mã.`;
    nodeKind = "uri_link";
    borderHex = "#0284C7";
    nodeSize = 20;
  } else if (isUriLink) {
    const actAnnotMatch = id.match(/annot_(\d+)_(\d+)/i);
    const pIdx = actAnnotMatch ? parseInt(actAnnotMatch[1], 10) : 0;
    pageIndex = pIdx;
    const uriMatch = snippet.match(/\/URI\s+([^\s>]+)/i);
    const shortUri = uriMatch ? uriMatch[1].replace(/^https?:\/\//i, "").slice(0, 24) : "Đường dẫn web";
    title = "Liên kết Web ngoài";
    subtitle = `/URI • ${shortUri}`;
    shortLabel = `Liên kết Web\n(Trang ${pIdx + 1})`;
    badgeText = "WEB";
    roleVi = "Liên kết mở trang Web (/URI)";
    plainExplain = "Liên kết mở trang web (/URI) gắn trên trang tài liệu.";
    nodeKind = "uri_link";
    borderHex = "#0284C7";
    nodeSize = 21;
  } else if (n.action_role === "destination") {
    title = "Điều hướng khi mở tài liệu";
    subtitle = "/OpenAction • Đích điều hướng";
    shortLabel = "Điều hướng\n(/OpenAction)";
    badgeText = "ĐÍCH";
    roleVi = "Thiết lập khung nhìn trang khi mở (/OpenAction)";
    plainExplain = "Chỉ thị điều hướng chọn trang hoặc khung nhìn khi mở tệp PDF.";
    nodeKind = "uri_link";
    borderHex = "#0284C7";
    nodeSize = 23;
  } else if ((kind === "action" || id.startsWith("action:")) && !isThreat) {
    title = "Hành động PDF";
    shortLabel = "Hành động PDF";
    roleVi = "Hành động trong cấu trúc PDF";
    plainExplain = "Phân tích tĩnh chưa ghi nhận dấu hiệu kích hoạt cần xem xét ở đối tượng này.";
  } else if (kind === "action" || id.startsWith("action:")) {
    if (id.includes("open_action")) {
      title = "Hành động tự chạy khi mở";
      subtitle = "/OpenAction • Tự kích hoạt";
      shortLabel = "Tự chạy khi mở\n(/OpenAction)";
      plainExplain = "CHÚ Ý: Khóa /OpenAction cấu hình hành động tự động thực thi ngay khi người dùng mở tệp PDF.";
    } else if (id.includes("aa")) {
      title = "Hành động tự động";
      subtitle = "/AA • Tự kích hoạt theo sự kiện";
      shortLabel = "Tự động theo sự kiện\n(/AA)";
      plainExplain =
        "CHÚ Ý: Khóa /AA (Additional Actions) cài đặt hành động tự chạy theo sự kiện đóng, mở hoặc chuyển trang.";
    } else {
      title = "Hành động kích hoạt (/Action)";
      subtitle = "/Action • Thực thi lệnh";
      shortLabel = "Hành động (/Action)";
      plainExplain = "Thành phần chứa chỉ thị kích hoạt hành vi tự động bên trong tệp PDF.";
    }
    badgeText = "LỆNH";
    roleVi = "Hành động tự động kích hoạt (/OpenAction / /AA)";
    nodeKind = "threat_action";
    borderHex = "#DC2626";
    nodeSize = 33;
  } else if (kind === "js" || kind === "script" || id.startsWith("script:") || kind === "filespec") {
    if (id.includes("names_js")) {
      title = "Danh mục kịch bản JavaScript";
      subtitle = "/Names/JavaScript • Lưu trữ mã";
      shortLabel = "Danh mục JS\n(/Names/JS)";
      plainExplain = "CHÚ Ý: Danh mục lưu trữ các đoạn mã JavaScript bên trong cấu trúc tệp PDF.";
    } else if (id.includes("open_action")) {
      title = "JavaScript nhúng";
      subtitle = "Chạy tự động qua /OpenAction";
      shortLabel = "JavaScript nhúng\n(Qua /OpenAction)";
      plainExplain =
        "CHÚ Ý: Trình phân tích ghi nhận JavaScript gắn với hành động tự chạy khi mở tài liệu (/OpenAction).";
    } else if (id.includes("aa")) {
      title = "JavaScript nhúng";
      subtitle = "Chạy tự động qua /AA";
      shortLabel = "JavaScript nhúng\n(Qua /AA)";
      plainExplain = "CHÚ Ý: Trình phân tích ghi nhận JavaScript gắn với sự kiện tự động (/AA) khi thao tác với trang.";
    } else if (kind === "filespec" || id.includes("embedded")) {
      title = "Tệp đính kèm nhúng";
      subtitle = "/EmbeddedFiles • Tệp nhúng";
      shortLabel = "Tệp nhúng\n(/EmbeddedFiles)";
      plainExplain = "CHÚ Ý: Tệp đính kèm nhúng bên trong cấu trúc tài liệu PDF.";
    } else {
      title = "Mã JavaScript nhúng";
      subtitle = "JavaScript trong tệp PDF";
      shortLabel = "JavaScript nhúng\n(/JS)";
      plainExplain = "CHÚ Ý: Đoạn mã JavaScript nhúng bên trong đối tượng của tệp PDF.";
    }
    const isEmbeddedFileNode = kind === "filespec" || id.includes("embedded");
    badgeText = isEmbeddedFileNode ? "ĐÍNH KÈM" : "MÃ JS";
    roleVi = isEmbeddedFileNode ? "Tệp đính kèm nhúng (/EmbeddedFiles)" : "Đoạn mã JavaScript nhúng (/JS)";
    nodeKind = "threat_script";
    borderHex = "#BE123C";
    nodeSize = 34;
  }

  const isAblated = appState.ablatedGraphNodeIds?.has(id);
  if (isAblated) {
    title = `Đã gỡ thử: ${title}`;
    subtitle = `${subtitle} • Đã gỡ thử trên bản sao`;
    shortLabel = `Đã gỡ thử\n${shortLabel.split("\n").pop() || id}`;
    badgeText = "ĐÃ GỠ";
    plainExplain =
      "Thành phần này đã được gỡ thử trên bản sao nhị phân. Hãy đối chiếu kết quả mô hình bên dưới để xem mức thay đổi điểm.";
    nodeKind = "ablated";
    borderHex = "#64748B";
  }

  const effectiveThreat = isThreat && !isAblated;
  const fontObj = {
    color: isAblated ? "#475569" : effectiveThreat ? "#881337" : "#0F172A",
    face: "Inter, sans-serif",
    size: effectiveThreat || kind === "catalog" ? 12 : 11,
    bold: effectiveThreat || kind === "catalog",
    background: isAblated
      ? "rgba(241, 245, 249, 0.94)"
      : effectiveThreat
        ? "rgba(255, 241, 242, 0.95)"
        : "rgba(255, 255, 255, 0.94)",
    strokeWidth: 0,
  };

  return {
    title,
    subtitle,
    shortLabel,
    fullLabel: shortLabel,
    badgeText,
    roleVi,
    plainExplain,
    isThreat: effectiveThreat,
    wasThreat: isThreat,
    isAblated,
    isUriLink,
    isAnnotKind,
    pageIndex,
    nodeKind,
    borderHex,
    nodeSize,
    imageUri: _createTechnicalNodeSvgUri(nodeKind, badgeText),
    fontObj,
  };
}

function _renderGraphFlowSummaryBar(mappedNodes) {
  const stepsEl = document.getElementById("graph-flow-steps");
  const badgeEl = document.getElementById("graph-flow-summary-badge");
  const barEl = document.getElementById("graph-flow-summary-bar");
  if (!stepsEl || !badgeEl || !barEl) return;

  const threatNodes = mappedNodes.filter((n) => n.desc?.isThreat);
  const pageNodes = mappedNodes.filter((n) => n.rawMeta && n.rawMeta.kind === "page");
  const streamNodes = mappedNodes.filter((n) => n.rawMeta && n.rawMeta.kind === "stream");

  barEl.className = "mb-3 p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2";
  badgeEl.textContent = `${pageNodes.length} nút trang · ${streamNodes.length} nút nội dung · ${threatNodes.length} đối tượng có dấu hiệu tĩnh`;
  badgeEl.className = "text-[11px] font-bold text-on-surface-variant";
  stepsEl.replaceChildren();
  if (threatNodes.length === 0) {
    const emptyNote = document.createElement("span");
    emptyNote.className = "text-xs text-on-surface-variant";
    emptyNote.textContent = "Không ghi nhận đối tượng kích hoạt hay JavaScript trong sơ đồ.";
    stepsEl.appendChild(emptyNote);
  } else {
    for (const node of threatNodes) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "px-2.5 py-1.5 rounded-lg border border-red-200 bg-white text-error text-xs font-semibold";
      button.textContent = node.desc.title;
      button.addEventListener("click", () => inspectAndAblateNode(node.id));
      stepsEl.appendChild(button);
    }
  }
}

export function toggleGraphControlsPopover(forceState) {
  const popover = document.getElementById("graph-controls-popover");
  if (typeof popover.togglePopover === "function") {
    if (typeof forceState === "boolean") popover.togglePopover(forceState);
    else popover.togglePopover();
    return;
  }
  const open = popover.classList.toggle(":popover-open", forceState ?? !popover.classList.contains(":popover-open"));
  syncGraphPopover(open);
}

export function wireGraphControls() {
  const byId = (id) => document.getElementById(id);
  const popover = byId("graph-controls-popover");
  const toggle = byId("btn-graph-controls-toggle");
  if (typeof popover.matches === "function") syncGraphPopover(popover.matches(":popover-open"));
  if (!("commandForElement" in HTMLButtonElement.prototype)) {
    for (const button of document.querySelectorAll('[commandfor="graph-controls-popover"]')) {
      button.addEventListener("click", () =>
        toggleGraphControlsPopover(button.getAttribute("command") === "hide-popover" ? false : undefined),
      );
    }
  }
  if (typeof popover.showPopover !== "function") {
    document.addEventListener("pointerdown", (event) => {
      if (!popover.contains(event.target) && !toggle.contains(event.target)) toggleGraphControlsPopover(false);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && popover.classList.contains(":popover-open")) {
        toggleGraphControlsPopover(false);
        toggle.focus();
      }
    });
  }
  const actions = {
    "btn-graph-mode-network": () => setGraphLayoutMode("network"),
    "btn-graph-mode-tree": () => setGraphLayoutMode("hierarchical"),
    "btn-graph-compact": toggleCompactPagesMode,
    "btn-graph-filter-threat": toggleThreatOnlyFilter,
    "btn-graph-physics": togglePhysics,
    "btn-graph-fit-popover": networkFit,
    "btn-graph-fit-quick": networkFit,
    "btn-graph-reset-controls": resetGraphViewControls,
    "btn-reset-ablation": resetGraphAblationState,
    "btn-ablate-node": () => executeNodeAblation("surgical"),
    "btn-ablate-all": () => executeNodeAblation("all_triggers"),
  };
  for (const [id, listener] of Object.entries(actions)) byId(id).addEventListener("click", listener);
  window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (event) => {
    if (event.matches) _stopGraphCanvasAnimation();
    else _startGraphCanvasAnimation();
  });
  _syncGraphControlsUI();
}

function _syncGraphControlsUI() {
  const isHierarchical = graphLayoutMode === "hierarchical";
  const btnNet = document.getElementById("btn-graph-mode-network");
  const btnTree = document.getElementById("btn-graph-mode-tree");
  const segActive =
    "px-2.5 py-1.5 rounded-lg bg-primary-container text-white font-bold shadow-xs transition flex items-center justify-center gap-1 active:scale-95 whitespace-nowrap";
  const segInactive =
    "px-2.5 py-1.5 rounded-lg text-on-surface-variant hover:text-on-surface font-semibold transition flex items-center justify-center gap-1 active:scale-95 whitespace-nowrap";
  if (btnNet) btnNet.className = isHierarchical ? segInactive : segActive;
  if (btnTree) btnTree.className = isHierarchical ? segActive : segInactive;

  const rowBase =
    "w-full flex items-center justify-between gap-2.5 px-2.5 py-2 rounded-xl border transition text-left active:scale-[0.99]";
  const rowIdle = `${rowBase} border-slate-200/80 bg-slate-50/70 hover:bg-slate-100/70`;
  const rowBlue = `${rowBase} border-blue-200/80 bg-blue-50/70`;
  const rowDanger = `${rowBase} border-red-200 bg-red-50/90`;

  const compactBtn = document.getElementById("btn-graph-compact");
  const compactLbl = document.getElementById("lbl-graph-compact");
  const compactTrack = document.getElementById("switch-graph-compact");
  if (compactBtn) {
    compactBtn.className = graphCompactPages ? rowBlue : rowIdle;
    compactBtn.setAttribute("aria-checked", graphCompactPages ? "true" : "false");
  }
  if (compactLbl)
    compactLbl.textContent = graphCompactPages
      ? "Đang bật · Thu gọn khi nhiều trang"
      : "Đang tắt · Hiện đủ tất cả trang";
  if (compactTrack) compactTrack.className = graphCompactPages ? "graph-switch-track is-on" : "graph-switch-track";

  const threatBtn = document.getElementById("btn-graph-filter-threat");
  const threatLbl = document.getElementById("lbl-graph-filter-threat");
  const threatTrack = document.getElementById("switch-graph-filter-threat");
  if (threatBtn) {
    threatBtn.className = graphThreatOnlyFilter ? rowDanger : rowIdle;
    threatBtn.setAttribute("aria-checked", graphThreatOnlyFilter ? "true" : "false");
  }
  if (threatLbl)
    threatLbl.textContent = graphThreatOnlyFilter
      ? "Đang lọc · Chỉ hiện đối tượng có dấu hiệu"
      : "Đang hiển thị tất cả thành phần";
  if (threatTrack)
    threatTrack.className = graphThreatOnlyFilter ? "graph-switch-track is-danger" : "graph-switch-track";

  const physicsBtn = document.getElementById("btn-graph-physics");
  const physicsLbl = document.getElementById("btn-physics-label");
  const physicsTrack = document.getElementById("switch-graph-physics");
  if (physicsBtn) {
    physicsBtn.className = physicsEnabled ? rowBlue : rowIdle;
    physicsBtn.setAttribute("aria-checked", physicsEnabled ? "true" : "false");
  }
  if (physicsLbl) {
    physicsLbl.textContent = physicsEnabled ? "Độ nảy vật lý: Đang bật" : "Độ nảy vật lý: Đã cố định";
    physicsLbl.className = physicsEnabled
      ? "block text-[11px] text-tertiary truncate"
      : "block text-[11px] text-outline truncate";
  }
  if (physicsTrack) physicsTrack.className = physicsEnabled ? "graph-switch-track is-on" : "graph-switch-track";

  const statusPill = document.getElementById("graph-toolbar-status-pill");
  if (statusPill) {
    const layoutText = isHierarchical ? "Phân tầng" : "Mạng lưới";
    if (graphThreatOnlyFilter) {
      statusPill.textContent = `${layoutText} · Chỉ dấu hiệu tĩnh`;
      statusPill.className =
        "px-1.5 py-0.5 rounded-md bg-red-50 text-error border border-red-200 text-[11px] font-bold whitespace-nowrap";
    } else if (!graphCompactPages) {
      statusPill.textContent = `${layoutText} · Đủ trang`;
      statusPill.className =
        "px-1.5 py-0.5 rounded-md bg-blue-50 text-primary-container border border-blue-200/80 text-[11px] font-bold whitespace-nowrap";
    } else {
      statusPill.textContent = layoutText;
      statusPill.className =
        "px-1.5 py-0.5 rounded-md bg-blue-50 text-primary-container border border-blue-200/80 text-[11px] font-bold whitespace-nowrap";
    }
  }
}

export function resetGraphViewControls() {
  graphLayoutMode = "network";
  graphCompactPages = true;
  graphThreatOnlyFilter = false;
  physicsEnabled = true;
  _syncGraphControlsUI();
  if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
  networkFit();
}

export function setGraphLayoutMode(mode) {
  graphLayoutMode = mode === "hierarchical" ? "hierarchical" : "network";
  physicsEnabled = graphLayoutMode !== "hierarchical";
  _syncGraphControlsUI();
  if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
}

export function toggleCompactPagesMode() {
  graphCompactPages = !graphCompactPages;
  _syncGraphControlsUI();
  if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
}

export function toggleThreatOnlyFilter() {
  graphThreatOnlyFilter = !graphThreatOnlyFilter;
  _syncGraphControlsUI();
  if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
}

export function _stopGraphCanvasAnimation() {
  if (graphAnimFrameId !== null) {
    cancelAnimationFrame(graphAnimFrameId);
    graphAnimFrameId = null;
  }
}

export function _startGraphCanvasAnimation() {
  if (graphAnimFrameId !== null) return;
  function step() {
    if (!network || appState.activeTab !== "graph" || document.hidden || prefersReducedMotion()) {
      graphAnimFrameId = null;
      return;
    }
    network.redraw();
    graphAnimFrameId = requestAnimationFrame(step);
  }
  step();
}
export function showCurrentGraph() {
  const data = appState.currentScanResult;
  if (!data) return;
  if (!appState.dagGraphDirty) {
    _startGraphCanvasAnimation();
    requestAnimationFrame(() => {
      if (appState.activeTab === "graph") network?.fit();
    });
    return;
  }
  if (graphRender?.data === data) return graphRender.task;
  const status = document.getElementById("graph-load-status");
  status.textContent = "Đang tải sơ đồ…";
  const task = (async () => {
    try {
      await loadOptionalScript("/assets/vis-network-10.1.5.min.js");
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      if (appState.activeTab !== "graph" || appState.currentScanResult !== data) return;
      initDAGGraph(data);
      appState.dagGraphDirty = false;
      status.textContent = "";
    } catch {
      if (appState.currentScanResult === data)
        status.textContent = "Không tải được sơ đồ. Bấm lại tab Sơ đồ cấu trúc để thử lại.";
    } finally {
      if (graphRender?.data === data) graphRender = null;
    }
  })();
  graphRender = { data, task };
  return task;
}

export function initDAGGraph(data) {
  const vis = window.vis;
  if (!vis) throw new Error("Không tải được thư viện sơ đồ.");
  const container = document.getElementById("vis-container");
  const emptyPl = document.getElementById("vis-empty-placeholder");
  if (emptyPl) emptyPl.remove();
  let nodesArray = [];
  const edgesArray = [];

  if (data.graph_nodes && data.graph_nodes.length > 0) {
    const allMapped = data.graph_nodes.map((n) => {
      const desc = _describeGraphNodeVi(n);
      return {
        id: n.id,
        label: desc.shortLabel,
        shape: "circularImage",
        image: desc.imageUri,
        size: desc.nodeSize,
        borderWidth: desc.isThreat ? 2.5 : 1.5,
        borderWidthSelected: 4,
        color: {
          border: desc.borderHex,
          background: "#FFFFFF",
          highlight: { border: "#D97706", background: "#FEF3C7" },
          hover: { border: "#0071E3", background: "#EFF6FF" },
        },
        font: desc.fontObj,
        title: `${desc.title} — ${desc.subtitle}`,
        rawMeta: n,
        desc,
      };
    });

    currentMappedGraphNodes = allMapped;
    _renderGraphFlowSummaryBar(allMapped);

    const nodeById = {};
    allMapped.forEach((item) => {
      nodeById[item.id] = item;
    });

    const rawEdges = data.graph_edges || [];

    const pageItems = allMapped.filter(
      (item) => (item.rawMeta && item.rawMeta.kind === "page") || String(item.id).startsWith("page:"),
    );
    const maxVisiblePages = 4;
    const shouldClusterPages = graphCompactPages && !graphThreatOnlyFilter && pageItems.length > maxVisiblePages;

    const hiddenByClusterIds = new Set();
    let clusterNodeObj = null;

    if (shouldClusterPages) {
      const pagesWithThreatChild = new Set();
      rawEdges.forEach((e) => {
        const target = nodeById[e.to];
        if (target?.desc?.isThreat && target.desc.pageIndex !== null) {
          pagesWithThreatChild.add(target.desc.pageIndex);
        }
      });

      const keptPageIndices = new Set([0, 1, 2]);
      for (const idx of pagesWithThreatChild) keptPageIndices.add(idx);

      let clusteredPageCount = 0;
      let clusteredStreamCount = 0;
      const hiddenPageNums = [];

      allMapped.forEach((item) => {
        const pIdx = item.desc.pageIndex;
        if (pIdx !== null && !keptPageIndices.has(pIdx) && !item.desc.isThreat) {
          hiddenByClusterIds.add(item.id);
          if (item.rawMeta && item.rawMeta.kind === "page") {
            clusteredPageCount++;
            hiddenPageNums.push(pIdx + 1);
          }
          if (item.rawMeta && item.rawMeta.kind === "stream") clusteredStreamCount++;
        }
      });

      allMapped.forEach((item) => {
        if (!hiddenByClusterIds.has(item.id) && (item.desc.isAnnotKind || item.desc.isUriLink)) {
          const m = String(item.id).match(/_(\d+)$/);
          const annotIdx = m ? parseInt(m[1], 10) : 0;
          if (annotIdx >= 2 && !item.desc.isThreat) hiddenByClusterIds.add(item.id);
        }
      });

      if (clusteredPageCount > 0) {
        hiddenPageNums.sort((a, b) => a - b);
        const firstHidden = hiddenPageNums[0] || 4;
        const lastHidden = hiddenPageNums[hiddenPageNums.length - 1] || pageItems.length;
        const rangeText = firstHidden === lastHidden ? `Trang ${firstHidden}` : `Trang ${firstHidden} → ${lastHidden}`;
        const shortRangeText = firstHidden === lastHidden ? `Tr.${firstHidden}` : `Tr.${firstHidden} → ${lastHidden}`;
        const clusterDesc = {
          title: `Cụm ${clusteredPageCount} trang văn bản được gộp`,
          subtitle: `${rangeText} • Đã thu gọn để sơ đồ dễ quan sát`,
          shortLabel: `+${clusteredPageCount} Trang khác\n(${shortRangeText})`,
          badgeText: `+${clusteredPageCount}`,
          roleVi: `Cụm ${clusteredPageCount} trang văn bản & ${clusteredStreamCount} luồng nội dung`,
          plainExplain: `Tài liệu PDF này có ${pageItems.length} trang. Hệ thống đã gộp tạm ${clusteredPageCount} trang (${rangeText}) không chứa dấu hiệu kích hoạt vào nút này. Bạn có thể tắt "Thu gọn tệp nhiều trang" để hiển thị đủ ${allMapped.length} thành phần.`,
          isThreat: false,
          isUriLink: false,
          isCluster: true,
          nodeKind: "cluster",
          borderHex: "#0D9488",
          nodeSize: 31,
          imageUri: _createTechnicalNodeSvgUri("cluster", `+${clusteredPageCount}`),
          fontObj: {
            color: "#065F46",
            face: "Inter, sans-serif",
            size: 11,
            bold: true,
            background: "rgba(236, 253, 245, 0.94)",
            strokeWidth: 0,
          },
        };
        clusterNodeObj = {
          id: "cluster:extra_pages",
          label: clusterDesc.shortLabel,
          shape: "circularImage",
          image: clusterDesc.imageUri,
          size: clusterDesc.nodeSize,
          borderWidth: 2,
          borderWidthSelected: 4,
          color: {
            border: "#0D9488",
            background: "#FFFFFF",
            highlight: { border: "#059669", background: "#D1FAE5" },
            hover: { border: "#059669", background: "#D1FAE5" },
          },
          font: clusterDesc.fontObj,
          title: clusterDesc.title,
          rawMeta: {
            id: "cluster:extra_pages",
            kind: "pages",
            size_bytes: null,
            entropy: null,
            saliency: null,
            snippet: `Đã gộp gọn ${clusteredPageCount} trang văn bản (Trang 4 -> Trang ${pageItems.length}) và ${clusteredStreamCount} luồng nội dung (/Contents).`,
          },
          desc: clusterDesc,
        };
      }
    }

    if (graphThreatOnlyFilter) {
      const anyThreat = allMapped.some((item) => item.desc.isThreat);
      nodesArray = anyThreat
        ? allMapped.filter((item) => item.id === "catalog:root" || item.id === "pages:root" || item.desc.isThreat)
        : allMapped.filter((item) => !hiddenByClusterIds.has(item.id));
    } else {
      nodesArray = allMapped.filter((item) => !hiddenByClusterIds.has(item.id));
      if (clusterNodeObj) nodesArray.push(clusterNodeObj);
    }

    const visibleIds = new Set(nodesArray.map((item) => item.id));
    const dedupEdgeSet = new Set();

    rawEdges.forEach((e) => {
      if (!visibleIds.has(e.from) || !visibleIds.has(e.to)) return;
      const key = `${e.from}->${e.to}`;
      if (dedupEdgeSet.has(key)) return;
      dedupEdgeSet.add(key);

      const toNode = nodeById[e.to];
      const isThreatEdge = Boolean(toNode?.desc?.isThreat);
      const isAblatedEdge = Boolean(toNode?.desc?.isAblated);
      edgesArray.push({
        from: e.from,
        to: e.to,
        isThreatEdge,
        arrows: { to: { enabled: true, scaleFactor: 0.72 } },
        color: isThreatEdge
          ? { color: "#DC2626", highlight: "#B91C1C", hover: "#B91C1C" }
          : { color: "#94A3B8", highlight: "#0071E3", hover: "#0071E3" },
        width: isThreatEdge ? 2.8 : 1.8,
        dashes: Boolean(isAblatedEdge || (toNode?.desc && (toNode.desc.isUriLink || toNode.desc.isAnnotKind))),
      });
    });

    if (
      clusterNodeObj &&
      visibleIds.has("pages:root") &&
      rawEdges.some(
        (edge) =>
          edge.from === "pages:root" && hiddenByClusterIds.has(edge.to) && nodeById[edge.to]?.rawMeta.kind === "page",
      )
    ) {
      edgesArray.push({
        from: "pages:root",
        to: "cluster:extra_pages",
        isThreatEdge: false,
        arrows: { to: { enabled: true, scaleFactor: 0.72 } },
        color: { color: "#059669", highlight: "#047857", hover: "#047857" },
        width: 2.0,
        dashes: [6, 5],
      });
    }
  } else {
    currentMappedGraphNodes = [];
  }

  currentVisibleEdges = edgesArray;
  document.getElementById("graph-node-count").textContent =
    currentMappedGraphNodes.length > nodesArray.length
      ? `${nodesArray.length} (gộp từ ${currentMappedGraphNodes.length})`
      : `${nodesArray.length}`;
  document.getElementById("graph-edge-count").textContent = edgesArray.length;

  const nodes = new vis.DataSet(nodesArray);
  const edges = new vis.DataSet(edgesArray);

  const isHierarchical = graphLayoutMode === "hierarchical";
  const options = {
    layout: isHierarchical
      ? {
          hierarchical: {
            enabled: true,
            direction: "UD",
            sortMethod: "directed",
            levelSeparation: 120,
            nodeSpacing: 170,
            treeSpacing: 195,
          },
        }
      : { hierarchical: { enabled: false } },
    physics: isHierarchical
      ? { enabled: false }
      : {
          enabled: true,
          stabilization: { iterations: 90, updateInterval: 25 },
          barnesHut: {
            gravitationalConstant: -3200,
            centralGravity: 0.28,
            springLength: 130,
            springConstant: 0.045,
            damping: 0.28,
            avoidOverlap: 0.92,
          },
        },
    interaction: { hover: true, zoomView: true, dragNodes: true, tooltipDelay: 80 },
    nodes: {
      shapeProperties: { useBorderWithImage: true },
      shadow: { enabled: true, color: "rgba(15, 23, 42, 0.10)", size: 8, x: 0, y: 3 },
    },
    edges: {
      smooth: isHierarchical
        ? { type: "cubicBezier", forceDirection: "vertical", roundness: 0.35 }
        : { type: "dynamic", roundness: 0.35 },
    },
  };

  if (network) network.destroy();
  physicsEnabled = !isHierarchical;
  _syncGraphControlsUI();

  network = new vis.Network(container, { nodes, edges }, options);

  network.on("beforeDrawing", (ctx) => {
    const now = performance.now() * 0.001;
    const positions = network.getPositions();
    nodesArray.forEach((n) => {
      const pos = positions[n.id];
      if (!pos) return;
      if (n.desc?.isThreat) {
        const pulse1 = (now * 1.1) % 1;
        const pulse2 = (now * 1.1 + 0.5) % 1;
        [pulse1, pulse2].forEach((p) => {
          const radius = (n.size || 30) + 6 + p * 24;
          const alpha = (1 - p) * 0.34;
          ctx.save();
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(220, 38, 38, ${alpha * 0.28})`;
          ctx.fill();
          ctx.lineWidth = 2.0;
          ctx.strokeStyle = `rgba(220, 38, 38, ${alpha})`;
          ctx.stroke();
          ctx.restore();
        });
        ctx.save();
        ctx.translate(pos.x, pos.y);
        ctx.rotate(now * 0.85);
        ctx.beginPath();
        ctx.setLineDash([5, 5]);
        ctx.arc(0, 0, (n.size || 30) + 8, 0, Math.PI * 2);
        ctx.lineWidth = 1.6;
        ctx.strokeStyle = "rgba(220, 38, 38, 0.55)";
        ctx.stroke();
        ctx.restore();
      } else if (n.id === "catalog:root") {
        const breathe = Math.sin(now * 2.2) * 3.5;
        ctx.save();
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, (n.size || 34) + 9 + breathe, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 113, 227, 0.10)";
        ctx.fill();
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = "rgba(0, 113, 227, 0.25)";
        ctx.stroke();
        ctx.restore();
      }

      if (appState.selectedGraphNode && appState.selectedGraphNode.id === n.id) {
        const bounce = Math.sin(now * 3.8) * 2.2;
        ctx.save();
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, (n.size || 26) + 7 + bounce, 0, Math.PI * 2);
        ctx.lineWidth = 2.5;
        ctx.strokeStyle = n.desc?.isThreat ? "#D97706" : "#0071E3";
        ctx.stroke();
        ctx.restore();
      }
    });
  });

  network.on("afterDrawing", (ctx) => {
    const now = performance.now() * 0.001;
    const positions = network.getPositions();

    currentVisibleEdges.forEach((edge, idx) => {
      const pFrom = positions[edge.from];
      const pTo = positions[edge.to];
      if (!pFrom || !pTo) return;
      const speed = edge.isThreatEdge ? 0.85 : 0.42;
      const t = (now * speed + idx * 0.21) % 1;
      const x = pFrom.x + (pTo.x - pFrom.x) * t;
      const y = pFrom.y + (pTo.y - pFrom.y) * t;

      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, edge.isThreatEdge ? 4.5 : 3.0, 0, Math.PI * 2);
      ctx.fillStyle = edge.isThreatEdge ? "#DC2626" : "#0071E3";
      ctx.shadowColor = edge.isThreatEdge ? "#DC2626" : "#0071E3";
      ctx.shadowBlur = 7;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(x, y, edge.isThreatEdge ? 2.0 : 1.3, 0, Math.PI * 2);
      ctx.fillStyle = "#FFFFFF";
      ctx.fill();
      ctx.restore();
    });

    nodesArray.forEach((n, idx) => {
      if (!n.desc?.isThreat) return;
      const pos = positions[n.id];
      if (!pos) return;
      const bobY = pos.y - (n.size || 32) - 16 + Math.sin(now * 3.2 + idx) * 2.6;
      const tagText =
        n.desc.nodeKind === "threat_action" ? "TỰ CHẠY" : n.desc.badgeText === "ĐÍNH KÈM" ? "ĐÍNH KÈM" : "MÃ JS";
      ctx.save();
      ctx.font = "700 9.5px Inter, sans-serif";
      const tw = ctx.measureText(tagText).width + 14;
      const rx = pos.x - tw / 2;
      const ry = bobY - 9;
      ctx.fillStyle = "#DC2626";
      ctx.strokeStyle = "rgba(255, 255, 255, 0.92)";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.roundRect(rx, ry, tw, 18, 6);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = "#FFFFFF";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(tagText, pos.x, bobY);
      ctx.restore();
    });
  });

  _startGraphCanvasAnimation();

  network.on("click", (params) => {
    if (params.nodes.length > 0) {
      const clickedId = params.nodes[0];
      const nodeObj =
        nodesArray.find((n) => n.id === clickedId) || currentMappedGraphNodes.find((n) => n.id === clickedId);
      if (nodeObj) selectNodeForInspection(nodeObj);
    }
  });

  network.on("doubleClick", (params) => {
    if (params.nodes.length > 0 && params.nodes[0] === "cluster:extra_pages") toggleCompactPagesMode();
  });

  const preservedSelection =
    appState.selectedGraphNode && nodesArray.find((n) => n.id === appState.selectedGraphNode.id);
  const threatNode = nodesArray.find((n) => n.desc?.isThreat);
  if (preservedSelection) {
    selectNodeForInspection(preservedSelection, true);
    network.selectNodes([preservedSelection.id]);
  } else if (threatNode) {
    selectNodeForInspection(threatNode);
    network.selectNodes([threatNode.id]);
  } else if (nodesArray.length > 0) {
    selectNodeForInspection(nodesArray[0]);
    network.selectNodes([nodesArray[0].id]);
  }
}

export function selectNodeForInspection(nodeObj, preserveAblationBox = false) {
  appState.selectedGraphNode = nodeObj;
  const meta = nodeObj.rawMeta || nodeObj || {};
  const desc = nodeObj.desc || _describeGraphNodeVi(meta);

  document.getElementById("graph-node-details").textContent =
    `Đang xem: ${desc.title} (${desc.subtitle}) • Vai trò: ${desc.roleVi}`;

  document.getElementById("hud-node-title").textContent = desc.title;
  document.getElementById("hud-node-subtitle").textContent = `${desc.subtitle} • ID nút: ${nodeObj.id}`;
  document.getElementById("hud-node-badge").textContent = desc.badgeText;

  const plainEl = document.getElementById("hud-node-plain-explain");
  const plainBox = document.getElementById("hud-node-plain-box");
  if (plainEl) plainEl.textContent = desc.plainExplain;
  if (plainBox) {
    plainBox.className = desc.isThreat
      ? "p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-950 leading-relaxed space-y-1"
      : desc.isAblated
        ? "p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-950 leading-relaxed space-y-1"
        : "p-3 rounded-lg bg-blue-50/70 border border-blue-200 text-xs text-on-surface leading-relaxed space-y-1";
  }

  const statusTag = document.getElementById("hud-node-status-tag");
  if (desc.isAblated) {
    statusTag.textContent = "ĐÃ GỠ TRÊN BẢN THỬ";
    statusTag.className =
      "px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 shrink-0";
  } else if (desc.isThreat) {
    statusTag.textContent = "CÓ DẤU HIỆU TĨNH";
    statusTag.className =
      "px-2.5 py-1 rounded-md text-xs font-bold bg-red-50 text-error border border-red-200 shrink-0";
  } else if (desc.isUriLink || desc.isAnnotKind) {
    statusTag.textContent = "LIÊN KẾT / GHI CHÚ";
    statusTag.className =
      "px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 shrink-0";
  } else {
    statusTag.textContent = "CẤU TRÚC PDF";
    statusTag.className =
      "px-2.5 py-1 rounded-md text-xs font-bold bg-slate-100 text-on-surface-variant border border-slate-200 shrink-0";
  }

  document.getElementById("hud-node-type").textContent = desc.roleVi;
  const measureSource = (source) => (source === "pdf_object_span" ? "đo trên đối tượng PDF" : "đo trên luồng mã hóa");
  document.getElementById("hud-node-size").textContent =
    meta.size_source && Number.isFinite(meta.size_bytes)
      ? `${meta.size_bytes} byte · ${measureSource(meta.size_source)}`
      : "Chưa đo";
  document.getElementById("hud-node-entropy").textContent =
    meta.entropy_source && Number.isFinite(meta.entropy)
      ? `${meta.entropy.toFixed(2)} / 8 · ${measureSource(meta.entropy_source)}`
      : "Chưa đo";
  const influence = meta.xai_saliency ?? meta.saliency;
  document.getElementById("hud-node-saliency").textContent = Number.isFinite(influence)
    ? `${(influence * 100).toFixed(1)}%`
    : "Chưa đo";
  document.getElementById("ablate-text").textContent = desc.isCluster
    ? "Mở cụm trang"
    : desc.isThreat
      ? "Thử gỡ trên bản sao"
      : "Thử che đặc trưng trong mô hình";

  const snippetEl = document.getElementById("hud-snippet-code");
  const rawSnippet = meta.snippet || "";
  snippetEl.textContent = rawSnippet
    ? _formatReadableCodeSnippet(rawSnippet)
    : "Chưa có bản xem trước cho đối tượng này.";

  if (!preserveAblationBox) document.getElementById("ablation-result-box").classList.add("hidden");
}

export async function inspectAndAblateNode(targetId) {
  const data = appState.currentScanResult;
  if (appState.dagGraphDirty) await showCurrentGraph();
  if (!data || data !== appState.currentScanResult || appState.activeTab !== "graph" || appState.dagGraphDirty) return;
  if (currentMappedGraphNodes && currentMappedGraphNodes.length > 0) {
    const found = currentMappedGraphNodes.find(
      (n) =>
        n.id === targetId ||
        String(targetId).includes(n.id) ||
        String(n.id).includes(targetId) ||
        (n.rawMeta &&
          (n.rawMeta.evidence_id === targetId ||
            n.rawMeta.obj_ref_str === targetId ||
            String(n.rawMeta.label || "").includes(targetId))),
    );
    if (found) {
      let needsReinit = false;
      if (graphThreatOnlyFilter && !found.desc?.isThreat && found.id !== "catalog:root" && found.id !== "pages:root") {
        graphThreatOnlyFilter = false;
        needsReinit = true;
      }
      if (
        graphCompactPages &&
        found.desc &&
        found.desc.pageIndex !== null &&
        found.desc.pageIndex >= 3 &&
        !found.desc.isThreat
      ) {
        graphCompactPages = false;
        needsReinit = true;
      }
      if (needsReinit) {
        _syncGraphControlsUI();
        if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
      }
      selectNodeForInspection(found);
      if (network) {
        try {
          network.selectNodes([found.id]);
          network.focus(found.id, { scale: 1.15, animation: { duration: 320, easingFunction: "easeInOutQuad" } });
        } catch (_e) {}
      }
    }
  }
}

export function resetGraphAblationState() {
  appState.ablatedGraphNodeIds.clear();
  const resetBtn = document.getElementById("btn-reset-ablation");
  if (resetBtn) resetBtn.classList.add("hidden");
  const resBox = document.getElementById("ablation-result-box");
  if (resBox) resBox.classList.add("hidden");
  if (appState.currentScanResult) initDAGGraph(appState.currentScanResult);
  showToast("Đã khôi phục sơ đồ cấu trúc về trạng thái ban đầu.", "info", 2200);
}

export async function executeNodeAblation(mode = "surgical") {
  if (!appState.selectedGraphNode) {
    showToast("Hãy bấm chọn một thành phần trên sơ đồ trước khi chạy phép thử.", "warning");
    return;
  }
  if (appState.selectedGraphNode.id === "cluster:extra_pages") {
    toggleCompactPagesMode();
    return;
  }

  const btn = document.getElementById("btn-ablate-node");
  const icon = document.getElementById("ablate-icon");
  const text = document.getElementById("ablate-text");

  setIcon(icon, "progress_activity");
  icon.classList.add("animate-spin");
  text.textContent = "Đang chạy phép thử…";
  btn.disabled = true;

  const formData = new FormData();
  formData.append("node_id", appState.selectedGraphNode.id);
  formData.append("ablate_mode", mode);
  if (appState.currentScanResult?.scan_id) formData.append("scan_id", appState.currentScanResult.scan_id);
  if (appState.ablatedGraphNodeIds.size > 0)
    formData.append("exclude_node_ids", Array.from(appState.ablatedGraphNodeIds).join(","));

  try {
    const res = await fetch("/api/xai/ablate", { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(_formatApiErrorVi(res.status, err.detail) || `Mã lỗi ${res.status}`);
    }
    const abl = await res.json();

    const binary = abl.ablation_method === "pikepdf_binary_excision";
    const excisedNodes = binary && Array.isArray(abl.excised_node_ids) ? abl.excised_node_ids : [];
    for (const id of excisedNodes) appState.ablatedGraphNodeIds.add(id);
    if (excisedNodes.length > 0 && appState.currentScanResult) {
      const resetBtn = document.getElementById("btn-reset-ablation");
      if (resetBtn) resetBtn.classList.remove("hidden");
      initDAGGraph(appState.currentScanResult);
    }

    const resBox = document.getElementById("ablation-result-box");
    resBox.classList.remove("hidden");

    const vAfter = abl.verdict_after;
    const vBadge = document.getElementById("ablation-res-verdict");
    vBadge.textContent = vAfter === "MALICIOUS" ? "VƯỢT NGƯỠNG" : vAfter === "BENIGN" ? "DƯỚI NGƯỠNG" : "CHƯA CÓ ĐIỂM";
    vBadge.className =
      vAfter === "MALICIOUS"
        ? "px-2 py-0.5 rounded-md text-[10px] font-bold bg-red-50 text-error border border-red-200"
        : vAfter === "BENIGN"
          ? "px-2 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 text-tertiary border border-emerald-200"
          : "px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200";

    const excisedKeysEl = document.getElementById("ablation-excised-keys");
    if (excisedKeysEl) {
      const keysList = Array.isArray(abl.excised_keys) ? abl.excised_keys : [];
      excisedKeysEl.textContent = binary
        ? keysList.length > 0
          ? `Khóa gỡ trên bản sao PDF: ${keysList.join(", ")}`
          : "Không có khóa kích hoạt nào cần gỡ cho thành phần này."
        : `Đã che ${abl.masked_node_count ?? 1} nút trong đầu vào mô hình. Tệp PDF giữ nguyên.`;
    }

    document.getElementById("ablation-prob-before").textContent = (abl.prob_before * 100).toFixed(2) + "%";
    document.getElementById("ablation-prob-after").textContent = (abl.prob_after * 100).toFixed(2) + "%";

    const delta = abl.prob_delta * 100;
    const deltaEl = document.getElementById("ablation-prob-delta");
    deltaEl.textContent = `${delta >= 0 ? "+" : ""}${delta.toFixed(2)} điểm %`;
    deltaEl.className =
      delta <= 0
        ? "text-sm font-extrabold text-tertiary font-mono num"
        : "text-sm font-extrabold text-error font-mono num";

    const remBox = document.getElementById("ablation-remaining-box");
    const remText = document.getElementById("ablation-remaining-text");
    const remNodes = Array.isArray(abl.remaining_threat_node_ids) ? abl.remaining_threat_node_ids : [];
    if (remBox && remText) {
      remBox.classList.toggle("hidden", !binary || remNodes.length === 0);
      if (binary && remNodes.length) {
        remText.textContent = `Bản thử còn ${remNodes.length} đối tượng có dấu hiệu tĩnh.`;
      }
    }

    document.getElementById("ablation-latency-tag").textContent = Number.isFinite(abl.latency_ms)
      ? `Thời gian phép thử ${abl.latency_ms.toFixed(1)} ms`
      : "";
  } catch (err) {
    showToast("Không thể thử gỡ thành phần này: " + err.message, "error");
  } finally {
    setIcon(icon, "content_cut");
    icon.classList.remove("animate-spin");
    text.textContent = appState.selectedGraphNode?.desc?.isCluster
      ? "Mở cụm trang"
      : appState.selectedGraphNode?.desc?.isThreat
        ? "Thử gỡ trên bản sao"
        : "Thử che đặc trưng trong mô hình";
    btn.disabled = false;
  }
}

export function networkFit() {
  network?.fit({ animation: prefersReducedMotion() ? false : { duration: 280, easingFunction: "easeInOutQuad" } });
}

export function togglePhysics() {
  physicsEnabled = !physicsEnabled;
  if (network) network.setOptions({ physics: { enabled: physicsEnabled } });
  _syncGraphControlsUI();
}

// ==========================================
// 9. LIVE CDR DISARM & VISUAL DIFF
