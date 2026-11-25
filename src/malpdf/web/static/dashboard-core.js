export const appState = {
  currentScanResult: null,
  currentCDRAudit: null,
  selectedGraphNode: null,
  ablatedGraphNodeIds: new Set(),
  activeTab: "scan",
  dagGraphDirty: false,
  diffViewMode: "side",
  diffSplitPercent: 50,
  isDraggingDiffSplit: false,
  totalDiffPages: 1,
  currentDiffPage: 0,
  activeScanToken: 0,
  maxUploadBytes: 100 * 1024 * 1024,
  gzipScanUpload: false,
  activeScanXhr: null,
  previewRequest: null,
  historyRequest: 0,
  disarmingScans: new Set(),
  unconfirmedCDR: new Map(),
  visualDiffCache: new Map(),
};

const assetPaths = new Set([
  "/assets/vis-network-10.1.5.min.js",
  "/assets/marked-18.3.0.min.js",
  "/assets/purify-3.5.0.min.js",
]);
const optionalScripts = new Map();
let policies;

export function initTrustedTypes() {
  if (policies) return policies;
  const trustedTypes = globalThis.trustedTypes ?? { createPolicy: (_name, rules) => rules };
  policies = {
    scriptUrlPolicy: trustedTypes.createPolicy("malpdf-script-url", {
      createScriptURL(value) {
        const url = new URL(value, window.location.origin);
        if (
          url.origin !== window.location.origin ||
          !assetPaths.has(url.pathname) ||
          url.username ||
          url.password ||
          url.hash ||
          (url.search && !/^\?v=[\w.-]+$/.test(url.search))
        ) {
          throw new TypeError("Invalid optional dashboard asset");
        }
        return url.href;
      },
    }),
    htmlPolicy: trustedTypes.createPolicy("malpdf-html", { createHTML: _escTax }),
  };
  return policies;
}

export function dom(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    if (child instanceof Node) el.append(child);
    else {
      const text = document.createTextNode("");
      text.textContent = String(child);
      el.append(text);
    }
  }
  return el;
}

export function setIcon(el, iconName) {
  el.dataset.icon = iconName;
  el.textContent = "";
  el.setAttribute("aria-hidden", "true");
}

export function icon(name, classes = "") {
  const el = dom("span", { class: "material-symbols-outlined " + classes });
  setIcon(el, name);
  return el;
}

export function prefersReducedMotion() {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

export function loadOptionalScript(src) {
  const { scriptUrlPolicy } = initTrustedTypes();
  const trustedSrc = scriptUrlPolicy.createScriptURL(src);
  const key = String(trustedSrc);
  if (!optionalScripts.has(key)) {
    const script = document.createElement("script");
    script.src = trustedSrc;
    const pending = new Promise((resolve, reject) => {
      script.addEventListener("load", resolve, { once: true });
      script.addEventListener(
        "error",
        () => {
          optionalScripts.delete(key);
          script.remove();
          reject(new Error("Không tải được tài nguyên giao diện"));
        },
        { once: true },
      );
    });
    optionalScripts.set(key, pending);
    document.head.append(script);
  }
  return optionalScripts.get(key);
}

export function syncGraphPopover(open) {
  const toggle = document.getElementById("btn-graph-controls-toggle");
  if (!toggle) return;
  toggle.setAttribute("aria-expanded", String(open));
  document.getElementById("graph-controls-chevron")?.classList.toggle("rotate-180", open);
  if (open && !CSS.supports("top", "anchor(bottom)")) {
    const popover = document.getElementById("graph-controls-popover");
    const anchor = toggle.getBoundingClientRect();
    const left = Math.max(8, Math.min(anchor.left, window.innerWidth - popover.offsetWidth - 8));
    const below = anchor.bottom + 8;
    const top =
      below + popover.offsetHeight <= window.innerHeight ? below : Math.max(8, anchor.top - popover.offsetHeight - 8);
    popover.style.setProperty("--graph-popover-left", left + "px");
    popover.style.setProperty("--graph-popover-top", top + "px");
  }
}

export function updateTabs(tablist, selected, untilFound = false) {
  for (const tab of tablist.querySelectorAll('[role="tab"]')) {
    const active = tab.dataset.tab === selected;
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    const panel = document.getElementById(tab.getAttribute("aria-controls"));
    if (!panel) continue;
    panel.classList.toggle("hidden", !active && !untilFound);
    if (active) panel.removeAttribute("hidden");
    else panel.setAttribute("hidden", untilFound ? "until-found" : "");
  }
}

export function showToast(message, type = "info", duration = 3500) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const tones = {
    success: ["check_circle", "text-tertiary"],
    error: ["error", "text-error"],
    warning: ["warning", "text-amber-800"],
    info: ["info", "text-primary-container"],
  };
  const [name, tone] = Object.hasOwn(tones, type) ? tones[type] : tones.info;
  const msg = String(message ?? "");
  let previousFocus = document.activeElement;
  const close = dom(
    "button",
    {
      type: "button",
      class: "text-outline hover:text-on-surface shrink-0 toast-close",
      "aria-label": "Đóng thông báo",
    },
    icon("close", "text-[16px]"),
  );
  const progress = dom("div", { class: "toast-progress " + tone, "aria-hidden": "true" });
  const toast = dom(
    "div",
    {
      class: "glass-card pointer-events-auto p-3.5 rounded-xl flex items-start gap-3 overflow-hidden toast-enter",
    },
    icon(name, "text-[20px] shrink-0 mt-0.5 " + tone),
    dom("div", { class: "flex-1 text-xs text-on-surface font-semibold leading-relaxed" }, msg),
    close,
    progress,
  );
  container.append(toast);
  if (
    container.hasAttribute("popover") &&
    typeof container.showPopover === "function" &&
    !container.matches(":popover-open")
  )
    container.showPopover();

  if (typeof document.body?.ariaNotify === "function") document.body.ariaNotify(msg);
  else {
    const announcer = document.getElementById("sr-announcer");
    if (announcer) {
      announcer.textContent = "";
      requestAnimationFrame(() => {
        announcer.textContent = msg;
      });
    }
  }

  let remaining = Math.max(0, duration);
  let deadline;
  let timer;
  let hovered = false;
  let focused = false;
  let dismissed = false;
  const countdown = prefersReducedMotion()
    ? null
    : progress.animate?.([{ transform: "scaleX(1)" }, { transform: "scaleX(0)" }], {
        duration: remaining,
        fill: "forwards",
      });
  function dismiss() {
    dismissed = true;
    clearTimeout(timer);
    countdown?.cancel();
    const restore = toast.contains(document.activeElement);
    const next =
      toast.nextElementSibling?.querySelector(".toast-close") ??
      toast.previousElementSibling?.querySelector(".toast-close");
    toast.remove();
    if (!container.childElementCount && container.hasAttribute("popover")) container.hidePopover?.();
    if (restore) (next ?? previousFocus)?.focus({ preventScroll: true });
  }
  function syncTimer() {
    if (dismissed) return;
    if (hovered || focused) {
      if (timer === undefined) return;
      remaining = Math.max(0, deadline - performance.now());
      clearTimeout(timer);
      timer = undefined;
      countdown?.pause();
      return;
    }
    if (timer !== undefined) return;
    deadline = performance.now() + remaining;
    timer = setTimeout(dismiss, remaining);
    countdown?.play();
  }
  close.addEventListener("click", dismiss);
  toast.addEventListener("pointerenter", () => {
    hovered = true;
    syncTimer();
  });
  toast.addEventListener("pointerleave", () => {
    hovered = false;
    syncTimer();
  });
  toast.addEventListener("focusin", (event) => {
    if (event.relatedTarget && !container.contains(event.relatedTarget)) previousFocus = event.relatedTarget;
    focused = true;
    syncTimer();
  });
  toast.addEventListener("focusout", (event) => {
    focused = toast.contains(event.relatedTarget);
    syncTimer();
  });
  syncTimer();
}

const copyTimers = new WeakMap();

export async function copyText(elementId, btnElement = null) {
  const text = document.getElementById(elementId)?.textContent.trim();
  if (!text || text === "--") {
    showToast("Chưa có mã SHA-256 để sao chép.", "info");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    showToast("Không sao chép được mã SHA-256.", "error");
    return;
  }
  showToast("Đã sao chép mã SHA-256: " + text.slice(0, 20) + "…", "success");
  if (!btnElement) return;
  const previous = copyTimers.get(btnElement);
  clearTimeout(previous?.timer);
  const children = previous?.children ?? Array.from(btnElement.childNodes);
  btnElement.classList.add("copy-confirmed");
  btnElement.replaceChildren(icon("check", "text-[13px]"), " Đã chép");
  const timer = setTimeout(() => {
    btnElement.classList.remove("copy-confirmed");
    btnElement.replaceChildren(...children);
    copyTimers.delete(btnElement);
  }, 1800);
  copyTimers.set(btnElement, { timer, children });
}

export function animateValue(id, start, end, duration, decimals = 0, suffix = "") {
  const obj = typeof id === "string" ? document.getElementById(id) : id;
  if (!obj) return;
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
    obj.textContent = Number(end.toFixed(decimals)).toLocaleString() + suffix;
    return;
  }
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    const ease = 1 - (1 - progress) ** 3;
    const val = (start + (end - start) * ease).toFixed(decimals);
    obj.textContent = Number(val).toLocaleString() + suffix;
    if (progress < 1) window.requestAnimationFrame(step);
  };
  window.requestAnimationFrame(step);
}

export function formatBytesVi(bytes) {
  const n = Number(bytes || 0);
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export const _API_ERROR_VI = {
  empty_upload: "Tệp tải lên bị rỗng.",
  empty_eml_upload: "Tệp email tải lên bị rỗng.",
  size_limit_exceeded: "Tệp vượt quá giới hạn dung lượng cho phép.",
  not_a_pdf_missing_header: "Tệp không có phần mở đầu PDF (%PDF-).",
  pdf_parse_failed: "Không đọc được cấu trúc PDF (tệp có thể bị hỏng hoặc đặt mật khẩu).",
  scan_job_not_found: "Không tìm thấy phiên kiểm tra này (phiên có thể đã hết hạn).",
  no_document_staged_upload_first: "Chưa có tệp PDF đang mở; vui lòng tải lên một tệp trước.",
  question_empty: "Vui lòng nhập nội dung câu hỏi.",
  question_too_long: "Câu hỏi vượt quá giới hạn độ dài cho phép.",
  no_scan_data_for_ai_analysis: "Chưa có dữ liệu kết quả quét để giải thích.",
  cloud_ai_unavailable: "Cloud AI hiện chưa khả dụng trên máy chủ này.",
  no_sanitized_output_run_disarm_first: "Chưa có bản đã xử lý; hãy chạy Làm sạch tệp trước.",
  eml_job_not_found: "Không tìm thấy phiên kiểm tra email này.",
  email_held_for_review: "Email có tệp đính kèm chưa thể chấm điểm tự động nên không xuất bản tải về.",
  quarantine_item_not_found: "Không tìm thấy tệp trong danh sách cách ly.",
  no_scan_result_available: "Chưa có kết quả kiểm tra để xuất báo cáo.",
  cdr_action_traversal_limit: "Cấu trúc hành động PDF vượt quá giới hạn duyệt an toàn khi làm sạch.",
  cdr_active_key_verification_failed: "Xác minh sau làm sạch vẫn còn khóa thực thi nên đã hủy xuất tệp.",
  cdr_page_content_or_resources_changed: "Nội dung hiển thị hoặc tài nguyên trang bị thay đổi nên đã hủy xuất tệp.",
  cdr_extracted_text_changed: "Văn bản trích xuất sau làm sạch không khớp bản gốc nên đã hủy xuất tệp.",
  ablation_target_not_observed: "Thành phần này không tồn tại ở dạng khóa có thể cắt thử.",
  "Trained model weights unavailable": "Mô hình chấm điểm chưa sẵn sàng trên máy chủ.",
  "ONNX model weights unavailable": "Mô hình ONNX chưa sẵn sàng trên máy chủ.",
  "Ablation unavailable: training feature contract unverified":
    "Chưa thể thử gỡ đối chứng vì thiếu thông số hợp đồng đặc trưng.",
  "Ablation rescoring unavailable": "Chưa thể chấm điểm lại cho phép thử này.",
};

export function _formatApiErrorVi(status, detail) {
  const clean = String(detail || "").trim();
  if (clean && _API_ERROR_VI[clean]) return _API_ERROR_VI[clean];
  if (status === 404) return "Phiên làm việc đã hết hạn hoặc không tìm thấy dữ liệu. Hãy tải tệp lại.";
  if (status === 403) return "Yêu cầu bị từ chối vì không đúng nguồn truy cập hợp lệ.";
  if (status === 502 || status === 504) return "Máy chủ phản hồi quá thời gian chờ. Vui lòng thử lại.";
  return clean || `Mã lỗi ${status}`;
}

export function _formatScanErrorVi(status, detail) {
  if (detail === "invalid_scan_upload_gzip" || detail === "unsupported_scan_upload_encoding") {
    return "Máy chủ không đọc được tệp đã nén khi gửi. Hãy thử kiểm tra lại.";
  }
  const limitMb = Math.max(1, Math.round(appState.maxUploadBytes / (1024 * 1024)));
  if (status === 413 || detail === "size_limit_exceeded") {
    return `Tệp vượt quá giới hạn dung lượng ${limitMb} MB hoặc bị máy chủ từ chối vì quá lớn.`;
  }
  if (status === 415 || detail === "not_a_pdf_missing_header") {
    return "Tệp không có phần mở đầu PDF (%PDF-).";
  }
  if (detail === "pdf_parse_failed") {
    return "Không đọc được cấu trúc PDF (tệp bị hỏng hoặc được bảo vệ bằng mật khẩu).";
  }
  if (status === 502 || status === 504) {
    return "Máy chủ phản hồi quá thời gian chờ khi xử lý tệp lớn. Vui lòng thử lại.";
  }
  return _formatApiErrorVi(status, detail);
}
export function _escTax(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export const _INDICATOR_VI = {
  unescape_decode: "Giải mã chuỗi %u (unescape)",
  from_char_code: "Ghép mã ký tự (String.fromCharCode)",
  heap_spray_pattern: "Chuỗi ký tự %uXXXX",
  long_hex_sequence: "Chuỗi byte thập lục phân dài (\\xNN)",
  util_printf_overflow: "Gọi util.printf()",
  eval_exec: "Chạy mã động (eval)",
  app_doc_payload: "Gọi API trình đọc (app/doc)",
  document_write_exec: "Ghi nội dung qua document.write()",
};

export function _confidenceVi(conf) {
  const upper = String(conf || "").toUpperCase();
  if (upper === "HIGH") return "Cao";
  if (upper === "MEDIUM") return "Trung bình";
  if (upper === "LOW") return "Thấp";
  return "--";
}

export function _cleanEvidenceTextVi(rawText) {
  const s = String(rawText || "");
  if (!s) return "";
  return s
    .replace(/➔/g, "→")
    .replace(/\(unescape_percent_decode\)/gi, "(giải mã %u / unescape)")
    .replace(/unescape_percent_decode/gi, "giải mã %u / unescape")
    .replace(/\(fromCharCode_decode\)/gi, "(ghép ký tự String.fromCharCode)")
    .replace(/fromCharCode_decode/gi, "ghép ký tự String.fromCharCode")
    .replace(/\(hex_escape_decode\)/gi, "(chuỗi thoát thập lục phân \\xNN)")
    .replace(/hex_escape_decode/gi, "chuỗi thoát thập lục phân \\xNN")
    .replace(/\(unicode_escape_decode\)/gi, "(chuỗi thoát Unicode \\uNNNN)")
    .replace(/unicode_escape_decode/gi, "chuỗi thoát Unicode \\uNNNN")
    .replace(/\(string_concat_fold\)/gi, "(nối chuỗi phân mảnh)")
    .replace(/string_concat_fold/gi, "nối chuỗi phân mảnh")
    .replace(/\beval_exec\b/gi, "gọi hàm eval()")
    .replace(/\bunescape_decode\b/gi, "gọi hàm unescape()")
    .replace(/\bfrom_char_code\b/gi, "gọi String.fromCharCode()")
    .replace(/\(obj_(\d+)\s+0\s+R\)/gi, "(Đối tượng PDF #$1)")
    .replace(/obj_(\d+)\s+0\s+R/gi, "Đối tượng PDF #$1")
    .replace(/\(action:open_action\)/gi, "(Khóa /OpenAction)")
    .replace(/action:open_action\/JS/gi, "Mã JavaScript tại /OpenAction → /JS")
    .replace(/script:action:open_action/gi, "Mã JavaScript trong /OpenAction")
    .replace(/\(action:aa\)/gi, "(Khóa /AA)")
    .replace(/action:aa\/JS/gi, "Mã JavaScript tại /AA → /JS")
    .replace(/script:action:aa/gi, "Mã JavaScript trong /AA")
    .replace(/script:names_js/gi, "Danh mục JavaScript (/Names/JavaScript)");
}

export function _formatReadableCodeSnippet(rawSnippet) {
  const s = String(rawSnippet || "").trim();
  if (!s) return "Chưa trích xuất được nội dung đoạn mã.";
  const lines = s.split(/\r?\n/);
  const formattedSections = lines
    .map((line) => {
      const cleanLine = line.trim();
      if (!cleanLine) return "";
      let header = "";
      let body = cleanLine;
      const deobMatch = cleanLine.match(/^\[DEOBFUSCATED\s*\(([^)]+)\)\]:\s*(.*)$/i);
      const rawMatch = cleanLine.match(/^\[RAW\]:\s*(.*)$/i);
      if (deobMatch) {
        header = `// Bản đã giải mã tự động (${_cleanEvidenceTextVi(deobMatch[1])}):`;
        body = deobMatch[2];
      } else if (rawMatch) {
        header = `// Mã gốc trong tệp PDF:`;
        body = rawMatch[1];
      }
      const prettyBody = body
        .replace(/;\s*/g, ";\n")
        .replace(/\{\s*/g, "{\n  ")
        .replace(/\s*\}\s*/g, "\n}\n")
        .split("\n")
        .map((l) => l.trimEnd())
        .filter(Boolean)
        .join("\n");
      return header ? `${header}\n${prettyBody}` : prettyBody;
    })
    .filter(Boolean);
  return formattedSections.join("\n\n");
}

export function _formatAttackPathStepVi(step, isMal = true) {
  const s = String(step || "").trim();
  if (!s) return "Thành phần PDF";
  if (s.includes("Catalog") || s.includes("/Trailer/Root") || s === "catalog:root")
    return "Khung gốc tài liệu (/Catalog)";
  if (s.includes("Pages") || s === "pages:root") return "Danh sách trang (/Pages)";
  if (s.startsWith("Page (")) {
    const m = s.match(/Kids\[(\d+)\]/i) || s.match(/\((\d+)\)/);
    return m ? `Trang tài liệu số ${Number(m[1]) + 1}` : "Trang tài liệu";
  }
  if (s.includes("action:open_action/JS") || s.includes("script:action:open_action"))
    return "Mã JavaScript tại /OpenAction → /JS";
  if (s.includes("action:aa/JS") || s.includes("script:action:aa")) return "Mã JavaScript tại /AA → /JS";
  if (s.includes("/Names/JavaScript") || s.includes("names_js")) return "Danh mục JavaScript (/Names/JavaScript)";
  if (s.includes("/OpenAction") || s.includes("open_action")) return "Hành động khi mở (/OpenAction)";
  if (s.includes("/Catalog/AA") || s.includes("Action (/AA)") || s === "action:aa")
    return isMal ? "Hành động tự động (/AA)" : "Thiết lập sự kiện (/AA)";
  if (s.includes("Annot") || s.includes("annot_")) return "Vùng tương tác / Liên kết trên trang";
  if (s.startsWith("Script (")) return _cleanEvidenceTextVi(s.replace("Script (", "Mã JavaScript ("));
  if (s.startsWith("Action (")) return _cleanEvidenceTextVi(s.replace("Action (", "Hành động ("));
  return _cleanEvidenceTextVi(s);
}
export function scanAssessment(data) {
  if (data.verdict === "MALICIOUS") {
    return {
      tone: "danger",
      title: "Có cảnh báo mã độc",
      guidance: "Đừng mở bản gốc. Nếu cần đọc tài liệu, hãy tạo bản đã làm sạch.",
    };
  }
  const lockedGap = Boolean(data.forensic_dossier?.encryption_analysis?.password_locked);
  if (lockedGap) {
    return {
      tone: "caution",
      title: "Tệp bị khóa mật khẩu — chưa kiểm tra được nội dung",
      guidance:
        "Tệp PDF được đặt mật khẩu nên chưa thể phân tích cấu trúc hay JavaScript bên trong. Đừng mở nếu chưa xác minh, hoặc nhập mật khẩu để quét sâu.",
    };
  }
  const heads =
    data.threat_taxonomy?.ml_label_predictions ?? data.forensic_dossier?.threat_taxonomy?.ml_label_predictions;
  if (heads?.some((head) => head.evidence_status === "observed")) {
    return {
      tone: "caution",
      title: "Có dấu hiệu đáng ngờ",
      guidance: "Tránh mở bản gốc. Nếu cần đọc tài liệu, hãy tạo bản đã làm sạch.",
    };
  }
  const detectedCount =
    data.threat_taxonomy?.detected_count ?? data.forensic_dossier?.threat_taxonomy?.detected_count ?? 0;
  const hasThreatScripts = Boolean(data.forensic_dossier?.threat_scripts?.length);
  const staticCheckClear =
    heads?.length &&
    detectedCount === 0 &&
    !hasThreatScripts &&
    heads.every((head) => head.evidence_status === "not_observed");
  if (!data.prediction_available || data.verdict !== "BENIGN" || data.is_ood !== false || !staticCheckClear) {
    return {
      tone: "caution",
      title: "Chưa đủ căn cứ để kết luận",
      guidance: "Tạm thời đừng mở bản gốc. Hãy kiểm tra lại hoặc xin một bản khác từ người gửi.",
    };
  }
  if (data.cdr_provenance?.verified_sanitized === true) {
    return {
      tone: "clear",
      title: "Bản PDF đã làm sạch — Chưa thấy dấu hiệu nguy hiểm",
      guidance: "Tệp khớp mã băm SHA-256 của bản đã làm sạch trong phiên này; không ghi nhận khóa kích hoạt thực thi.",
    };
  }
  return {
    tone: "clear",
    title: "Chưa thấy dấu hiệu nguy hiểm",
    guidance: "Chỉ mở nếu bạn tin nguồn gửi.",
  };
}
export async function consumeCloudStream(response, onDelta, onReady) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("cloud_ai_invalid_response");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let pending = "";
  let fullReply = "";
  let completed = false;
  try {
    while (!completed) {
      const { value, done } = await reader.read();
      pending = (pending + decoder.decode(value, { stream: !done })).replace(/\r\n/g, "\n");
      for (let boundary = pending.indexOf("\n\n"); boundary !== -1; boundary = pending.indexOf("\n\n")) {
        const frame = pending.slice(0, boundary);
        pending = pending.slice(boundary + 2);
        const event = frame.match(/^event: ?(.*)$/m)?.[1]?.trim();
        const fields = frame.split("\n").filter((line) => line.startsWith("data:"));
        if (!fields.length) continue;
        const data = JSON.parse(fields.map((line) => line.slice(5).replace(/^ /, "")).join("\n"));
        if (!data || typeof data !== "object") throw new Error("cloud_ai_invalid_response");
        if (event === "error") throw new Error(String(data.detail || "cloud_ai_provider_error"));
        if (event === "ready" && data.mode === "cloud") onReady?.();
        if (event === "delta") {
          if (typeof data.text !== "string" || fullReply.length + data.text.length > 16000) {
            throw new Error("cloud_ai_invalid_response");
          }
          fullReply += data.text;
          if (fullReply.trim()) onDelta(fullReply);
        } else if (event === "done") {
          if (data.mode !== "cloud" || !fullReply.trim()) throw new Error("cloud_ai_invalid_response");
          completed = true;
          break;
        }
      }
      if (pending.length > 65536) throw new Error("cloud_ai_invalid_response");
      if (done && !completed) throw new Error("cloud_ai_stream_interrupted");
    }
    return fullReply.trim();
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function renderEMLInspectionResult(data) {
  if (!data) return;
  const held = (data.unavailable_attachments || 0) > 0 || data.action_taken === "HELD_FOR_REVIEW";
  const threatText = held
    ? "Có tệp đính kèm chưa xác minh — cần kiểm tra thêm"
    : data.malicious_attachments > 0
      ? `Đã làm sạch ${data.malicious_attachments} tệp PDF vượt ngưỡng`
      : "Không có tệp PDF vượt ngưỡng";
  const badgeLabel = held
    ? "Cần kiểm tra thêm"
    : data.malicious_attachments > 0
      ? "Đã làm sạch tệp đính kèm"
      : "Không vượt ngưỡng";
  const badgeCls = held
    ? "px-2.5 py-0.5 rounded-md text-xs font-bold bg-amber-100 text-amber-800"
    : data.malicious_attachments > 0
      ? "px-2.5 py-0.5 rounded-md text-xs font-bold bg-red-50 text-error border border-red-200"
      : "px-2.5 py-0.5 rounded-md text-xs font-bold bg-emerald-50 text-tertiary border border-emerald-200";

  const tabCard = document.getElementById("mail-tab-result-card");
  if (tabCard) {
    tabCard.classList.remove("hidden");
    document.getElementById("mail-tab-res-subject").textContent = data.subject || "--";
    document.getElementById("mail-tab-res-sender").textContent = data.sender || "--";
    document.getElementById("mail-tab-res-attachments").textContent = `${data.total_attachments || 0} tệp đính kèm`;
    const threatsEl = document.getElementById("mail-tab-res-threats");
    if (threatsEl) {
      threatsEl.textContent = threatText;
      threatsEl.className = held
        ? "text-xs font-bold text-amber-800"
        : data.malicious_attachments > 0
          ? "text-xs font-bold text-error"
          : "text-xs font-bold text-tertiary";
    }
    const tabBadge = document.getElementById("mail-tab-action-badge");
    if (tabBadge) {
      tabBadge.textContent = badgeLabel;
      tabBadge.className = badgeCls;
    }
    const tabDlBtn = document.getElementById("btn-mail-tab-download-eml");
    if (tabDlBtn) {
      tabDlBtn.classList.toggle("hidden", held || !data.eml_job_id);
      if (held || !data.eml_job_id) tabDlBtn.removeAttribute("href");
      else tabDlBtn.href = `/api/gateway/download/eml/${encodeURIComponent(data.eml_job_id)}`;
    }
  }
}
