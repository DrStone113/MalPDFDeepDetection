import {
  appState,
  consumeCloudStream,
  dom,
  loadOptionalScript,
  scanAssessment,
  setIcon,
  showToast,
  updateTabs,
} from "./dashboard-core.js";
export const CLIENT_LLM_SYSTEM_PROMPT =
  "Bạn là trợ lý giải thích báo cáo kiểm tra PDF của hệ thống MalPDF DeepDetection. " +
  "Trả lời trực tiếp, ngắn gọn bằng tiếng Việt, chỉ dựa trên dữ liệu phân tích đã cung cấp; " +
  "không suy đoán vượt quá bằng chứng và không tự ý kết luận tệp hoàn toàn an toàn.";

export const clientAIState = {
  checked: false,
  hardwareSupported: false,
  hardwareReason: "",
  detectedRamGb: null,
  adapterInfo: null,
  selectedModel: "cnb/minimax-m3.1-flash",
  loadedModel: null,
  engine: null,
  engineReady: false,
  isInitializing: false,
  preferNewModel: true,
  lastFallbackReason: "",
};

export async function checkSystemRequirements() {
  if (!navigator.gpu) {
    clientAIState.hardwareReason = "Trình duyệt hiện tại chưa bật hoặc không hỗ trợ WebGPU.";
    return false;
  }
  const rawRam = navigator.deviceMemory;
  clientAIState.detectedRamGb = rawRam || null;
  if (typeof rawRam === "number" && rawRam < 4) {
    clientAIState.hardwareReason = `RAM thiết bị báo cáo (${rawRam} GB) chưa đủ để nạp mô hình trên máy.`;
    return false;
  }
  try {
    const adapter =
      (await navigator.gpu.requestAdapter({ powerPreference: "high-performance" })) ||
      (await navigator.gpu.requestAdapter());
    if (!adapter) {
      clientAIState.hardwareReason = "Không tìm thấy GPU tương thích WebGPU trên trình duyệt.";
      return false;
    }
    const maxBinding = adapter.limits?.maxStorageBufferBindingSize || 0;
    if (maxBinding > 0 && maxBinding < 128 * 1024 * 1024) {
      clientAIState.hardwareReason = `Bộ nhớ đệm GPU tối đa (${Math.round(maxBinding / (1024 * 1024))} MB) chưa đủ để nạp mô hình trên máy.`;
      return false;
    }
    clientAIState.adapterInfo = adapter.info || null;
    const gpuDesc =
      (adapter.info && (adapter.info.description || adapter.info.vendor || adapter.info.architecture)) ||
      "WebGPU Adapter";
    clientAIState.hardwareReason = `Đạt chuẩn WebGPU (${gpuDesc})`;
    return true;
  } catch (_e) {
    clientAIState.hardwareReason = "Không thể khởi tạo kết nối phần cứng WebGPU trên trình duyệt.";
    return false;
  }
}

export async function evaluateClientAIHardware() {
  const badge = document.getElementById("ai-engine-mode-badge");
  const fallbackBanner = document.getElementById("ai-hardware-fallback-banner");
  const fallbackTitle = document.getElementById("ai-hardware-fallback-title");
  const fallbackReason = document.getElementById("ai-hardware-fallback-reason");
  const selectEl = document.getElementById("webllm-model-select");
  const initBtn = document.getElementById("btn-init-webllm");
  const initText = document.getElementById("btn-init-webllm-text");
  const initIcon = document.getElementById("btn-init-webllm-icon");

  if (selectEl) selectEl.disabled = false;

  if (clientAIState.selectedModel === "cnb/minimax-m3.1-flash") {
    if (badge) {
      badge.textContent = "Cloud AI";
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 text-tertiary border border-emerald-200";
    }
    if (initIcon) {
      setIcon(initIcon, "cloud_done");
      initIcon.classList.remove("animate-spin");
    }
    if (initText) initText.textContent = "Cloud AI";
    if (initBtn) {
      initBtn.disabled = true;
      initBtn.className =
        "px-3 py-1 rounded-md text-[11px] font-bold bg-tertiary text-white shadow-xs transition hidden items-center gap-1 shrink-0";
    }
    if (fallbackBanner) fallbackBanner.classList.add("hidden");
    return true;
  }

  if (clientAIState.selectedModel === "deterministic-server") {
    if (badge) {
      badge.textContent = "Chế độ máy chủ";
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-blue-50 text-primary-container border border-blue-200";
    }
    if (initIcon) {
      setIcon(initIcon, "verified_user");
      initIcon.classList.remove("animate-spin");
    }
    if (initText) initText.textContent = "Sẵn sàng";
    if (initBtn) {
      initBtn.disabled = true;
      initBtn.className =
        "px-3 py-1 rounded-md text-[11px] font-bold bg-primary-container text-white shadow-xs transition hidden items-center gap-1 shrink-0";
    }
    if (fallbackBanner) fallbackBanner.classList.add("hidden");
    return true;
  }

  const supported = await checkSystemRequirements();
  clientAIState.checked = true;
  clientAIState.hardwareSupported = supported;

  if (!supported) {
    clientAIState.engineReady = false;
    clientAIState.lastFallbackReason = clientAIState.hardwareReason;
    if (badge) {
      badge.textContent = "Chế độ máy chủ";
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200";
    }
    if (fallbackBanner) fallbackBanner.classList.remove("hidden");
    if (fallbackTitle) fallbackTitle.textContent = "Trình duyệt chưa hỗ trợ WebGPU — Đã chuyển sang chế độ máy chủ";
    if (fallbackReason)
      fallbackReason.textContent = `Chạy AI trên trình duyệt cần WebGPU và tối thiểu 4 GB RAM (${clientAIState.hardwareReason}). Bạn vẫn có thể chọn Cloud AI hoặc dùng báo cáo trực tiếp từ máy chủ.`;
    if (initBtn) {
      initBtn.disabled = true;
      initBtn.className =
        "px-3 py-1 rounded-md text-[11px] font-bold bg-slate-200 text-outline cursor-not-allowed flex items-center gap-1 shrink-0";
    }
    if (initIcon) {
      setIcon(initIcon, "lock");
      initIcon.classList.remove("animate-spin");
    }
    if (initText) initText.textContent = "WebGPU chưa sẵn sàng";
    return false;
  }

  if (fallbackBanner && !clientAIState.lastFallbackReason) fallbackBanner.classList.add("hidden");
  if (initBtn) {
    initBtn.disabled = clientAIState.isInitializing;
    initBtn.className = clientAIState.engineReady
      ? "px-3 py-1 rounded-md text-[11px] font-bold bg-tertiary text-white shadow-xs transition flex items-center gap-1 active:scale-95 shrink-0"
      : "px-3 py-1 rounded-md text-[11px] font-bold bg-primary-container hover:bg-primary text-white shadow-xs transition flex items-center gap-1 active:scale-95 shrink-0";
  }
  const shortName = clientAIState.selectedModel?.includes("Llama") ? "Llama-3.2-1B" : "Qwen2.5-1.5B";
  if (clientAIState.engineReady) {
    if (badge) {
      badge.textContent = `Local AI (${shortName})`;
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 text-tertiary border border-emerald-200";
    }
    if (initIcon) {
      setIcon(initIcon, "verified");
      initIcon.classList.remove("animate-spin");
    }
    if (initText) initText.textContent = `Local AI (${shortName})`;
  } else if (clientAIState.isInitializing) {
    if (badge) {
      badge.textContent = `Đang nạp Local AI (${shortName})...`;
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-blue-50 text-primary-container border border-blue-200";
    }
    if (initIcon) {
      setIcon(initIcon, "progress_activity");
      initIcon.classList.add("animate-spin");
    }
    if (initText) initText.textContent = "Đang nạp...";
  } else {
    if (badge) {
      badge.textContent = `Local AI (${shortName}) sẵn sàng nạp`;
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-blue-50 text-primary-container border border-blue-200";
    }
    if (initIcon) {
      setIcon(initIcon, "bolt");
      initIcon.classList.remove("animate-spin");
    }
    if (initText) initText.textContent = "Nạp Local AI";
    if (clientAIState.preferNewModel && !clientAIState.isInitializing && !clientAIState.engineReady) {
      setTimeout(() => {
        if (!clientAIState.engineReady && !clientAIState.isInitializing && clientAIState.hardwareSupported) {
          initWebLLMEngine(true);
        }
      }, 350);
    }
  }
  return true;
}

export function handleWebLLMModelChange(modelId) {
  clientAIState.selectedModel = modelId;
  if (modelId.includes("MLC")) {
    if (clientAIState.loadedModel && clientAIState.loadedModel !== modelId) clientAIState.engineReady = false;
    evaluateClientAIHardware();
    if (clientAIState.hardwareSupported && !clientAIState.engineReady && !clientAIState.isInitializing)
      initWebLLMEngine(false);
  } else {
    evaluateClientAIHardware();
  }
}

export function buildCompactScanContextJSON(scanResult, cdrAudit) {
  const aiExp = scanResult?.ai_threat_explanation || {};
  if (aiExp.llm_compact_context) return JSON.stringify(aiExp.llm_compact_context);
  if (!scanResult)
    return JSON.stringify({ status: "NoScan", threat_type: "None", details: "No PDF document scanned yet." });
  const verdict = scanResult.verdict || "UNAVAILABLE";
  const prob = Number.isFinite(scanResult.malware_probability)
    ? Number((scanResult.malware_probability * 100).toFixed(2))
    : null;
  const dossier = scanResult.forensic_dossier || {};
  const taxonomy = scanResult.threat_taxonomy || dossier.threat_taxonomy || {};
  const triggers = (dossier.trigger_objects || [])
    .filter((t) => t.is_threat_trigger)
    .slice(0, 5)
    .map((t) => `${t.invoker || "/Unknown"} (${t.obj_ref_str || t.object_id || ""})`);
  const scripts = (dossier.threat_scripts || []).slice(0, 3).map((s) => ({
    script_id: s.script_id || "script",
    indicators: (s.dangerous_indicators || []).slice(0, 5),
    snippet_preview: String(s.deobfuscated_code || s.raw_code_snippet || s.snippet || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 120),
  }));
  const detailsList = [];
  scripts.forEach((s) => {
    if (s.indicators.length > 0) detailsList.push(`Found suspicious ${s.indicators.join(", ")} inside ${s.script_id}`);
  });
  if (triggers.length > 0) detailsList.push(`Triggers: ${triggers.join(", ")}`);
  return JSON.stringify({
    status: verdict === "MALICIOUS" ? "Malicious" : verdict === "BENIGN" ? "Benign" : "Unavailable",
    verdict,
    malware_probability_pct: prob,
    threat_type: scripts.length > 0 ? "Embedded Javascript" : taxonomy.threat_label || "PDF Structure",
    threat_label: taxonomy.threat_label || "Generic",
    threat_title_vi: taxonomy.threat_title_vi || "",
    details: detailsList.join("; ").slice(0, 360) || "Standard PDF structural inspection.",
    file_name: scanResult.file_name || "document.pdf",
    pages_count: scanResult.pages_count || 1,
    file_size_kb: Number(((scanResult.file_size_bytes || 0) / 1024).toFixed(2)),
    attack_path: (dossier.attack_path_string || "").slice(0, 180),
    triggers,
    scripts,
    cdr_sanitization: cdrAudit?.is_sanitized
      ? {
          is_sanitized: true,
          removed_triggers: (cdrAudit.removed_triggers || []).slice(0, 6),
          pages_preserved: `${cdrAudit.sanitized_pages}/${cdrAudit.original_pages}`,
        }
      : null,
  });
}

export async function initWebLLMEngine(autoTriggered = false) {
  if (!String(clientAIState.selectedModel || "").includes("MLC")) return false;
  const supported = await evaluateClientAIHardware();
  if (!supported) return false;
  if (clientAIState.engineReady && clientAIState.engine && clientAIState.loadedModel === clientAIState.selectedModel)
    return true;
  if (clientAIState.isInitializing) return false;

  clientAIState.isInitializing = true;
  const progressBox = document.getElementById("webllm-progress-box");
  const progressBar = document.getElementById("webllm-progress-bar");
  const progressPct = document.getElementById("webllm-progress-pct");
  const progressText = document.getElementById("webllm-progress-text");
  const initBtn = document.getElementById("btn-init-webllm");
  const initText = document.getElementById("btn-init-webllm-text");
  const initIcon = document.getElementById("btn-init-webllm-icon");
  const fallbackBanner = document.getElementById("ai-hardware-fallback-banner");
  const fallbackTitle = document.getElementById("ai-hardware-fallback-title");
  const fallbackReason = document.getElementById("ai-hardware-fallback-reason");

  if (progressBox) progressBox.classList.remove("hidden");
  if (initBtn) initBtn.disabled = true;
  if (initIcon) {
    setIcon(initIcon, "progress_activity");
    initIcon.classList.add("animate-spin");
  }
  if (initText) initText.textContent = "Đang nạp mô hình...";

  try {
    const webllm = await import("https://esm.run/@mlc-ai/web-llm@0.2.89");
    const targetModel = clientAIState.selectedModel || "Qwen2.5-1.5B-Instruct-q4f16_1-MLC";
    const shortLabel = targetModel.includes("Llama") ? "Llama-3.2-1B" : "Qwen2.5-1.5B";
    const engine = await webllm.CreateMLCEngine(targetModel, {
      initProgressCallback: (report) => {
        const pct = Math.min(100, Math.max(0, Math.round((report.progress || 0) * 100)));
        if (progressBar) progressBar.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct}%`;
        if (progressText) progressText.textContent = report.text || `Đang tải ${shortLabel} vào bộ nhớ...`;
      },
    });
    clientAIState.engine = engine;
    clientAIState.loadedModel = targetModel;
    clientAIState.engineReady = true;
    clientAIState.lastFallbackReason = "";
    if (progressBar) progressBar.style.width = "100%";
    if (progressPct) progressPct.textContent = "100%";
    if (progressText) progressText.textContent = `Đã nạp ${shortLabel} vào bộ nhớ.`;
    if (fallbackBanner) fallbackBanner.classList.add("hidden");
    if (!autoTriggered) showToast(`Đã nạp mô hình ${shortLabel} sẵn sàng.`, "success");
    return true;
  } catch (err) {
    clientAIState.engineReady = false;
    clientAIState.engine = null;
    clientAIState.lastFallbackReason = err?.message ? err.message : "Không thể tải trọng số mô hình";
    if (fallbackBanner) fallbackBanner.classList.remove("hidden");
    if (fallbackTitle)
      fallbackTitle.textContent = "Không thể khởi tạo mô hình trên trình duyệt — Đã chuyển sang chế độ máy chủ";
    if (fallbackReason)
      fallbackReason.textContent = `Không thể nạp mô hình (${clientAIState.lastFallbackReason}). Hệ thống trả lời trực tiếp từ kết quả quét trên máy chủ.`;
    const badge = document.getElementById("ai-engine-mode-badge");
    if (badge) {
      badge.textContent = "Chế độ máy chủ";
      badge.className =
        "px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200";
    }
    return false;
  } finally {
    clientAIState.isInitializing = false;
    if (initIcon) initIcon.classList.remove("animate-spin");
    await evaluateClientAIHardware();
  }
}

export function switchAITab(tab) {
  const btnExplain = document.getElementById("ai-tab-explain");
  const btnChat = document.getElementById("ai-tab-chat");
  updateTabs(document.getElementById("ai-tablist"), tab);
  const activeClass =
    "px-3 py-1 rounded-md bg-white text-primary-container shadow-xs border border-slate-200 transition flex items-center gap-1";
  const inactiveClass =
    "px-3 py-1 rounded-md text-on-surface-variant hover:text-on-surface transition flex items-center gap-1";
  if (btnExplain) btnExplain.className = tab === "explain" ? activeClass : inactiveClass;
  if (btnChat) btnChat.className = tab === "chat" ? activeClass : inactiveClass;
  if (tab === "chat") {
    evaluateClientAIHardware();
    if (
      String(clientAIState.selectedModel || "").includes("MLC") &&
      clientAIState.hardwareSupported &&
      !clientAIState.engineReady &&
      !clientAIState.isInitializing &&
      clientAIState.preferNewModel
    ) {
      initWebLLMEngine(true);
    }
  }
}

export function renderAIExplainer(aiData, isMal, fullScanResult) {
  function getObjText(item, preferField = "explanation") {
    if (!item) return "";
    if (typeof item === "string") return item;
    if (typeof item === "object")
      return (
        item[preferField] ||
        item.detail ||
        item.explanation ||
        item.meaning ||
        item.title ||
        Object.values(item).join(" - ")
      );
    return String(item);
  }
  if (!aiData) return;
  const summaryEl = document.getElementById("ai-executive-summary");
  if (summaryEl) summaryEl.textContent = aiData.executive_summary || "";

  const dAnalysis = aiData.danger_analysis || [];
  const t0 = document.getElementById("ai-card-title-0");
  const t1 = document.getElementById("ai-card-title-1");
  const t2 = document.getElementById("ai-card-title-2");
  if (t0 && dAnalysis[0]?.title) t0.textContent = dAnalysis[0].title;
  if (t1 && dAnalysis[1]?.title) t1.textContent = dAnalysis[1].title;
  if (t2 && dAnalysis[2]?.title) t2.textContent = dAnalysis[2].title;

  const impactEl = document.getElementById("ai-card-impact");
  const vectorEl = document.getElementById("ai-card-vector");
  const evasionEl = document.getElementById("ai-card-evasion");
  if (impactEl) impactEl.textContent = getObjText(dAnalysis[0], "explanation") || "Chưa có dữ liệu.";
  if (vectorEl) vectorEl.textContent = getObjText(dAnalysis[1], "explanation") || "Chưa có dữ liệu.";
  if (evasionEl) evasionEl.textContent = getObjText(dAnalysis[2], "explanation") || "Chưa có dữ liệu.";

  const listEl = document.getElementById("ai-technical-list");
  if (listEl) {
    const techItems = aiData.technical_breakdown || [];
    const items = techItems.length ? techItems : ["Chưa ghi nhận dấu hiệu kích hoạt hay mã kịch bản đáng ngờ."];
    listEl.replaceChildren(
      ...items.map((item) => {
        let detail = dom("span", {}, item == null ? "" : String(item));
        if (item && typeof item === "object") {
          const title = item.vector || item.title || item.kind || "Mục kiểm tra";
          const meaning = item.meaning || item.explanation || item.detail;
          detail = meaning ? dom("span", {}, dom("strong", {}, title + ":"), " " + meaning) : dom("span", {}, title);
        }
        return dom(
          "li",
          { class: "flex items-start gap-1 leading-relaxed" },
          dom(
            "span",
            { class: `${techItems.length && isMal ? "text-error" : "text-tertiary"} font-bold shrink-0` },
            "•",
          ),
          detail,
        );
      }),
    );
  }

  const remEl = document.getElementById("ai-remediation-text");
  if (remEl) remEl.textContent = aiData.remediation || "";

  const chatBox = document.getElementById("ai-chat-messages");
  const chatScanId = fullScanResult?.scan_id || "";
  if (chatBox && chatBox.dataset.scanId !== chatScanId) {
    chatBox.dataset.scanId = chatScanId;
    const fileName = fullScanResult?.file_name || "PDF";
    chatBox.replaceChildren(
      chatReply(
        dom(
          "div",
          { class: "chat-prose" },
          dom("p", {}, "Đã kiểm tra xong tệp ", dom("strong", {}, fileName), "."),
          dom("p", {}, dom("strong", {}, scanAssessment(fullScanResult).title), "."),
          dom("p", {}, "Bạn có thể chọn câu hỏi gợi ý bên trên hoặc đặt câu hỏi về cấu trúc và nội dung tệp này."),
        ),
      ),
    );
  }
}

export function askAIPreset(question) {
  const input = document.getElementById("ai-chat-input");
  if (input) input.value = question;
  sendAIChatMessage();
}

function _buildGroundedWebLLMPrompt(question, groundedReport) {
  const compactCtx = buildCompactScanContextJSON(appState.currentScanResult, appState.currentCDRAudit);
  return [
    "Dữ liệu kết quả quét PDF (JSON):",
    compactCtx,
    "",
    "Tóm tắt đã kiểm chứng từ máy chủ:",
    String(groundedReport || "").slice(0, 1400),
    "",
    `Câu hỏi của người dùng: ${String(question || "").trim()}`,
    "Hãy trả lời ngắn gọn, trung thực bằng tiếng Việt dựa trên dữ liệu trên.",
  ].join("\n");
}

export function _isIdentityOrGreetingQuery(question) {
  const q = String(question || "")
    .toLowerCase()
    .trim();
  const phrasePatterns = [
    "model gi",
    "model gì",
    "mo hinh gi",
    "mô hình gì",
    "ban la ai",
    "bạn là ai",
    "ban la gi",
    "bạn là gì",
    "ten gi",
    "tên gì",
    "ai day",
    "ai đấy",
    "qwen",
    "llama",
    "webllm",
    "xin chao",
    "xin chào",
    "chao ban",
    "chào bạn",
  ];
  if (phrasePatterns.some((p) => q === p || q.includes(p))) return true;
  return /\b(hello|hi|hey|alo)\b/.test(q);
}

export function _isRefusalOrBrokenLLMReply(replyText) {
  const t = String(replyText || "")
    .toLowerCase()
    .trim();
  if (!t || t.length < 6) return true;
  const refusalMarkers = [
    "không thể cung cấp thông tin",
    "không thể giải thích mã độc",
    "vì nó có thể gây hại",
    'bản chất của "ban"',
    "bản chất của 'ban'",
    "không đủ dữ liệu để trả lời",
    "hãy liên hệ với chuyên gia bảo mật",
    "tôi không thể hỗ trợ",
    "tôi không thể đáp ứng",
    "i cannot provide",
    "i cannot assist",
    "as an ai",
  ];
  return refusalMarkers.some((m) => t.includes(m));
}

const ALLOWED_MD_ELEMENTS = [
  "p",
  "br",
  "strong",
  "em",
  "del",
  "code",
  "pre",
  "blockquote",
  "ul",
  "ol",
  "li",
  "h1",
  "h2",
  "h3",
  "h4",
  "hr",
  "table",
  "thead",
  "tbody",
  "tr",
  "th",
  "td",
  "a",
];

export function renderAIChatMarkdown(rawText) {
  return window.marked?.parse(String(rawText ?? "").trim(), { gfm: true, breaks: true });
}

export async function safeSetMarkdownHTML(el, rawText) {
  const plainText = () => {
    el.replaceChildren(
      ...String(rawText ?? "")
        .trim()
        .split(/\r?\n\s*\r?\n/)
        .map((paragraph) => dom("p", { class: "whitespace-pre-wrap" }, paragraph)),
    );
  };
  try {
    const rawHtml = renderAIChatMarkdown(rawText);
    if (typeof rawHtml !== "string") {
      plainText();
      return;
    }
    if ("setHTML" in Element.prototype) {
      el.setHTML(rawHtml, { sanitizer: { elements: ALLOWED_MD_ELEMENTS, attributes: ["href", "class"] } });
    } else {
      await loadOptionalScript("/assets/purify-3.5.0.min.js");
      const clean = window.DOMPurify.sanitize(rawHtml, {
        ALLOWED_TAGS: [...ALLOWED_MD_ELEMENTS, "#text"],
        ALLOWED_ATTR: ["href", "class"],
        ALLOW_ARIA_ATTR: false,
        ALLOW_DATA_ATTR: false,
        KEEP_CONTENT: false,
        RETURN_TRUSTED_TYPE: true,
      });
      el.innerHTML = clean;
    }
    for (const node of el.querySelectorAll("[class]")) {
      if (node.localName !== "code" || !/^language-[\w+-]+$/.test(node.className)) node.removeAttribute("class");
    }
    for (const link of el.querySelectorAll("a[href]")) {
      const href = link.getAttribute("href").trim();
      if (!/^https?:\/\//i.test(href)) {
        link.removeAttribute("href");
        continue;
      }
      link.setAttribute("href", href);
      link.rel = "noopener noreferrer";
      link.target = "_blank";
    }
  } catch {
    plainText();
  }
}
let activeChatTurn = null;

export function cancelActiveChat() {
  if (!activeChatTurn) return;
  activeChatTurn.abort();
  activeChatTurn = null;
  document.getElementById("ai-chat-input").disabled = false;
  document.getElementById("ai-chat-send-btn").disabled = false;
}

export function createChatActivity() {
  const title = dom("span", { class: "chat-activity-title" }, "Đang xử lý yêu cầu");
  const count = dom("span", { class: "chat-activity-count" });
  const list = dom("ol", { class: "chat-activity-list" });
  const announcement = dom("span", { class: "visually-hidden", role: "status" });
  const details = dom(
    "details",
    { open: true },
    dom("summary", {}, title, count, dom("span", { class: "chat-activity-chevron", "aria-hidden": "true" })),
    list,
  );
  const element = dom("div", { class: "chat-activity" }, details, announcement);
  const rows = new Map();
  const announce = (text) => {
    if (title.textContent !== text) {
      title.textContent = text;
      announcement.textContent = text;
    }
  };
  return {
    element,
    step(key, label, detail, state) {
      let row = rows.get(key);
      if (!row) {
        row = dom(
          "li",
          { class: "chat-activity-item", dataset: { step: key } },
          dom("span", { class: "chat-activity-dot", "aria-hidden": "true" }),
          dom("div", {}, dom("strong"), dom("p")),
        );
        rows.set(key, row);
        list.appendChild(row);
      }
      if (row.dataset.state !== state) {
        row.dataset.state = state;
        if (state === "active") row.setAttribute("aria-current", "step");
        else row.removeAttribute("aria-current");
        const finished = [...rows.values()].filter((item) => item.dataset.state === "done").length;
        count.textContent = finished ? `${finished} bước hoàn tất` : "";
      }
      row.querySelector("strong").textContent = label;
      row.querySelector("p").textContent = detail;
      if (state === "active") announce(label);
    },
    finish(label, state) {
      element.dataset.state = state;
      announce(label);
      if (state === "done") details.open = false;
    },
  };
}

function chatReply(...content) {
  return dom(
    "div",
    { class: "flex items-start gap-2.5" },
    dom(
      "div",
      {
        class:
          "w-6 h-6 rounded-md bg-primary-container text-white flex items-center justify-center shrink-0 text-[10px] font-bold mt-0.5",
      },
      "AI",
    ),
    dom(
      "div",
      {
        class: "p-3 rounded-lg bg-white text-on-surface border border-slate-200 leading-relaxed text-xs flex-1 min-w-0",
      },
      content,
    ),
  );
}

export function wireAIChatEvents() {
  const form = document.getElementById("ai-chat-form");
  const input = document.getElementById("ai-chat-input");
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    sendAIChatMessage();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (event.isComposing || event.keyCode === 229) return;
      form.requestSubmit();
    }
  });
  document.getElementById("webllm-model-select").addEventListener("change", (event) => {
    handleWebLLMModelChange(event.target.value);
  });
  document.getElementById("btn-init-webllm").addEventListener("click", () => initWebLLMEngine(false));
  for (const button of document.querySelectorAll("[data-ai-preset]")) {
    button.addEventListener("click", () => askAIPreset(button.dataset.aiPreset));
  }
}

export async function sendAIChatMessage() {
  const input = document.getElementById("ai-chat-input");
  const button = document.getElementById("ai-chat-send-btn");
  const messages = document.getElementById("ai-chat-messages");
  const question = input?.value.trim();
  const scanId = appState.currentScanResult?.scan_id;
  const model = clientAIState.selectedModel;
  if (!question || !messages || activeChatTurn) return;
  if (!scanId) {
    showToast("Hãy quét tệp PDF trước khi gửi câu hỏi.", "info");
    return;
  }

  const turn = new AbortController();
  activeChatTurn = turn;
  button.disabled = input.disabled = true;
  input.value = "";
  const markdownReady = loadOptionalScript("/assets/marked-18.3.0.min.js").catch(() => null);
  const userWrap = document.createElement("div");
  userWrap.className = "flex justify-end";
  const userBubble = document.createElement("div");
  userBubble.className =
    "px-3.5 py-2 rounded-lg bg-primary-container text-white text-xs max-w-[85%] break-words font-medium";
  userBubble.textContent = question;
  userWrap.append(userBubble);
  const activity = createChatActivity();
  const answer = dom("div", { class: "chat-reply chat-prose hidden" });
  const reply = chatReply(activity.element, answer);
  messages.append(userWrap, reply);
  messages.scrollTop = messages.scrollHeight;

  let displayedText = "";
  let frame = 0;
  let pendingStep = "report";
  let pendingLabel = "Đang đọc kết quả quét";
  function stage(key, label, detail) {
    const follow = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 48;
    pendingStep = key;
    pendingLabel = label;
    activity.step(key, label, detail, "active");
    if (follow) messages.scrollTop = messages.scrollHeight;
  }
  function paintAnswer(streaming) {
    if (!reply.isConnected || turn.signal.aborted) return;
    const follow =
      messages.scrollHeight - messages.scrollTop - messages.clientHeight < 48 || answer.classList.contains("hidden");
    answer.classList.remove("hidden");
    answer.dataset.streamState = streaming ? "streaming" : "complete";
    answer.textContent = displayedText;
    if (follow) messages.scrollTop = messages.scrollHeight;
    if (!streaming)
      markdownReady.then(async () => {
        if (!answer.isConnected || turn.signal.aborted) return;
        const stillFollowing = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 48;
        await safeSetMarkdownHTML(answer, displayedText);
        if (stillFollowing && answer.isConnected) messages.scrollTop = messages.scrollHeight;
      });
  }
  function receiveText(text) {
    if (!text.trim() || turn.signal.aborted) return;
    displayedText = text;
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      stage("output", "Đang nhận câu trả lời", `Đã nhận ${displayedText.length.toLocaleString("vi-VN")} ký tự.`);
      paintAnswer(true);
    });
  }
  function finishAnswer(text, label) {
    if (turn.signal.aborted) return;
    if (frame) cancelAnimationFrame(frame);
    frame = 0;
    displayedText = text;
    paintAnswer(false);
    activity.step("output", "Đã hiển thị câu trả lời", `${text.length.toLocaleString("vi-VN")} ký tự.`, "done");
    activity.finish(label, "done");
  }
  function postChat(payload) {
    return fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, question, ...payload }),
      signal: turn.signal,
    });
  }

  try {
    stage("report", "Đang đọc kết quả quét", "Lấy dữ liệu của tệp đang mở.");
    const response = await postChat();
    if (!response.ok)
      throw new Error(
        response.status === 404
          ? "Lượt quét đã hết hạn. Hãy quét lại tệp rồi gửi lại câu hỏi."
          : "Không tải được kết quả quét. Hãy thử lại.",
      );
    const report = await response.json();
    const grounded = typeof report.answer === "string" ? report.answer.trim() : "";
    if (report.scan_id !== scanId || !grounded) throw new Error("Chưa nhận được kết quả quét hợp lệ để trả lời.");
    const evidence = report.llm_compact_context || {};
    const pages = Number.isFinite(evidence.pages_count) ? ` • ${evidence.pages_count} trang` : "";
    activity.step("report", "Đã mở kết quả quét", `${report.file_name || "PDF"}${pages}`, "done");
    if (Array.isArray(evidence.triggers) && Array.isArray(evidence.scripts)) {
      const triggerRefs = evidence.triggers.map((value) => String(value)).join(", ");
      activity.step(
        "evidence",
        "Đã tập hợp bằng chứng",
        `${evidence.triggers.length} vị trí kích hoạt, ${evidence.scripts.length} đoạn mã trong bản tóm tắt${triggerRefs ? ": " + triggerRefs : "."}`,
        "done",
      );
    }
    if (evidence.cdr_sanitization?.is_sanitized) {
      activity.step(
        "cdr",
        "Đã đọc báo cáo làm sạch",
        `Số trang được giữ: ${evidence.cdr_sanitization.pages_preserved || "chưa có số liệu"}.`,
        "done",
      );
    }

    let fallbackReason = "Hệ thống dùng câu trả lời từ kết quả quét.";
    if (model === "cnb/minimax-m3.1-flash") {
      stage("cloud", "Đang gửi yêu cầu đến Cloud AI", "Gửi câu hỏi và dữ liệu quét tóm tắt qua máy chủ.");
      try {
        const cloud = await postChat({ mode: "cloud", stream: true });
        if (!cloud.ok) {
          const body = await cloud.json().catch(() => null);
          throw new Error(body?.detail || "cloud_ai_unavailable");
        }
        if (!cloud.headers.get("content-type")?.includes("text/event-stream")) {
          throw new Error("cloud_ai_unavailable");
        }
        const full = await consumeCloudStream(
          cloud,
          (text) => {
            if (!displayedText.trim())
              activity.step("cloud", "Cloud AI đã bắt đầu trả lời", "Đã nhận phần nội dung đầu tiên.", "done");
            receiveText(text);
          },
          () => stage("cloud", "Đã kết nối Cloud AI", "Đang chờ phần nội dung đầu tiên."),
        );
        finishAnswer(full, "Đã trả lời bằng Cloud AI");
        return;
      } catch (err) {
        if (turn.signal.aborted) return;
        const cloudStatus = {
          cloud_ai_timeout: "Cloud AI phản hồi quá lâu.",
          cloud_ai_output_limit: "Cloud AI đã tới giới hạn độ dài.",
          cloud_ai_busy: "Cloud AI đang bận.",
          cloud_ai_request_limit: "Đã tới giới hạn lượt hỏi. Hãy đợi rồi thử lại.",
          cloud_ai_authentication_failed: "Máy chủ chưa xác thực được với Cloud AI.",
          cloud_ai_provider_error: "Nhà cung cấp Cloud AI đang gặp lỗi tạm thời.",
          cloud_ai_invalid_response: "Phản hồi từ Cloud AI không đúng định dạng.",
          cloud_ai_unavailable: "Cloud AI chưa khả dụng trên máy chủ này.",
          cloud_ai_stream_interrupted: "Luồng trả lời kết thúc trước khi Cloud AI báo hoàn tất.",
        };
        const reason = cloudStatus[err.message] || "Không nhận được phản hồi hoàn chỉnh từ Cloud AI.";
        if (displayedText.trim()) {
          cancelAnimationFrame(frame);
          frame = 0;
          paintAnswer(false);
          answer.dataset.streamState = "interrupted";
          activity.step(
            "output",
            "Kết nối trả lời bị ngắt",
            reason + " Giữ phần đã nhận. Bạn có thể gửi lại câu hỏi.",
            "error",
          );
          activity.finish("Câu trả lời bị ngắt", "error");
          return;
        }
        fallbackReason = reason;
        activity.step(
          "cloud",
          "Chưa nhận được câu trả lời từ Cloud AI",
          "Chuyển sang câu trả lời từ kết quả quét.",
          "error",
        );
      }
    } else if (model?.includes("MLC") && !_isIdentityOrGreetingQuery(question)) {
      stage("local_check", "Đang kiểm tra khả năng chạy trên máy", "Kiểm tra WebGPU và bộ nhớ.");
      if ((await evaluateClientAIHardware()) && clientAIState.preferNewModel) {
        if (turn.signal.aborted) return;
        activity.step("local_check", "Thiết bị hỗ trợ mô hình trên máy", "Đã kiểm tra WebGPU và bộ nhớ.", "done");
        if (!clientAIState.engineReady || !clientAIState.engine) {
          stage("local_load", "Đang nạp mô hình trên máy", model);
          await initWebLLMEngine(true);
          if (turn.signal.aborted) return;
          activity.step(
            "local_load",
            clientAIState.engineReady ? "Mô hình đã sẵn sàng" : "Chưa nạp được mô hình",
            model,
            clientAIState.engineReady ? "done" : "error",
          );
        }
        if (clientAIState.engineReady && clientAIState.engine) {
          stage("local", "Mô hình trên máy đang soạn câu trả lời", model);
          try {
            const chunks = await clientAIState.engine.chat.completions.create({
              messages: [
                { role: "system", content: CLIENT_LLM_SYSTEM_PROMPT },
                { role: "user", content: _buildGroundedWebLLMPrompt(question, grounded) },
              ],
              temperature: 0.15,
              max_tokens: 420,
              stream: true,
            });
            let text = "";
            for await (const chunk of chunks) {
              if (turn.signal.aborted) return;
              text += chunk.choices?.[0]?.delta?.content || "";
              if (text.length > 18 && _isRefusalOrBrokenLLMReply(text)) break;
              if (text.trim()) {
                activity.step("local", "Mô hình đã bắt đầu trả lời", model, "done");
                receiveText(text);
              }
            }
            if (text.trim() && !_isRefusalOrBrokenLLMReply(text)) {
              finishAnswer(text.trim(), "Đã trả lời trên máy");
              return;
            }
          } catch {}
          activity.step(
            "local",
            "Mô hình trên máy chưa hoàn thành",
            "Chuyển sang câu trả lời từ kết quả quét.",
            "error",
          );
        }
      } else {
        activity.step(
          "local_check",
          "Trình duyệt chưa sẵn sàng để chạy mô hình",
          "Dùng kết quả quét từ máy chủ.",
          "error",
        );
      }
      fallbackReason = "Mô hình trên máy chưa tạo được câu trả lời đầy đủ.";
    }
    activity.step("fallback", "Dùng câu trả lời từ kết quả quét", fallbackReason, "done");
    finishAnswer(grounded, "Đã trả lời từ kết quả quét");
  } catch (err) {
    if (turn.signal.aborted) return;
    activity.step(
      pendingStep,
      pendingLabel,
      err instanceof TypeError ? "Mất kết nối. Hãy gửi lại câu hỏi." : err.message,
      "error",
    );
    activity.finish("Chưa có câu trả lời", "error");
  } finally {
    if (frame) cancelAnimationFrame(frame);
    if (activeChatTurn === turn) {
      activeChatTurn = null;
      button.disabled = input.disabled = false;
      if (messages.isConnected && messages.offsetParent !== null && document.activeElement === document.body) {
        input.focus({ preventScroll: true });
      }
    }
  }
}
