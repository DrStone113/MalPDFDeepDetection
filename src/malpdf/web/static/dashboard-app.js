import { cancelActiveChat, renderAIExplainer, switchAITab, wireAIChatEvents } from "./dashboard-ai.js";
import {
  _cleanEvidenceTextVi,
  _confidenceVi,
  _formatApiErrorVi,
  _formatAttackPathStepVi,
  _formatReadableCodeSnippet,
  _formatScanErrorVi,
  _INDICATOR_VI,
  animateValue,
  appState,
  copyText,
  dom,
  formatBytesVi,
  icon as iconNode,
  initTrustedTypes,
  prefersReducedMotion,
  renderEMLInspectionResult,
  scanAssessment,
  setIcon,
  showToast,
  syncGraphPopover,
  updateTabs,
} from "./dashboard-core.js";

const colorSchemeMeta = document.querySelector('meta[name="color-scheme"]');
const systemDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");

function isDarkScheme() {
  return colorSchemeMeta.content === "dark" || (colorSchemeMeta.content !== "light" && systemDarkScheme.matches);
}

function updateThemeToggle() {
  document.documentElement.toggleAttribute("data-system-dark", systemDarkScheme.matches);
  const isDark = isDarkScheme();
  const label = isDark ? "Chuyển sang giao diện sáng" : "Chuyển sang giao diện tối";
  const button = document.getElementById("btn-theme-toggle");
  setIcon(document.getElementById("theme-toggle-icon"), isDark ? "light_mode" : "dark_mode");
  document.getElementById("theme-toggle-text").textContent = isDark ? "Sáng" : "Tối";
  button.setAttribute("aria-label", label);
  button.title = label;
}

function syncThemeMetaFromStorage() {
  let scheme = "light dark";
  try {
    const saved = localStorage.getItem("color-scheme");
    if (saved === "light" || saved === "dark") scheme = saved;
  } catch {
    // Storage can be unavailable in embedded or restricted browser sessions.
  }
  colorSchemeMeta.content = scheme;
  updateThemeToggle();
}

function toggleColorScheme() {
  const next = isDarkScheme() ? "light" : "dark";
  const matchesSystem = window.matchMedia(`(prefers-color-scheme: ${next})`).matches;
  colorSchemeMeta.content = matchesSystem ? "light dark" : next;
  updateThemeToggle();
  try {
    if (matchesSystem) localStorage.removeItem("color-scheme");
    else localStorage.setItem("color-scheme", next);
  } catch {
    // The theme still applies for the current page if storage is blocked.
  }
}

function initAmbientCyberCanvas() {
  const canvas = document.getElementById("ambient-cyber-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let rafId = 0;
  let w = window.innerWidth;
  let h = window.innerHeight;
  canvas.width = w;
  canvas.height = h;

  const nodes = [];
  const count = Math.min(46, Math.max(24, Math.floor((w * h) / 36000)));
  const colors = [{ rgb: "0, 113, 227" }, { rgb: "71, 85, 105" }, { rgb: "14, 165, 233" }];

  for (let i = 0; i < count; i++) {
    const col = colors[i % colors.length];
    nodes.push({
      rx: Math.random(),
      ry: Math.random(),
      vx: (Math.random() - 0.5) * 0.00018,
      vy: (Math.random() - 0.5) * 0.00018,
      radius: Math.random() * 2.2 + 1.6,
      rgb: col.rgb,
      baseAlpha: Math.random() * 0.22 + 0.16,
      phase: Math.random() * Math.PI * 2,
    });
  }

  function renderCyberNetwork(ts) {
    ctx.clearRect(0, 0, w, h);
    const timeSec = (ts || 0) * 0.001;
    const maxDist = 210;

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      n.rx += n.vx;
      n.ry += n.vy;
      if (n.rx < 0.02 || n.rx > 0.98) n.vx *= -1;
      if (n.ry < 0.02 || n.ry > 0.98) n.vy *= -1;

      const nx = n.rx * w;
      const ny = n.ry * h;
      const pulse = 0.85 + 0.15 * Math.sin(timeSec * 1.6 + n.phase);

      ctx.beginPath();
      ctx.arc(nx, ny, n.radius * 2.6, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${n.rgb}, ${n.baseAlpha * 0.18 * pulse})`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(nx, ny, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${n.rgb}, ${n.baseAlpha * pulse})`;
      ctx.fill();

      for (let j = i + 1; j < nodes.length; j++) {
        const m = nodes[j];
        const mx = m.rx * w;
        const my = m.ry * h;
        const d = Math.hypot(nx - mx, ny - my);
        if (d < maxDist) {
          const alpha = (1 - d / maxDist) * 0.14;
          ctx.beginPath();
          ctx.moveTo(nx, ny);
          ctx.lineTo(mx, my);
          ctx.strokeStyle = `rgba(100, 116, 139, ${alpha})`;
          ctx.lineWidth = 1.0;
          ctx.stroke();

          if ((i + j) % 5 === 0 && d < maxDist * 0.78) {
            const t = (((timeSec * 0.35 + i * 0.17) % 1) + 1) % 1;
            const px = nx + (mx - nx) * t;
            const py = ny + (my - ny) * t;
            ctx.beginPath();
            ctx.arc(px, py, 1.7, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 113, 227, ${alpha * 1.8})`;
            ctx.fill();
          }
        }
      }
    }
  }

  let resizeTimer = null;
  window.addEventListener(
    "resize",
    () => {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
        if (!document.hidden && reducedMotion.matches) renderCyberNetwork(0);
      }, 120);
    },
    { passive: true },
  );

  function renderFrame(ts) {
    rafId = 0;
    if (document.hidden || reducedMotion.matches) return;
    renderCyberNetwork(ts);
    rafId = requestAnimationFrame(renderFrame);
  }

  function syncAnimation() {
    if (document.hidden || reducedMotion.matches) {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = 0;
      if (!document.hidden) renderCyberNetwork(0);
    } else if (!rafId) {
      rafId = requestAnimationFrame(renderFrame);
    }
  }

  document.addEventListener("visibilitychange", syncAnimation);
  reducedMotion.addEventListener("change", syncAnimation);
  syncAnimation();
}

function setDiffViewMode(mode, persist = true) {
  if (mode !== "side" && mode !== "slider") return;
  appState.diffViewMode = mode;
  const sideBtn = document.getElementById("diff-mode-side");
  const sliderBtn = document.getElementById("diff-mode-slider");
  const sideView = document.getElementById("diff-side-by-side-view");
  const sliderView = document.getElementById("diff-split-slider-view");
  if (!sideBtn || !sliderBtn || !sideView || !sliderView) return;
  sideBtn.setAttribute("aria-pressed", String(mode === "side"));
  sliderBtn.setAttribute("aria-pressed", String(mode === "slider"));
  if (persist) {
    const url = new URL(location.href);
    if (mode === "slider") url.searchParams.set("diff", mode);
    else url.searchParams.delete("diff");
    history.replaceState(history.state, "", url);
  }

  if (mode === "side") {
    sideBtn.className =
      "px-3 py-1 rounded-md bg-primary-container text-white font-bold transition shadow-xs flex items-center gap-1 active:scale-95";
    sliderBtn.className =
      "px-3 py-1 rounded-md text-on-surface-variant hover:text-on-surface transition font-semibold flex items-center gap-1 active:scale-95";
    sideView.classList.remove("hidden");
    sliderView.classList.add("hidden");
  } else {
    sliderBtn.className =
      "px-3 py-1 rounded-md bg-primary-container text-white font-bold transition shadow-xs flex items-center gap-1 active:scale-95";
    sideBtn.className =
      "px-3 py-1 rounded-md text-on-surface-variant hover:text-on-surface transition font-semibold flex items-center gap-1 active:scale-95";
    sliderView.classList.remove("hidden");
    sideView.classList.add("hidden");
    updateSplitSliderPosition(appState.diffSplitPercent);
  }
}

function updateSplitSliderPosition(percent) {
  appState.diffSplitPercent = Math.max(2, Math.min(98, percent));
  const origImg = document.getElementById("diff-split-orig-img");
  const wrap = document.getElementById("diff-split-clean-wrap");
  const handle = document.getElementById("diff-split-handle");
  if (origImg) origImg.style.clipPath = `inset(0 ${100 - appState.diffSplitPercent}% 0 0)`;
  if (wrap) {
    wrap.style.width = "100%";
    wrap.style.clipPath = `inset(0 0 0 ${appState.diffSplitPercent}%)`;
  }
  if (handle) {
    handle.style.left = `${appState.diffSplitPercent}%`;
    handle.setAttribute("aria-valuenow", String(Math.round(appState.diffSplitPercent)));
  }
}

function initSplitSliderEvents() {
  const box = document.getElementById("diff-split-box");
  if (!box) return;
  const handle = document.getElementById("diff-split-handle");
  handle.addEventListener("keydown", (event) => {
    const positions = {
      ArrowLeft: appState.diffSplitPercent - 5,
      ArrowRight: appState.diffSplitPercent + 5,
      Home: 2,
      End: 98,
    };
    if (!Object.hasOwn(positions, event.key)) return;
    event.preventDefault();
    updateSplitSliderPosition(positions[event.key]);
  });
  let frame = 0;
  let latestX;
  const onMove = (clientX) => {
    latestX = clientX;
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      const rect = box.getBoundingClientRect();
      if (rect.width) updateSplitSliderPosition(((latestX - rect.left) / rect.width) * 100);
    });
  };
  box.addEventListener("pointerdown", (e) => {
    appState.isDraggingDiffSplit = true;
    if (box.setPointerCapture) {
      try {
        box.setPointerCapture(e.pointerId);
      } catch (_err) {}
    }
    onMove(e.clientX);
  });
  box.addEventListener("pointermove", (e) => {
    if (appState.isDraggingDiffSplit) onMove(e.clientX);
  });
  const stopDrag = (e) => {
    appState.isDraggingDiffSplit = false;
    if (e && e.pointerId !== undefined && box.releasePointerCapture) {
      try {
        box.releasePointerCapture(e.pointerId);
      } catch (_err) {}
    }
  };
  box.addEventListener("pointerup", stopDrag);
  box.addEventListener("pointercancel", stopDrag);
  window.addEventListener("mouseup", () => {
    appState.isDraggingDiffSplit = false;
  });
}

async function quickSwitchAndDisarm(event) {
  const scanId = appState.currentScanResult?.scan_id;
  if (!scanId) {
    showToast("Tải tệp PDF lên kiểm tra trước khi làm sạch.", "warning");
    return;
  }
  event?.currentTarget.focus({ preventScroll: true });
  await switchTab("cdr");
  if (appState.currentScanResult?.scan_id !== scanId) return;
  await executeLiveCDR();
}

async function handleFileList(fileList) {
  if (!fileList || fileList.length === 0) return;
  const files = Array.from(fileList);
  for (const f of files) {
    await handleFileSelect(f);
  }
  const inputEl = document.getElementById("file-input");
  if (inputEl) inputEl.value = "";
}
function cancelActiveScan(event) {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  if (appState.activeScanXhr) {
    const xhr = appState.activeScanXhr;
    appState.activeScanXhr = null;
    xhr._cancelledByUser = true;
    xhr._uploadPreparation?.abort();
    xhr.abort();
  }
}

async function compressScanUpload(file, signal) {
  const gzip = (blob) => new Response(blob.stream().pipeThrough(new CompressionStream("gzip"), { signal })).blob();
  const startedAt = performance.now();
  const worthwhile = (original, compressed) => {
    const preparationSeconds = (performance.now() - startedAt) / 1000;
    return original.size - compressed.size >= Math.max(original.size * 0.2, preparationSeconds * 10 * 1024 * 1024);
  };
  const sampleBytes = 64 * 1024;
  const midpoint = Math.floor(file.size / 2);
  const sample = new Blob([
    file.slice(0, sampleBytes),
    file.slice(midpoint, midpoint + sampleBytes),
    file.slice(-sampleBytes),
  ]);
  if (!worthwhile(sample, await gzip(sample))) return file;
  const compressed = await gzip(file);
  return worthwhile(file, compressed) ? compressed : file;
}

async function handleFileSelect(file) {
  if (!file) return null;
  if (file.size > appState.maxUploadBytes) {
    const limitMb = Math.max(1, Math.round(appState.maxUploadBytes / (1024 * 1024)));
    showToast(
      `Tệp "${file.name}" (${formatBytesVi(file.size)}) vượt quá giới hạn tối đa ${limitMb} MB.`,
      "error",
      5000,
    );
    return null;
  }
  if (appState.activeScanXhr) {
    appState.activeScanXhr._superseded = true;
    appState.activeScanXhr._uploadPreparation?.abort();
    appState.activeScanXhr.abort();
    appState.activeScanXhr = null;
  }

  const scanToken = ++appState.activeScanToken;
  cancelActiveChat();
  appState.currentScanResult = null;
  appState.currentCDRAudit = null;
  document.getElementById("results-panel").classList.add("hidden");
  resetCDRAfterCard(file.name);
  clearVisualDiff();

  const dropzone = document.getElementById("dropzone");
  const idleBox = document.getElementById("dropzone-idle");
  const overlay = document.getElementById("scanning-overlay");
  const scanStage = document.getElementById("doc-scan-stage");
  const uploadBadge = document.getElementById("doc-upload-badge");
  const laser = document.getElementById("scan-laser-line");
  const phaseBadge = document.getElementById("scan-phase-badge");
  const text = document.getElementById("scan-spinner-text");
  const subtext = document.getElementById("scan-spinner-subtext");
  const sizeText = document.getElementById("scan-file-size");
  const progressBar = document.getElementById("scan-progress-bar");
  const progressPct = document.getElementById("scan-progress-pct");
  const step1Label = document.getElementById("scan-step-1-label");
  const steps = [document.getElementById("scan-step-1"), document.getElementById("scan-step-2")];

  const setStepState = (activeIdx) => {
    if (scanToken !== appState.activeScanToken) return;
    steps.forEach((s, idx) => {
      if (!s) return;
      const icon = s.querySelector(".material-symbols-outlined");
      if (idx < activeIdx) {
        s.className = "flex items-center gap-1.5 text-tertiary font-semibold transition-colors";
        if (icon) {
          setIcon(icon, "check_circle");
          icon.classList.remove("animate-spin");
        }
      } else if (idx === activeIdx) {
        s.className = "flex items-center gap-1.5 text-primary-container font-semibold transition-colors";
        if (icon) {
          setIcon(icon, "progress_activity");
          icon.classList.add("animate-spin");
        }
      } else {
        s.className = "flex items-center gap-1.5 text-outline transition-colors";
        if (icon) {
          setIcon(icon, "radio_button_unchecked");
          icon.classList.remove("animate-spin");
        }
      }
    });
  };

  let elapsedInterval = null;
  let currentPhase = "uploading";
  let uploadStartedAt = 0;
  let uploadSec = 0;
  let scanStartedAt = 0;

  if (dropzone) dropzone.dataset.scanning = "1";
  const moveFocusToCancel = idleBox?.contains(document.activeElement);
  if (idleBox) idleBox.classList.add("hidden");
  if (overlay) overlay.classList.remove("hidden");
  if (moveFocusToCancel) document.getElementById("btn-cancel-scan")?.focus({ preventScroll: true });
  if (scanStage) scanStage.dataset.phase = "uploading";
  if (uploadBadge) {
    uploadBadge.classList.remove("hidden");
    uploadBadge.classList.add("flex");
  }
  if (laser) laser.classList.add("hidden");
  if (phaseBadge) {
    phaseBadge.className =
      "inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold bg-sky-50 text-sky-700 border border-sky-200";
    phaseBadge.replaceChildren(
      iconNode("cloud_upload", "text-[14px]"),
      dom("span", {}, "Giai đoạn 1/2 • Đang tải tệp lên"),
    );
  }
  if (text) text.textContent = `Đang tải tệp "${file.name}" lên máy chủ...`;
  if (subtext) subtext.textContent = `Đang truyền ${formatBytesVi(file.size)} lên máy chủ...`;
  if (sizeText) sizeText.textContent = formatBytesVi(file.size);
  if (progressBar) {
    progressBar.className = "h-2 bg-sky-500 rounded-full transition-all duration-150";
    progressBar.style.width = "0%";
  }
  if (progressPct) {
    progressPct.className = "text-xs font-mono font-bold text-sky-700 num w-12 text-right shrink-0";
    progressPct.textContent = "0%";
  }
  if (step1Label) step1Label.textContent = "1. Tải tệp lên máy chủ";
  setStepState(0);

  const enterScanPhase = () => {
    if (scanToken !== appState.activeScanToken || currentPhase === "scanning") return;
    currentPhase = "scanning";
    scanStartedAt = performance.now();
    uploadSec = (scanStartedAt - uploadStartedAt) / 1000;
    if (scanStage) scanStage.dataset.phase = "scanning";
    if (uploadBadge) {
      uploadBadge.classList.add("hidden");
      uploadBadge.classList.remove("flex");
    }
    if (laser) laser.classList.remove("hidden");
    if (phaseBadge) {
      phaseBadge.className =
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold bg-blue-50 text-primary-container border border-blue-200";
      phaseBadge.replaceChildren(
        iconNode("document_scanner", "text-[14px]"),
        dom("span", {}, "Giai đoạn 2/2 • Đang phân tích tệp"),
      );
    }
    if (text) text.textContent = `Đang kiểm tra "${file.name}"...`;
    if (subtext)
      subtext.textContent = `Đã tải lên (${uploadSec.toFixed(1)}s) • Đang phân tích cấu trúc và chấm điểm...`;
    if (progressBar) {
      progressBar.className = "h-2 bg-primary-container shimmer-bar rounded-full transition-all duration-200";
      progressBar.style.width = "100%";
    }
    if (progressPct) {
      progressPct.className = "text-xs font-mono font-bold text-primary-container num w-12 text-right shrink-0";
      progressPct.textContent = "0.0s";
    }
    if (step1Label) step1Label.textContent = `1. Đã tải lên (${uploadSec.toFixed(1)}s)`;
    setStepState(1);
    elapsedInterval = setInterval(() => {
      if (scanToken !== appState.activeScanToken) return;
      const elapsedS = (performance.now() - scanStartedAt) / 1000;
      if (progressPct) progressPct.textContent = `${elapsedS.toFixed(1)}s`;
    }, 200);
  };

  const uploadAndScan = new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    appState.activeScanXhr = xhr;
    xhr.open("POST", "/api/scan", true);
    xhr.upload.onprogress = (e) => {
      if (scanToken !== appState.activeScanToken || currentPhase !== "uploading") return;
      if (e.lengthComputable && e.total > 0) {
        const pct = Math.min(99, Math.round((e.loaded / e.total) * 100));
        const elapsedSec = Math.max(0.05, (performance.now() - uploadStartedAt) / 1000);
        const mbps = e.loaded / (1024 * 1024) / elapsedSec;
        const remainBytes = Math.max(0, e.total - e.loaded);
        const etaSec = mbps > 0.01 ? remainBytes / (1024 * 1024) / mbps : 0;
        const speedStr = `${mbps.toFixed(1)} MiB/s` + (etaSec >= 1 ? ` • còn ~${Math.ceil(etaSec)}s` : "");
        if (progressBar) progressBar.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct}%`;
        if (subtext)
          subtext.textContent = `Đã gửi ${formatBytesVi(e.loaded)} / ${formatBytesVi(e.total)} • ${speedStr}`;
        if (step1Label) step1Label.textContent = `1. Đang tải lên (${pct}%)`;
      }
    };
    xhr.upload.onload = () => {
      enterScanPhase();
    };
    xhr.onload = () => {
      if (appState.activeScanXhr === xhr) appState.activeScanXhr = null;
      let payload = null;
      try {
        payload = JSON.parse(xhr.responseText || "{}");
      } catch {}
      if (xhr.status >= 200 && xhr.status < 300 && payload) {
        enterScanPhase();
        resolve(payload);
        return;
      }
      const detail = payload && typeof payload.detail === "string" ? payload.detail : "";
      reject(new Error(_formatScanErrorVi(xhr.status, detail)));
    };
    xhr.onerror = () => {
      if (appState.activeScanXhr === xhr) appState.activeScanXhr = null;
      reject(new Error("Kết nối mạng bị gián đoạn khi tải tệp lên máy chủ."));
    };
    xhr.onabort = () => {
      if (appState.activeScanXhr === xhr) appState.activeScanXhr = null;
      const err = new Error("CANCELLED");
      err._cancelled = Boolean(xhr._cancelledByUser);
      err._superseded = Boolean(xhr._superseded);
      reject(err);
    };
    const send = (body) => {
      xhr._uploadPreparation = null;
      if (xhr._cancelledByUser || xhr._superseded) {
        xhr.onabort();
        return;
      }
      if (body !== file) xhr.setRequestHeader("X-MalPDF-Upload-Encoding", "gzip");
      if (subtext) subtext.textContent = `Đang truyền ${formatBytesVi(body.size)} lên máy chủ...`;
      const formData = new FormData();
      formData.append("file", body, file.name);
      uploadStartedAt = performance.now();
      xhr.send(formData);
    };
    if (appState.gzipScanUpload && typeof CompressionStream === "function" && file.size >= 2 * 1024 * 1024) {
      const preparation = new AbortController();
      xhr._uploadPreparation = preparation;
      if (subtext) subtext.textContent = "Đang chuẩn bị tệp để tải lên...";
      compressScanUpload(file, preparation.signal)
        .catch(() => file)
        .then(send)
        .catch(reject);
    } else {
      send(file);
    }
  });

  try {
    const data = await uploadAndScan;
    if (scanToken !== appState.activeScanToken) return null;
    const assessment = renderScanResult(data);
    showToast(`${data.file_name} · ${assessment.title}`, assessment.tone === "clear" ? "success" : "warning");
    return data.scan_id;
  } catch (err) {
    if (err?._cancelled) {
      showToast("Đã hủy tải lên và quét tệp.", "info");
    } else if (scanToken === appState.activeScanToken && !err?._superseded) {
      showToast("Không thể kiểm tra tệp: " + err.message, "error", 5000);
    }
    return null;
  } finally {
    if (elapsedInterval) clearInterval(elapsedInterval);
    if (scanToken === appState.activeScanToken) {
      if (dropzone) delete dropzone.dataset.scanning;
      if (scanStage) scanStage.dataset.phase = "idle";
      if (uploadBadge) {
        uploadBadge.classList.add("hidden");
        uploadBadge.classList.remove("flex");
      }
      if (laser) laser.classList.add("hidden");
      const restoreUploadFocus = overlay?.contains(document.activeElement);
      if (overlay) overlay.classList.add("hidden");
      if (idleBox) idleBox.classList.remove("hidden");
      if (restoreUploadFocus) document.getElementById("btn-select-pdf")?.focus({ preventScroll: true });
      if (step1Label) step1Label.textContent = "1. Tải tệp lên máy chủ";
    }
  }
}

let _analyzerBtnBaseLabel = "Xem chi tiết 8 nhóm kiểm tra";

function toggleAnalyzerGrid() {
  const wrap = document.getElementById("tax-analyzers-wrap");
  const btn = document.getElementById("btn-toggle-analyzers");
  const lbl = document.getElementById("btn-toggle-analyzers-label");
  if (!wrap) return;
  const isNowHidden = wrap.classList.toggle("hidden");
  if (btn) btn.setAttribute("aria-expanded", isNowHidden ? "false" : "true");
  if (lbl) lbl.textContent = isNowHidden ? _analyzerBtnBaseLabel : _analyzerBtnBaseLabel.replace(/^Xem /, "Ẩn ");
}

function renderThreatTaxonomy(data) {
  const tax = data.threat_taxonomy || data.forensic_dossier?.threat_taxonomy || null;
  const card = document.getElementById("taxonomy-intel-card");
  if (!card) return;
  if (!tax) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");

  const detCnt = (tax.ml_label_predictions || []).filter((h) => h.evidence_status === "observed").length;
  const totCnt = Number(tax.total_analyzers || 0);
  const isFlagged = detCnt > 0 || data.verdict === "MALICIOUS";

  const ring = document.getElementById("tax-score-ring");
  const ratioEl = document.getElementById("tax-detected-ratio");
  if (ratioEl) ratioEl.textContent = `${detCnt}/${totCnt}`;
  if (ring) {
    ring.className = isFlagged
      ? "w-14 h-14 rounded-lg flex flex-col items-center justify-center font-extrabold text-xs shrink-0 border border-error/40 bg-error/10 text-error"
      : "w-14 h-14 rounded-lg flex flex-col items-center justify-center font-extrabold text-xs shrink-0 border border-tertiary/40 bg-tertiary/10 text-tertiary";
    const subSpans = ring.querySelectorAll("span");
    if (subSpans.length > 1) subSpans[1].textContent = "DẤU HIỆU";
  }

  const titleViEl = document.getElementById("tax-threat-title-vi");
  if (titleViEl) {
    titleViEl.textContent = tax.ml_label_predictions?.some((head) => head.evidence_status)
      ? tax.threat_title_vi
      : "Kết quả quét cũ";
    titleViEl.className = isFlagged
      ? "font-bold text-sm sm:text-base text-error"
      : "font-bold text-sm sm:text-base text-tertiary";
  }

  const labelEl = document.getElementById("tax-threat-label");
  if (labelEl) {
    labelEl.textContent = tax.threat_label || "--";
    labelEl.className = isFlagged
      ? "px-2 py-0.5 rounded-md font-mono font-semibold text-xs bg-error/10 text-error truncate"
      : "px-2 py-0.5 rounded-md font-mono font-semibold text-xs bg-tertiary/10 text-tertiary truncate";
  }

  const sumEl = document.getElementById("tax-summary-vi");
  if (sumEl)
    sumEl.textContent = tax.ml_label_predictions?.some((head) => head.evidence_status)
      ? _cleanEvidenceTextVi(tax.summary_vi || "")
      : "Quét lại tệp để cập nhật chi tiết từng nhóm kiểm tra.";

  _analyzerBtnBaseLabel = `Xem chi tiết ${totCnt} nhóm (${detCnt}/${totCnt} có dấu hiệu tĩnh)`;
  const btnLabel = document.getElementById("btn-toggle-analyzers-label");
  const toggleBtn = document.getElementById("btn-toggle-analyzers");
  if (btnLabel) btnLabel.textContent = _analyzerBtnBaseLabel;
  if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "false");

  const hasProvenance = tax.ml_label_predictions?.some((head) => head.evidence_status);
  const catsVi = hasProvenance && Array.isArray(tax.categories_vi) ? tax.categories_vi : [];
  const famsVi = hasProvenance && Array.isArray(tax.families_vi) ? tax.families_vi : [];
  const btagsVi = hasProvenance && Array.isArray(tax.behavior_tags_vi) ? tax.behavior_tags_vi : [];
  const mitre = hasProvenance && Array.isArray(tax.mitre_attack) ? tax.mitre_attack : [];

  const tagsStrip = document.getElementById("tax-tags-strip");
  const hasSubstantiveTags = isFlagged || famsVi.length > 0 || mitre.length > 0 || btagsVi.some((t) => t.is_risk);
  if (tagsStrip) tagsStrip.classList.toggle("hidden", !hasSubstantiveTags);

  const catsEl = document.getElementById("tax-categories");
  if (catsEl) {
    catsEl.replaceChildren(
      ...(catsVi.length
        ? catsVi.map((c) =>
            dom(
              "span",
              {
                title: c.code,
                class: `px-2 py-0.5 rounded-md font-bold text-[11px] ${c.code === "clean" ? "bg-tertiary/15 text-tertiary" : "bg-error/15 text-error"}`,
              },
              c.label_vi,
            ),
          )
        : [dom("span", { class: "text-outline" }, "--")]),
    );
  }

  const famsEl = document.getElementById("tax-families");
  if (famsEl) {
    famsEl.replaceChildren(
      ...(famsVi.length
        ? famsVi.map((f) =>
            dom(
              "span",
              {
                title: f.code,
                class:
                  "px-2 py-0.5 rounded-md font-semibold text-[11px] bg-blue-50 text-primary-container border border-blue-200",
              },
              f.label_vi,
            ),
          )
        : [dom("span", { class: "text-outline italic text-[11px]" }, "Không có nhóm dấu hiệu nào được ghi nhận")]),
    );
  }

  const tagsEl = document.getElementById("tax-behavior-tags");
  if (tagsEl) {
    tagsEl.replaceChildren(
      ...btagsVi.map((t) => {
        const cls = t.is_risk
          ? "bg-amber-50 text-amber-800 border border-amber-200 font-semibold"
          : "bg-slate-100 text-on-surface-variant border border-slate-200";
        return dom("span", { title: t.code, class: `px-2 py-0.5 rounded-md text-[11px] ${cls}` }, t.label_vi);
      }),
    );
  }

  const mitreEl = document.getElementById("tax-mitre-list");
  if (mitreEl) {
    mitreEl.replaceChildren(
      ...(mitre.length
        ? mitre.map((m) =>
            dom(
              "span",
              {
                title: `${m.tactic || ""} — ${_cleanEvidenceTextVi(m.evidence || "")}`,
                class: "px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-800 text-white cursor-help",
              },
              `${m.name ?? ""} (${m.id ?? ""})`,
            ),
          )
        : [dom("span", { class: "text-outline italic text-[11px]" }, "Chưa có kỹ thuật tương ứng")]),
    );
  }

  const wrapEl = document.getElementById("tax-analyzers-wrap");
  if (wrapEl) wrapEl.classList.add("hidden");

  const gridEl = document.getElementById("tax-analyzers-grid");
  if (gridEl) {
    const heads =
      Array.isArray(tax.ml_label_predictions) && tax.ml_label_predictions.length
        ? tax.ml_label_predictions
        : Array.isArray(tax.analyzer_detections)
          ? tax.analyzer_detections
          : [];
    gridEl.replaceChildren(
      ...heads.map((h) => {
        const det = h.evidence_status === "observed";
        const score =
          h.evidence_status && Number.isFinite(h.probability_pct) ? h.probability_pct.toFixed(2) + "%" : "chưa có";
        const name = h.label_vi || h.analyzer || "";
        const cleanEv = _cleanEvidenceTextVi(h.evidence_status ? h.evidence : "Dữ liệu từ lần quét cũ");
        const status = det
          ? "Có dấu hiệu tĩnh"
          : h.model_flagged
            ? "Mô hình cảnh báo (chưa có bằng chứng tĩnh)"
            : "Chưa ghi nhận";
        return dom(
          "div",
          {
            class: `p-3 rounded-lg border ${det ? "border-error/30 bg-red-50/40" : "border-slate-200 bg-white"} flex flex-col gap-1.5`,
          },
          dom(
            "div",
            { class: "flex items-center justify-between gap-2" },
            dom("span", { class: "font-bold text-on-surface truncate" }, name),
            dom("span", { class: "text-[11px] text-outline shrink-0" }, `Điểm: ${score}`),
          ),
          dom("span", { class: "font-semibold text-[11px]" }, status),
          dom("div", { class: "text-[11px] text-on-surface-variant leading-snug", title: cleanEv }, cleanEv),
        );
      }),
    );
  }
}

function formatRatioPercent(value) {
  return Number.isFinite(value) ? (value * 100).toFixed(2) + "%" : "--";
}

function renderConformalAnalysis(analysis, data = null) {
  const states = {
    CERTIFIED_BENIGN: "Chứng nhận an toàn (Conformal)",
    CERTIFIED_MALICIOUS: "Chứng nhận nguy hiểm (Conformal)",
    AMBIGUOUS_BOTH: "Vùng lưỡng lự · Đẩy CDR",
    DRIFT_OOD_EMPTY: "Lệch phân phối (Drift) · Đẩy CDR",
  };
  const state = analysis?.conformal_state;
  const hasState = Object.hasOwn(states, state);
  const badge = document.getElementById("conformal-state-badge");
  document.getElementById("conformal-status").hidden = !hasState;
  badge.dataset.state = hasState ? state : "";
  const policyDisagreement = analysis?.policy_override === true;
  const thresholdDisagreement =
    !policyDisagreement &&
    ((state === "CERTIFIED_BENIGN" && data?.verdict === "MALICIOUS") ||
      (state === "CERTIFIED_MALICIOUS" && data?.verdict === "BENIGN"));
  badge.textContent = !hasState
    ? "--"
    : policyDisagreement
      ? analysis?.policy_reject_for_cdr
        ? "Bất đồng Mô hình–Luật tĩnh · Đẩy CDR"
        : "Bất đồng Mô hình–Luật tĩnh"
      : thresholdDisagreement
        ? "Vùng biên ngưỡng quyết định"
        : state === "DRIFT_OOD_EMPTY" && data?.verdict === "BENIGN" && data?.is_ood === false
          ? "Dưới ngưỡng cảnh báo · Ngoài dải chuẩn 99%"
          : states[state];
  document.getElementById("conformal-credibility").textContent = hasState
    ? "Độ khả tín " +
      formatRatioPercent(analysis.credibility) +
      " · Độ tin cậy " +
      formatRatioPercent(analysis.confidence)
    : "--";
}

function applyJsThreatHighlights(container, extraIndicators = []) {
  CSS.highlights?.clear();
  const tokens = [
    "this.exportDataObject",
    "app.alert",
    "eval",
    "unescape",
    "launchURL",
    "exportDataObject",
    "submitForm",
    "getAnnots",
    "fromCharCode",
    "ActiveXObject",
    "WScript",
    "Collab",
    "printf",
    ...extraIndicators
      .filter((value) => typeof value === "string")
      .map((value) => value.trim())
      .filter((value) => /^[a-z0-9]{3,}$/i.test(value)),
  ];
  const pattern = tokens.map((token) => token.replaceAll(".", "\\.")).join("|");
  const identifier = "\\p{ID_Continue}$\\u200c\\u200d";
  const tokenPattern = new RegExp("(?<![" + identifier + "])(?:" + pattern + ")(?![" + identifier + "])", "giu");
  const useHighlight = CSS.highlights && typeof globalThis.Highlight === "function";
  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  const ranges = [];
  for (let node = walker.nextNode(); node; node = walker.nextNode()) textNodes.push(node);
  for (const node of textNodes) {
    const matches = Array.from(node.data.matchAll(tokenPattern));
    if (!matches.length) continue;
    if (useHighlight) {
      for (const match of matches) {
        const range = new Range();
        range.setStart(node, match.index);
        range.setEnd(node, match.index + match[0].length);
        ranges.push(range);
      }
    } else {
      const fragment = document.createDocumentFragment();
      let offset = 0;
      for (const match of matches) {
        fragment.append(document.createTextNode(node.data.slice(offset, match.index)));
        fragment.append(dom("mark", { class: "js-threat-mark" }, match[0]));
        offset = match.index + match[0].length;
      }
      fragment.append(document.createTextNode(node.data.slice(offset)));
      node.replaceWith(fragment);
    }
  }
  if (useHighlight && ranges.length > 0) CSS.highlights.set("malpdf-js-threat", new Highlight(...ranges));
}

function renderThreatSnippet(threats, jsSemantics = null) {
  const snippetEl = document.getElementById("threat-code-snippet");
  const indicatorsEl = document.getElementById("threat-indicators");
  const isVerifiedBenign = (script) =>
    (Boolean(jsSemantics?.is_verified_benign_js) || Boolean(script.is_verified_benign)) &&
    (script.dangerous_indicators || []).length === 0;
  const threat = threats.find((script) => !isVerifiedBenign(script)) || threats[0];
  const allVerifiedBenign = threats.length > 0 && threats.every(isVerifiedBenign);
  document.getElementById("js-threat-count").textContent =
    `${threats.length} đoạn mã${allVerifiedBenign ? " hợp lệ" : ""}`;
  document.getElementById("threat-code-empty").classList.toggle("hidden", Boolean(threat));
  document.getElementById("threat-code-box").classList.toggle("hidden", !threat);
  if (threat) {
    snippetEl.textContent = _formatReadableCodeSnippet(threat.code_snippet || threat.snippet);
    document.getElementById("threat-entropy").textContent = (threat.entropy || 0).toFixed(2);
    if (isVerifiedBenign(threat)) {
      CSS.highlights?.clear();
      const intent =
        threat.intent_label_vi ||
        jsSemantics?.intent_summary_vi ||
        "Mã JavaScript hợp lệ (không có hành vi khai thác hay làm rối)";
      indicatorsEl.replaceChildren(
        dom(
          "span",
          {
            class:
              "inline-block px-2 py-0.5 rounded-md font-semibold bg-emerald-50 text-tertiary border border-emerald-200",
          },
          "Đã xác minh hợp lệ",
        ),
        " ",
        dom("span", { class: "font-medium text-tertiary" }, intent),
      );
    } else {
      const indicators = threat.dangerous_indicators || [];
      applyJsThreatHighlights(snippetEl, indicators);
      indicatorsEl.textContent = indicators.length
        ? indicators.map((ind) => _INDICATOR_VI[ind] || ind).join(", ")
        : "Không có dấu hiệu rủi ro cụ thể";
    }
  } else {
    CSS.highlights?.clear();
    snippetEl.textContent = "";
    document.getElementById("threat-entropy").textContent = "--";
    indicatorsEl.textContent = "Không có";
  }
}

function renderScanResult(data, cdrAudit = null) {
  if (data.scan_id !== appState.currentScanResult?.scan_id) {
    cancelActiveChat();
    appState.selectedGraphNode = null;
  }
  clearVisualDiff();
  appState.currentScanResult = data;
  appState.currentCDRAudit = null;
  resetCDRAfterCard(data.file_name);
  if (cdrAudit) applyCDRAuditToUI(cdrAudit);
  if (appState.disarmingScans.has(data.scan_id)) setCDRPending(true);
  appState.ablatedGraphNodeIds.clear();
  const resetAblBtn = document.getElementById("btn-reset-ablation");
  if (resetAblBtn) resetAblBtn.classList.add("hidden");
  document.getElementById("results-panel").classList.remove("hidden");

  const topLat = document.getElementById("telemetry-latency");
  const topDot = document.getElementById("telemetry-dot");
  const topLabel = document.getElementById("telemetry-status-label");
  if (topDot)
    topDot.className = data.prediction_available
      ? "w-2 h-2 rounded-full bg-tertiary animate-pulse"
      : "w-2 h-2 rounded-full bg-amber-500";
  if (topLabel) topLabel.textContent = data.prediction_available ? "Đã kiểm tra tệp" : "Chỉ kiểm tra được một phần";
  const latVal = Number.isFinite(data.latency_ms) ? data.latency_ms : data.inference_latency_ms;
  if (topLat && Number.isFinite(latVal)) {
    animateValue("telemetry-latency", 0, latVal, 500, 1, " ms");
  }

  const isMal = data.verdict === "MALICIOUS";
  const ribbon = document.getElementById("status-ribbon");
  const icon = document.getElementById("status-icon");
  const headline = document.getElementById("status-headline");
  const subtext = document.getElementById("status-subtext");
  const assessment = scanAssessment(data);
  const styles = {
    danger: ["border-error bg-red-50/40", "text-error", "security_update_warning"],
    caution: ["border-amber-500 bg-amber-50/40", "text-amber-900", "info"],
    clear: ["border-tertiary bg-emerald-50/40", "text-tertiary", "verified"],
  };
  const [surfaceClass, textClass, iconName] = styles[assessment.tone];
  ribbon.className = `glass-card rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 border-l-4 ${surfaceClass} reveal-stagger-1`;
  setIcon(icon, iconName);
  icon.className = `material-symbols-outlined text-[28px] ${textClass} shrink-0 mt-0.5 sm:mt-0`;
  headline.textContent = assessment.title;
  headline.className = `font-bold text-lg sm:text-xl ${textClass} leading-snug break-words`;
  subtext.textContent = data.file_name;
  document.getElementById("status-action").textContent = assessment.guidance;
  renderConformalAnalysis(data.forensic_dossier?.conformal_analysis, data);

  renderThreatTaxonomy(data);

  const verdictEl = document.getElementById("card-verdict");
  if (isMal) {
    verdictEl.textContent = "Nguy hiểm";
    verdictEl.className = "text-2xl font-bold tracking-tight text-error";
  } else if (assessment.tone === "clear") {
    verdictEl.textContent = "An toàn";
    verdictEl.className = "text-2xl font-bold tracking-tight text-tertiary";
  } else if (!data.prediction_available && assessment.title === "Cần lưu ý trước khi mở tệp") {
    verdictEl.textContent = "Chưa xác định";
    verdictEl.className = "text-2xl font-bold tracking-tight text-amber-700";
  } else {
    verdictEl.textContent = "Cần lưu ý";
    verdictEl.className = "text-2xl font-bold tracking-tight text-amber-700";
  }

  const thrPct = Number.isFinite(data.decision_threshold) ? Number((data.decision_threshold * 100).toFixed(2)) : null;
  const thrLabelEl = document.getElementById("card-threshold-label");
  if (thrLabelEl) {
    thrLabelEl.textContent = thrPct === null ? "Chưa có ngưỡng" : `Ngưỡng nguy hiểm ${thrPct}%`;
  }
  document.getElementById("card-confidence").textContent = _confidenceVi(data.confidence);

  const probPct = Number.isFinite(data.malware_probability)
    ? Number((data.malware_probability * 100).toFixed(2))
    : null;
  const probEl = document.getElementById("card-prob");
  probEl.className = isMal
    ? "text-3xl font-extrabold text-error font-mono num animate-pulse-subtle"
    : "text-3xl font-extrabold text-tertiary font-mono num";
  if (probPct === null) {
    probEl.textContent = "--";
    probEl.className = "text-3xl font-extrabold text-slate-400 font-mono num";
  } else {
    animateValue("card-prob", 0, probPct, 750, 2, "%");
  }

  const barProb = document.getElementById("bar-prob");
  barProb.style.width = (probPct ?? 0) + "%";
  barProb.className = isMal
    ? "bg-error shimmer-bar h-2 rounded-full transition-all duration-700"
    : "bg-tertiary shimmer-bar h-2 rounded-full transition-all duration-700";

  const oodAvailable = Number.isFinite(data.ood_score);
  const oodThr = Number.isFinite(data.ood_threshold) ? data.ood_threshold.toFixed(2) : null;
  const oodDotEl = document.getElementById("ood-status-dot");
  if (oodDotEl) {
    oodDotEl.className = !oodAvailable
      ? "w-2 h-2 rounded-full bg-slate-400"
      : data.is_ood
        ? "w-2 h-2 rounded-full bg-amber-500 animate-pulse"
        : "w-2 h-2 rounded-full bg-tertiary";
  }
  const cardOodEl = document.getElementById("card-ood");
  cardOodEl.textContent = !oodAvailable ? "Chưa đo" : data.is_ood ? "Mẫu lạ (OOD)" : "Mẫu phổ biến";
  cardOodEl.className = !oodAvailable
    ? "text-xl font-bold text-outline"
    : data.is_ood
      ? "text-xl font-bold text-amber-600"
      : "text-xl font-bold text-on-surface";
  document.getElementById("ood-threshold-label").textContent =
    oodAvailable && oodThr !== null ? `Chỉ số OOD (ngưỡng ${oodThr})` : "Chỉ số OOD";
  document.getElementById("badge-ood").textContent = oodAvailable ? data.ood_score.toFixed(3) : "--";

  if (Number.isFinite(data.latency_ms)) animateValue("card-latency", 0, data.latency_ms, 500, 1, " ms");
  else document.getElementById("card-latency").textContent = "--";
  document.getElementById("card-size").textContent = formatBytesVi(data.file_size_bytes || 0);
  const modelTypeEl = document.getElementById("card-model-type");
  if (modelTypeEl) {
    const pageNodesCount = Array.isArray(data.graph_nodes)
      ? data.graph_nodes.filter((n) => n.kind === "page").length
      : 0;
    const pageCnt = data.forensic_dossier?.page_count || data.pages_count || pageNodesCount;
    modelTypeEl.textContent = pageCnt > 0 ? `${pageCnt} trang` : "Tệp PDF";
  }

  if (data.forensic_dossier) {
    const weights = data.forensic_dossier.cross_modal_weights || {};
    const gw = Number.isFinite(weights.graph_weight) ? (weights.graph_weight * 100).toFixed(1) : null;
    const secLabelEl = document.getElementById("xai-secondary-branch-label");
    const useTabularAsSecondary =
      Number.isFinite(weights.tabular_weight) && (!Number.isFinite(weights.ast_weight) || weights.ast_weight === 0);
    const secWeight = useTabularAsSecondary ? weights.tabular_weight : weights.ast_weight;
    if (secLabelEl) {
      secLabelEl.textContent = useTabularAsSecondary ? "Chỉ số cấu trúc & thống kê tệp" : "Mã JavaScript (AST)";
    }
    const aw = Number.isFinite(secWeight) ? (secWeight * 100).toFixed(1) : null;
    document.getElementById("xai-graph-weight").textContent = gw === null ? "--" : gw + "%";
    document.getElementById("xai-graph-bar").style.width = (gw ?? 0) + "%";
    document.getElementById("xai-ast-weight").textContent = aw === null ? "--" : aw + "%";
    document.getElementById("xai-ast-bar").style.width = (aw ?? 0) + "%";

    const pathLabelEl = document.getElementById("attack-path-label");
    const activePath = data.forensic_dossier.attack_path_kind === "observed_active_object";
    if (pathLabelEl)
      pathLabelEl.textContent = activePath
        ? "Chuỗi tham chiếu đến đối tượng cần xem xét"
        : "Chuỗi tham chiếu cấu trúc cơ bản";
    const pathFlowEl = document.getElementById("attack-path-flow");
    pathFlowEl.replaceChildren();
    const pathItems =
      data.forensic_dossier?.attack_path && data.forensic_dossier.attack_path.length > 0
        ? data.forensic_dossier.attack_path
        : [];
    if (pathItems.length === 0) {
      pathFlowEl.replaceChildren(
        dom("span", { class: "text-xs text-on-surface-variant italic" }, "Chưa có chuỗi tham chiếu."),
      );
    } else {
      pathItems.forEach((p, idx) => {
        if (idx > 0) {
          const arr = document.createElement("span");
          arr.className = isMal ? "text-error font-bold text-sm px-0.5" : "text-tertiary font-bold text-sm px-0.5";
          arr.textContent = "→";
          pathFlowEl.appendChild(arr);
        }
        const badge = document.createElement("span");
        badge.className = isMal
          ? "px-2.5 py-1 rounded-md bg-red-50 text-error text-xs font-semibold border border-red-200"
          : "px-2.5 py-1 rounded-md bg-emerald-50 text-tertiary text-xs font-semibold border border-emerald-200";
        badge.title = _cleanEvidenceTextVi(p);
        badge.textContent = _formatAttackPathStepVi(p, activePath);
        pathFlowEl.appendChild(badge);
      });
    }
  }
  renderThreatSnippet(data.forensic_dossier?.threat_scripts || [], data.forensic_dossier?.js_semantics || null);
  renderMitreCascade(data.forensic_dossier?.mitre_cascade || [], isMal);
  renderCrossAttentionTable(data.forensic_dossier?.cross_attention_matrix || []);

  updateCDRBeforeCard(data, assessment);

  const nCount = Array.isArray(data.graph_nodes) ? data.graph_nodes.length : 0;
  const eCount = Array.isArray(data.graph_edges) ? data.graph_edges.length : 0;
  const gnEl = document.getElementById("graph-node-count");
  const geEl = document.getElementById("graph-edge-count");
  if (gnEl) gnEl.textContent = nCount;
  if (geEl) geEl.textContent = eCount;
  appState.dagGraphDirty = true;
  if (appState.activeTab === "graph") showCurrentGraph();

  renderAIExplainer(data.ai_threat_explanation, isMal, data);
  fetchScanHistory();
  appState.currentDiffPage = 0;
  if (appState.activeTab === "cdr") loadVisualDiff(0);
  return assessment;
}
async function deleteScanJob(event, scanId) {
  if (event) {
    event.stopPropagation();
    event.preventDefault();
  }
  if (!scanId) return;
  try {
    const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`Mã lỗi ${res.status}`);
    appState.unconfirmedCDR.delete(scanId);
    if (appState.currentScanResult?.scan_id === scanId) {
      cancelActiveChat();
      appState.currentScanResult = null;
      appState.currentCDRAudit = null;
      document.getElementById("results-panel").classList.add("hidden");
      resetCDRAfterCard();
      clearVisualDiff();
      if (appState.activeTab !== "scan") switchTab("scan");
    }
    showToast("Đã xóa tệp khỏi danh sách vừa kiểm tra.", "info", 2200);
    await fetchScanHistory();
  } catch (err) {
    showToast("Không thể xóa mục này: " + err.message, "error");
  }
}

function renderVerticalQueue(jobs) {
  const vContainer = document.getElementById("scan-history-items-vertical");
  const badge = document.getElementById("queue-count-badge");
  if (!vContainer) return;
  if (!jobs || jobs.length === 0) {
    vContainer.replaceChildren(
      dom(
        "div",
        { class: "p-3 text-center text-outline text-xs rounded-lg bg-white border border-dashed border-slate-200" },
        "Chưa có tệp nào được kiểm tra",
      ),
    );
    if (badge) badge.textContent = "0 tệp";
    return;
  }
  if (badge) badge.textContent = `${jobs.length} tệp`;
  vContainer.replaceChildren();

  jobs.slice(0, 20).forEach((j) => {
    const hasResult =
      j.has_scan_result === true ||
      ((j.verdict === "BENIGN" || j.verdict === "MALICIOUS" || j.verdict === "UNAVAILABLE") &&
        ("threat_taxonomy" in j || "forensic_dossier" in j));
    const isFailedNoResult = !hasResult && j.status === "FAILED";
    const isPending =
      !hasResult &&
      !isFailedNoResult &&
      (j.status === "PENDING" || j.status === "QUEUED" || j.status === "SCANNING" || j.verdict === "PENDING");
    const qAssess = hasResult ? scanAssessment(j) : null;
    const isUnavail =
      isFailedNoResult ||
      (!hasResult && !isPending && j.verdict !== "BENIGN" && j.verdict !== "MALICIOUS") ||
      (hasResult && j.prediction_available === false && qAssess?.title === "Cần lưu ý trước khi mở tệp");
    const qTone = isPending
      ? "pending"
      : isUnavail
        ? "unavail"
        : qAssess
          ? qAssess.tone
          : j.verdict === "MALICIOUS"
            ? "danger"
            : "clear";
    const isDisarmed = j.status === "DISARMED" || j.has_sanitized_pdf;
    const isActive = appState.currentScanResult?.scan_id === j.scan_id;
    const sizeLabel = j.file_size_bytes
      ? `${Math.round(j.file_size_bytes / 1024).toLocaleString("vi-VN")} KB`
      : "-- KB";
    const pillText =
      qTone === "danger"
        ? "Nguy hiểm"
        : qTone === "pending"
          ? "Đang quét"
          : isFailedNoResult
            ? "Lỗi xử lý"
            : qTone === "unavail"
              ? "Chưa xác định"
              : qTone === "caution"
                ? "Cần lưu ý"
                : "An toàn";
    const iconWrapClass =
      qTone === "danger"
        ? "bg-red-50 text-error"
        : qTone === "unavail" || qTone === "caution"
          ? "bg-amber-50 text-amber-800"
          : qTone === "pending"
            ? "bg-slate-100 text-outline"
            : "bg-emerald-50 text-tertiary";
    const iconName =
      qTone === "danger"
        ? "gpp_maybe"
        : qTone === "pending"
          ? "pending"
          : qTone === "unavail"
            ? "help"
            : qTone === "caution"
              ? "info"
              : "check_circle";
    const pillClass =
      qTone === "danger"
        ? "bg-red-50 text-error border border-red-200"
        : qTone === "unavail" || qTone === "caution"
          ? "bg-amber-50 text-amber-800 border border-amber-200"
          : qTone === "pending"
            ? "bg-slate-100 text-outline"
            : "bg-emerald-50 text-tertiary border border-emerald-200";

    const item = document.createElement("div");
    item.className = `p-2.5 rounded-lg border transition cursor-pointer flex items-center justify-between gap-2 active:scale-98 group ${
      isActive
        ? "border-primary-container bg-blue-50/70 ring-1 ring-primary-container shadow-xs"
        : "border-slate-200 bg-white hover:border-slate-300"
    }`;
    const open = dom(
      "button",
      {
        type: "button",
        class: "flex flex-1 items-center gap-2 min-w-0 text-left",
        "aria-current": isActive ? "true" : null,
        dataset: { scanJob: j.scan_id },
      },
      iconNode(iconName, `w-6 h-6 rounded-md ${iconWrapClass} text-[14px] font-bold shrink-0`),
      dom(
        "span",
        { class: "block min-w-0 flex-1" },
        dom(
          "span",
          { class: `block text-xs font-bold text-on-surface truncate ${isActive ? "text-primary-container" : ""}` },
          j.file_name || "document.pdf",
        ),
        dom(
          "span",
          { class: "block text-[10px] text-on-surface-variant truncate num" },
          sizeLabel + (isDisarmed ? " · Có bản đã làm sạch" : ""),
        ),
      ),
    );
    const remove = dom(
      "button",
      {
        type: "button",
        title: "Xóa khỏi danh sách",
        "aria-label": "Xóa khỏi danh sách",
        class:
          "w-5 h-5 rounded-md hover:bg-red-50 text-outline hover:text-error transition flex items-center justify-center",
        dataset: { deleteScan: j.scan_id },
      },
      iconNode("close", "text-[13px]"),
    );
    open.append(
      dom("span", { class: `px-2 py-0.5 rounded-md text-[10px] font-bold num shrink-0 ${pillClass}` }, pillText),
    );
    item.replaceChildren(open, remove);
    vContainer.appendChild(item);
  });
}

const _AST_TOKEN_VI = {
  Identifier: "Định danh / Tên biến hoặc hàm (Identifier)",
  BlockStatement: "Khối lệnh ({...})",
  ForStatement: "Vòng lặp for",
  WhileStatement: "Vòng lặp while",
  DoWhileStatement: "Vòng lặp do...while",
  UpdateExpression: "Biểu thức cập nhật bộ đếm (i++)",
  AssignmentExpression: "Biểu thức gán (=)",
  CallExpression: "Lời gọi hàm (CallExpression)",
  MemberExpression: "Truy cập thuộc tính đối tượng",
  BinaryExpression: "Biểu thức hai ngôi (nối chuỗi / tính toán)",
  VariableDeclaration: "Khai báo biến (var / let / const)",
  VariableDeclarator: "Thành phần khai báo biến",
  Literal: "Hằng giá trị chuỗi hoặc số",
  ArrayExpression: "Khai báo mảng ([...])",
  FunctionDeclaration: "Khai báo hàm",
  FunctionExpression: "Biểu thức hàm",
  ReturnStatement: "Lệnh return",
  IfStatement: "Câu lệnh điều kiện (if)",
  TryStatement: "Khối xử lý ngoại lệ (try/catch)",
  NewExpression: "Khởi tạo đối tượng (new)",
  ExpressionStatement: "Câu lệnh biểu thức",
};

const _TABULAR_FEATURE_VI = {
  byte_image_file_encoded_ratio: "Tỷ lệ dữ liệu mã hóa trong tệp",
  byte_image_file_persisted_ratio: "Mật độ lưu trữ luồng nhị phân",
  stream_truncation_ratio: "Tỷ lệ cắt cụt luồng dữ liệu",
  evasive_timeout_anomaly: "Bất thường liên quan thời gian thực thi",
  flag_decompression_ratio_exceeded: "Tỷ lệ giải nén luồng vượt ngưỡng",
  is_truncated_stream: "Luồng dữ liệu bị cắt ngang",
  flag_spec_violation_flood: "Số lượng vi phạm cấu trúc PDF vượt ngưỡng",
  flag_excessive_object_graph: "Số lượng đối tượng PDF vượt ngưỡng",
  flag_ast_complexity_truncated: "Cây cú pháp JavaScript bị cắt theo giới hạn phân tích",
  js_entropy: "Độ hỗn loạn chuỗi JavaScript (Entropy)",
  raw_entropy: "Độ hỗn loạn byte toàn tệp (Entropy)",
  PdfSize: "Dung lượng tổng thể tệp PDF",
  file_size: "Dung lượng tệp PDF",
  page_count: "Số trang tài liệu",
  stream_count: "Số luồng dữ liệu (/Stream)",
  object_count: "Tổng số đối tượng PDF",
  xref_count: "Số bảng tham chiếu chéo (xref)",
  trailer_count: "Số phần kết (trailer)",
  startxref_count: "Số khóa startxref",
  density_obj_stream_ratio: "Tỷ lệ đối tượng trên số luồng",
  lexical_url_count: "Số URL xuất hiện trong nội dung thô",
  lexical_js_keyword_hits: "Số từ khóa JavaScript trong tệp",
  lexical_obfuscation_hits: "Số dấu hiệu làm rối chuỗi trong mã",
  Pages: "Số lượng trang tài liệu",
  JS: "Số khóa mã ngắn (/JS)",
  JavaScript: "Số lượng kịch bản (/JavaScript)",
  OpenAction: "Khóa tự chạy khi mở tệp (/OpenAction)",
  AA: "Khóa hành động tự động (/AA)",
  Launch: "Lệnh khởi chạy chương trình ngoài (/Launch)",
  EmbeddedFiles: "Tệp đính kèm bên trong (/EmbeddedFiles)",
};

function _humanizeComponentSource(refRaw, roleRaw) {
  const ref = String(refRaw || "").trim();
  const role = String(roleRaw || "").trim();
  const combined = `${ref} ${role}`;
  if (combined.includes("names_js") || combined.includes("/Names/JavaScript")) {
    return { title: "Danh mục kịch bản (/Names/JavaScript)", sub: "Nơi lưu trữ tập trung mã JavaScript trong tệp" };
  }
  if (combined.includes("action:open_action/JS") || combined.includes("script:action:open_action")) {
    return { title: "Mã JavaScript tại /OpenAction → /JS", sub: "Đoạn mã gắn với hành động tự chạy khi mở tệp" };
  }
  if (combined.includes("action:aa/JS") || combined.includes("script:action:aa")) {
    return { title: "Mã JavaScript tại /AA → /JS", sub: "Đoạn mã gắn với sự kiện tự động của tệp hoặc trang" };
  }
  if (combined.includes("/OpenAction") || combined.includes("open_action")) {
    const objMatch = ref.match(/obj_(\d+)/i);
    return {
      title: "Khóa tự động chạy khi mở (/OpenAction)",
      sub: objMatch
        ? `Đối tượng PDF #${objMatch[1]} • Cấu hình tự chạy khi mở`
        : "Khóa kích hoạt tự động trong đối tượng gốc",
    };
  }
  if (combined.includes("/AA") || combined.includes("action:aa")) {
    return { title: "Khóa hành động bổ sung (/AA)", sub: "Cấu hình tự kích hoạt theo sự kiện trang hoặc tài liệu" };
  }
  if (combined.includes("Catalog") || combined.includes("/Trailer/Root") || ref === "obj_1 0 R") {
    return { title: "Đối tượng gốc tài liệu (/Catalog)", sub: "Gốc quản lý toàn bộ cấu trúc tệp PDF" };
  }
  if (combined.includes("annot_") || combined.includes("/Annot")) {
    return { title: "Chú thích / Liên kết trên trang (/Annot)", sub: "Thành phần gắn trên trang tài liệu" };
  }
  const cleanTitle = _formatAttackPathStepVi(role || ref);
  const cleanRef = _cleanEvidenceTextVi(ref);
  return { title: cleanTitle, sub: cleanRef !== cleanTitle ? cleanRef : "Thành phần cấu trúc bên trong tệp PDF" };
}

function _humanizeCascadeStage(st) {
  const rawTitle = String(st.title || "");
  const rawDesc = String(st.description || "");
  const numMatch = rawTitle.match(/^Điểm kiểm tra\s*(\d+)\s*:\s*(.*)$/i);
  const prefix = numMatch ? `Điểm kiểm tra ${numMatch[1]}: ` : "";
  const body = numMatch ? numMatch[2] : rawTitle;
  let friendlyBody = _cleanEvidenceTextVi(body);
  if (body.includes("action:open_action/JS") || body.includes("script:action:open_action"))
    friendlyBody = "Mã JavaScript tại /OpenAction → /JS";
  else if (body.includes("action:aa/JS") || body.includes("script:action:aa"))
    friendlyBody = "Mã JavaScript tại /AA → /JS";
  else if (body.includes("script:names_js") || body.includes("/Names/JavaScript"))
    friendlyBody = "Danh mục kịch bản (/Names/JavaScript)";
  else if (body.includes("/Catalog/OpenAction")) friendlyBody = "Khóa hành động khi mở (/Catalog/OpenAction)";
  else if (body.includes("/Catalog/AA")) friendlyBody = "Khóa hành động tự động (/Catalog/AA)";
  else if (body.includes("annot_") || body.includes("/URI")) friendlyBody = "Liên kết ngoài trên trang (/Annot → /URI)";

  const friendlyTags = (st.tags || []).map((t) => _cleanEvidenceTextVi(String(t || "").trim()));
  return { title: `${prefix}${friendlyBody}`, description: _cleanEvidenceTextVi(rawDesc), tags: friendlyTags };
}

function renderMitreCascade(stages, isMal) {
  const container = document.getElementById("mitre-cascade-container");
  if (!container) return;
  const badgeEl = document.getElementById("mitre-card-badge");
  const iconEl = document.getElementById("mitre-card-icon");
  if (badgeEl) badgeEl.textContent = `${stages ? stages.length : 0}`;
  if (iconEl) {
    setIcon(iconEl, isMal ? "security_update_warning" : "verified_user");
    iconEl.className = isMal
      ? "material-symbols-outlined text-error text-[18px]"
      : "material-symbols-outlined text-tertiary text-[18px]";
  }

  container.replaceChildren();
  if (!stages || stages.length === 0) {
    container.replaceChildren(
      dom(
        "div",
        { class: "p-4 text-center text-on-surface-variant text-xs" },
        "Chưa ghi nhận đối tượng kích hoạt hay chuỗi hành vi đáng ngờ trong tệp.",
      ),
    );
    return;
  }

  stages.forEach((st) => {
    const div = document.createElement("div");
    div.className = "relative group";
    const isCritical = st.severity === "critical";
    const isPrimary = st.severity === "primary";
    const isSecondary = st.severity === "secondary";
    const dotColor = isMal
      ? isCritical
        ? "bg-error"
        : isPrimary
          ? "bg-primary-container"
          : isSecondary
            ? "bg-slate-600"
            : "bg-tertiary"
      : "bg-tertiary";
    const humanized = _humanizeCascadeStage(st);
    const tags = humanized.tags.map((t) =>
      dom(
        "span",
        {
          class:
            "px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 text-on-surface-variant text-[10px] font-semibold",
        },
        t,
      ),
    );
    const statusLabel = st.risk_score || (isMal ? "Cần lưu ý" : "Bình thường");
    const statusColor = isMal ? (isCritical ? "text-error" : "text-on-surface-variant") : "text-tertiary";
    const targetNodeRef = st.node_id || st.object_ref || (Array.isArray(st.tags) && st.tags[1]) || "";

    div.replaceChildren(
      dom("div", { class: `absolute -left-6 top-1.5 w-4 h-4 rounded-full ${dotColor} ring-4 ring-white shadow-sm` }),
      dom(
        "div",
        { class: "p-3.5 rounded-lg bg-slate-50 space-y-1 border border-slate-200" },
        dom(
          "div",
          { class: "flex items-center justify-between gap-2" },
          dom("span", { class: "font-bold text-xs text-on-surface" }, humanized.title),
          dom("span", { class: `text-xs font-bold shrink-0 ${statusColor}` }, statusLabel),
        ),
        dom("p", { class: "text-xs text-on-surface-variant leading-relaxed" }, humanized.description),
        dom(
          "div",
          { class: "flex flex-wrap items-center justify-between gap-1.5 pt-1" },
          dom("div", { class: "flex flex-wrap items-center gap-1.5" }, tags),
          targetNodeRef &&
            dom(
              "button",
              {
                type: "button",
                dataset: { graphNode: targetNodeRef },
                class: "text-[10px] font-bold text-primary-container hover:underline",
              },
              "Xem trên sơ đồ →",
            ),
        ),
      ),
    );
    container.appendChild(div);
  });
}

function renderCrossAttentionTable(matrix) {
  const tbody = document.getElementById("cross-matrix-body");
  tbody.replaceChildren();
  if (!matrix || matrix.length === 0) {
    tbody.replaceChildren(
      dom(
        "tr",
        {},
        dom(
          "td",
          { colspan: 5, class: "p-4 text-center text-on-surface-variant text-xs" },
          "Chưa ghi nhận điểm chú ý nổi bật nào từ mô hình cho tệp này.",
        ),
      ),
    );
    return;
  }

  const tierViMap = {
    Critical: "Ảnh hưởng rất cao",
    Severe: "Ảnh hưởng cao",
    High: "Đáng chú ý",
    Normal: "Bình thường",
  };
  matrix.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 transition";
    const isCrit = r.impact_tier === "Critical";
    const isSevere = r.impact_tier === "Severe";
    const isHigh = r.impact_tier === "High";
    const heatBadgeClass = isCrit
      ? "px-2.5 py-0.5 rounded-md bg-red-50 text-error border border-red-200 font-bold text-[10px]"
      : isSevere
        ? "px-2.5 py-0.5 rounded-md bg-orange-50 text-orange-800 border border-orange-200 font-bold text-[10px]"
        : isHigh
          ? "px-2.5 py-0.5 rounded-md bg-amber-50 text-amber-800 border border-amber-200 font-bold text-[10px]"
          : "px-2.5 py-0.5 rounded-md bg-slate-100 text-on-surface-variant text-[10px]";

    const srcInfo = _humanizeComponentSource(r.source_obj_ref, r.source_role);
    let targetBadge = dom("span", { class: "font-semibold text-primary-container" }, r.target_token);
    if (r.target_token?.startsWith("AST::")) {
      const rawName = r.target_token.replace("AST::", "");
      targetBadge = dom(
        "span",
        { class: "inline-flex items-center gap-1.5 flex-wrap" },
        dom(
          "span",
          {
            class:
              "px-1.5 py-0.5 rounded-md bg-slate-100 text-slate-700 text-[10px] font-bold border border-slate-200 shrink-0",
          },
          "Cú pháp JavaScript",
        ),
        dom("span", { class: "font-semibold text-slate-900 text-xs" }, _AST_TOKEN_VI[rawName] || rawName),
      );
    } else if (r.target_token?.startsWith("Tabular::")) {
      const rawName = r.target_token.replace("Tabular::", "");
      targetBadge = dom(
        "span",
        { class: "inline-flex items-center gap-1.5 flex-wrap" },
        dom(
          "span",
          {
            class:
              "px-1.5 py-0.5 rounded-md bg-sky-50 text-sky-800 text-[10px] font-bold border border-sky-200 shrink-0",
          },
          "Chỉ số tệp",
        ),
        dom(
          "span",
          { class: "font-semibold text-sky-950 text-xs" },
          _TABULAR_FEATURE_VI[rawName] || rawName.replace(/_/g, " "),
        ),
      );
    } else if (r.target_token?.startsWith("Structure::")) {
      const rawName = r.target_token.replace("Structure::", "");
      targetBadge = dom(
        "span",
        { class: "inline-flex items-center gap-1.5 flex-wrap" },
        dom(
          "span",
          {
            class:
              "px-1.5 py-0.5 rounded-md bg-emerald-50 text-emerald-800 text-[10px] font-bold border border-emerald-200 shrink-0",
          },
          "Liên kết PDF",
        ),
        dom("span", { class: "font-semibold text-emerald-950 text-xs" }, _formatAttackPathStepVi(rawName)),
      );
    }

    const tierLabel = tierViMap[r.impact_tier] || r.impact_tier || "Bình thường";
    const scorePct = `${((r.attention_score || 0) * 100).toFixed(1)}%`;

    tr.replaceChildren(
      dom(
        "td",
        { class: "p-3 align-middle" },
        dom("div", { class: "font-bold text-on-surface text-xs" }, srcInfo.title),
        dom("div", { class: "text-[11px] text-on-surface-variant font-normal" }, srcInfo.sub),
      ),
      dom("td", { class: "p-3 align-middle" }, targetBadge),
      dom(
        "td",
        {
          class: `p-3 align-middle text-right font-bold font-mono num ${isCrit ? "text-error" : "text-on-surface-variant"}`,
          dataset: { sortValue: r.attention_score || 0 },
        },
        scorePct,
      ),
      dom(
        "td",
        { class: "p-3 align-middle" },
        dom("span", { class: `inline-flex items-center whitespace-nowrap ${heatBadgeClass}` }, tierLabel),
      ),
      dom(
        "td",
        { class: "p-3 align-middle text-right" },
        dom(
          "button",
          {
            type: "button",
            dataset: { graphNode: r.node_id },
            class:
              "px-3 py-1 rounded-md text-[11px] font-bold bg-slate-100 hover:bg-primary-container hover:text-white text-on-surface transition active:scale-95 whitespace-nowrap",
          },
          "Xem trên sơ đồ",
        ),
      ),
    );
    labelTableCells(tbody, tr);
    tbody.appendChild(tr);
  });
  resortActiveTable(tbody);
}

function updateCDRBeforeCard(data, assessment) {
  const isMal = assessment.tone === "danger";
  const needsReview = assessment.tone === "caution";
  const beforeCard = document.getElementById("card-cdr-before");
  const badgeBefore = document.getElementById("badge-cdr-before");

  beforeCard.className = isMal
    ? "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-error flex flex-col justify-between"
    : needsReview
      ? "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-amber-400 flex flex-col justify-between"
      : "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-tertiary flex flex-col justify-between";
  badgeBefore.textContent = isMal ? "CÓ CẢNH BÁO" : needsReview ? "CẦN XEM XÉT" : "ĐÃ KIỂM TRA";
  badgeBefore.className = isMal
    ? "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-red-50 text-error border border-red-200"
    : needsReview
      ? "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200"
      : "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 text-tertiary border border-emerald-200";

  document.getElementById("cdr-orig-filename").textContent = data.file_name;
  document.getElementById("cdr-orig-verdict").textContent = assessment.title;
  document.getElementById("cdr-orig-verdict").className = isMal
    ? "font-bold text-error text-right"
    : needsReview
      ? "font-bold text-amber-800 text-right"
      : "font-bold text-tertiary text-right";

  const scripts = data.forensic_dossier?.threat_scripts ? data.forensic_dossier.threat_scripts.length : 0;
  const observedObjects = (data.forensic_dossier?.trigger_objects || []).filter(
    (item) => item.is_threat_trigger,
  ).length;
  document.getElementById("cdr-orig-triggers").textContent =
    `${observedObjects} đối tượng có dấu hiệu · ${scripts} đoạn JavaScript`;
  document.getElementById("cdr-orig-pages").textContent = `${((data.file_size_bytes || 0) / 1024).toFixed(1)} KB`;
  document.getElementById("cdr-clean-filename").textContent = `sanitized_${data.file_name}`;

  const shaShort = (data.sha256 || "").substring(0, 16);
  document.getElementById("cdr-orig-sha-short").textContent = shaShort ? `${shaShort}...` : "--";
  const origStatus = document.getElementById("cdr-orig-status");
  if (origStatus) {
    origStatus.textContent = isMal || needsReview ? "Tránh mở bản gốc" : "Chỉ mở nếu tin nguồn gửi";
    origStatus.className = isMal
      ? "text-error font-semibold"
      : needsReview
        ? "text-amber-800 font-semibold"
        : "text-tertiary font-semibold";
  }
  document.getElementById("hash-ingress").textContent = data.sha256 || "--";
}
async function handleCDRFileUpload(file) {
  if (!file) return;
  document.getElementById("cdr-file-input").value = "";
  const scanId = await handleFileSelect(file);
  if (!scanId || appState.currentScanResult?.scan_id !== scanId) return;
  switchTab("cdr");
  await executeLiveCDR();
}

function resetCDRAfterCard(fileName = "document.pdf") {
  setCDRPending(false);
  const cardAfter = document.getElementById("card-cdr-after");
  if (cardAfter)
    cardAfter.className = "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-slate-300 flex flex-col justify-between";
  const badgeAfter = document.getElementById("badge-cdr-after");
  if (badgeAfter) {
    badgeAfter.textContent = "CHƯA LÀM SẠCH";
    badgeAfter.className =
      "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-slate-100 text-on-surface-variant border border-slate-200";
  }
  const cleanNameEl = document.getElementById("cdr-clean-filename");
  if (cleanNameEl) cleanNameEl.textContent = `sanitized_${fileName || "document.pdf"}`;
  const cleanVerdictEl = document.getElementById("cdr-clean-verdict");
  if (cleanVerdictEl) {
    cleanVerdictEl.textContent = "Chưa chạy";
    cleanVerdictEl.className = "font-bold text-on-surface-variant text-right";
  }
  const strippedEl = document.getElementById("cdr-stripped-count");
  if (strippedEl) strippedEl.textContent = "Chưa chạy";
  const pagesEl = document.getElementById("cdr-pages-preserved");
  if (pagesEl) pagesEl.textContent = "--";
  const textIntEl = document.getElementById("cdr-text-integrity");
  if (textIntEl) textIntEl.textContent = "--";
  document.getElementById("cdr-ssim-metric").textContent = "--";
  const hashSanEl = document.getElementById("hash-sanitized");
  if (hashSanEl) hashSanEl.textContent = "--";
  const footerBox = document.getElementById("cdr-integrity-footer");
  const footerIcon = document.getElementById("cdr-integrity-footer-icon");
  const footerText = document.getElementById("cdr-integrity-footer-text");
  if (footerBox) footerBox.className = "flex items-center gap-1 text-[11px] text-outline font-semibold";
  if (footerIcon) setIcon(footerIcon, "schedule");
  if (footerText) {
    footerText.textContent = "Chờ thực hiện làm sạch để đối chiếu nội dung và cấu trúc.";
    footerText.removeAttribute("title");
  }
  const body = document.getElementById("cdr-diff-table-body");
  if (body) {
    body.replaceChildren(
      dom(
        "tr",
        {},
        dom(
          "td",
          { colspan: 6, class: "p-6 text-center text-outline text-xs" },
          'Nhấn "Làm sạch tệp PDF ngay" ở trên để gỡ các khóa hành động theo chính sách và xem chi tiết tại đây.',
        ),
      ),
    );
  }
  const summary = document.getElementById("cdr-diff-summary");
  if (summary) summary.textContent = "0 thành phần đã gỡ";
}

function applyCDRAuditToUI(audit) {
  if (!audit?.is_sanitized || audit.quarantine_recommended || audit.scan_id !== appState.currentScanResult?.scan_id)
    return;
  appState.currentCDRAudit = audit;
  const psv = audit.post_scan_verification || {};
  const vAfter = psv.verdict_after;
  const postMal = vAfter === "MALICIOUS";
  const postBenign = vAfter === "BENIGN";

  const ratioPct = audit.size_before > 0 ? ((audit.size_after / audit.size_before) * 100).toFixed(1) : "--";
  const cardAfter = document.getElementById("card-cdr-after");
  if (cardAfter) {
    cardAfter.className = postMal
      ? "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-error flex flex-col justify-between"
      : postBenign
        ? "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-tertiary flex flex-col justify-between"
        : "glass-card rounded-xl p-4 sm:p-5 border-l-4 border-amber-400 flex flex-col justify-between";
  }
  const badgeAfter = document.getElementById("badge-cdr-after");
  if (badgeAfter) {
    badgeAfter.textContent = postMal ? "CẦN KIỂM TRA LẠI" : "ĐÃ LƯU BẢN LÀM SẠCH";
    badgeAfter.className = postMal
      ? "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-red-50 text-error border border-red-200"
      : postBenign
        ? "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-emerald-50 text-tertiary border border-emerald-200"
        : "px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200";
  }
  const cleanNameEl = document.getElementById("cdr-clean-filename");
  if (cleanNameEl) cleanNameEl.textContent = `sanitized_${audit.file_name || "document.pdf"}`;
  const cleanVerdictEl = document.getElementById("cdr-clean-verdict");
  if (cleanVerdictEl) {
    cleanVerdictEl.textContent = postMal
      ? "Vẫn có cảnh báo từ mô hình"
      : postBenign
        ? "Mô hình không cảnh báo"
        : "Chưa có kết quả quét lại";
    cleanVerdictEl.className = postMal
      ? "font-bold text-error text-right"
      : postBenign
        ? "font-bold text-tertiary text-right"
        : "font-bold text-amber-800 text-right";
  }
  const remCount = Array.isArray(audit.removed_triggers) ? audit.removed_triggers.length : 0;
  const strippedEl = document.getElementById("cdr-stripped-count");
  if (strippedEl)
    strippedEl.textContent = remCount > 0 ? `Đã gỡ ${remCount} mục theo chính sách` : "Không có khóa kích hoạt cần gỡ";
  const pagesEl = document.getElementById("cdr-pages-preserved");
  if (pagesEl) {
    const sizeSuffix = ratioPct !== "--" ? ` (${ratioPct}% dung lượng)` : "";
    pagesEl.textContent = `Giữ nguyên ${audit.sanitized_pages}/${audit.original_pages} trang${sizeSuffix}`;
  }
  const suffix = audit.text_integrity_verified === true ? " ký tự (khớp văn bản gốc)" : " ký tự";
  const textIntEl = document.getElementById("cdr-text-integrity");
  if (textIntEl) textIntEl.textContent = Number(audit.extracted_text_chars || 0).toLocaleString("vi-VN") + suffix;
  document.getElementById("cdr-ssim-metric").textContent = formatRatioPercent(audit.visual_similarity?.mean_ssim);
  const hashSanEl = document.getElementById("hash-sanitized");
  if (hashSanEl) hashSanEl.textContent = audit.sha256_after || "--";

  const footerBox = document.getElementById("cdr-integrity-footer");
  const footerIcon = document.getElementById("cdr-integrity-footer-icon");
  const footerText = document.getElementById("cdr-integrity-footer-text");
  const intact = Boolean(audit.content_streams_preserved && audit.resources_preserved && !postMal);
  if (footerBox)
    footerBox.className = `flex items-center gap-1 text-[11px] font-semibold ${intact ? "text-tertiary" : "text-amber-800"}`;
  if (footerIcon) setIcon(footerIcon, intact ? "verified_user" : "info");
  if (footerText) {
    footerText.textContent = audit.text_integrity_verified
      ? "Đã giữ nguyên luồng nội dung trang và đối chiếu văn bản trích xuất."
      : "Đã lưu bản sao loại bỏ khóa hành động; chưa đối chiếu hết văn bản trích xuất.";
    const modes = {
      full: "Full CDR",
      minimal_cut: "CF-CDR",
      full_fallback: "Đã chuyển từ CF-CDR sang Full CDR",
    };
    const preserved = audit.preserved_interactive_elements;
    if (Object.hasOwn(modes, audit.sanitization_mode))
      footerText.textContent += " " + modes[audit.sanitization_mode] + ".";
    if (Array.isArray(preserved)) {
      footerText.textContent += ` Giữ lại ${preserved.length} thành phần tương tác.`;
      footerText.title = preserved.join(", ");
    } else {
      footerText.removeAttribute("title");
    }
  }

  renderCDRDiffMatrix(audit);
  setCDRPending(appState.disarmingScans.has(audit.scan_id));
}

function selectedCDRMode() {
  return document.getElementById("cdr-mode-select")?.value === "minimal_cut" ? "minimal_cut" : "full";
}

function hasCompletedCDRMode(scanId, mode) {
  const audit = appState.currentCDRAudit;
  return Boolean(scanId && audit?.scan_id === scanId && (audit.sanitization_mode ?? "full") === mode);
}

function setCDRPending(pending) {
  const scanId = appState.currentScanResult?.scan_id;
  const completed = !pending && !appState.unconfirmedCDR.has(scanId) && hasCompletedCDRMode(scanId, selectedCDRMode());
  const button = document.getElementById("btn-execute-disarm");
  button.disabled = pending;
  button.setAttribute("aria-busy", String(pending));
  button.classList.toggle("bg-tertiary", completed);
  button.classList.toggle("bg-primary-container", !completed);
  document.getElementById("cdr-mode-select").disabled = pending;
  document.getElementById("btn-quick-disarm").disabled = pending;
  document.getElementById("btn-download-sanitized").disabled =
    pending || !appState.currentCDRAudit || appState.unconfirmedCDR.has(scanId);
  document.getElementById("cdr-disarm-scan-overlay").classList.toggle("hidden", !pending);
  const icon = document.getElementById("cdr-disarm-icon");
  setIcon(icon, pending ? "progress_activity" : completed ? "verified" : "healing");
  icon.classList.toggle("animate-spin", pending);
  document.getElementById("btn-disarm-text").textContent = pending
    ? "Đang kiểm tra và làm sạch cấu trúc PDF..."
    : completed
      ? "Đã làm sạch tệp"
      : "Làm sạch tệp PDF ngay";
}

async function readCDRStatus(scanId) {
  const res = await fetch(`/api/scans/${scanId}?include_preview_images=false`, { cache: "no-store" });
  if (res.status === 404) throw new Error("Lượt quét đã hết hạn. Hãy chọn lại tệp PDF.");
  if (!res.ok) throw new Error("Chưa xác nhận được trạng thái lượt quét.");
  const job = await res.json();
  if (job.status === "DISARMING") throw new Error("Máy chủ vẫn đang làm sạch. Hãy kiểm tra lại sau.");
  if (job.has_sanitized && job.cdr_audit?.is_sanitized && !job.cdr_audit.quarantine_recommended) {
    return { ...job.cdr_audit, scan_id: job.scan_id };
  }
  return null;
}

function confirmsCDRAttempt(audit, attempt) {
  if (!audit) return false;
  const mode = audit.sanitization_mode ?? "full";
  if (mode !== attempt.mode && !(attempt.mode === "minimal_cut" && mode === "full_fallback")) return false;
  const previous = attempt.previousAudit;
  return (
    !previous ||
    mode !== (previous.sanitization_mode ?? "full") ||
    audit.sha256_after !== previous.sha256_after ||
    audit.disarm_latency_ms !== previous.disarm_latency_ms
  );
}

async function executeLiveCDR() {
  const scanId = appState.currentScanResult?.scan_id;
  if (!scanId) {
    showToast("Hãy tải tệp PDF lên trước khi làm sạch tệp.", "warning");
    return;
  }
  const cdrMode = selectedCDRMode();
  if (appState.disarmingScans.has(scanId)) return;
  if (!appState.unconfirmedCDR.has(scanId) && hasCompletedCDRMode(scanId, cdrMode)) return;
  const previousAudit = appState.currentCDRAudit;
  appState.disarmingScans.add(scanId);
  setCDRPending(true);
  try {
    let audit;
    const unconfirmed = appState.unconfirmedCDR.get(scanId);
    if (unconfirmed) {
      const savedAudit = await readCDRStatus(scanId);
      appState.unconfirmedCDR.delete(scanId);
      if (appState.currentScanResult?.scan_id !== scanId) return;
      if (savedAudit) {
        applyCDRAuditToUI(savedAudit);
        if (
          hasCompletedCDRMode(scanId, cdrMode) ||
          (unconfirmed.mode === cdrMode && confirmsCDRAttempt(savedAudit, unconfirmed))
        ) {
          audit = savedAudit;
        }
      } else if (appState.currentCDRAudit) {
        appState.currentCDRAudit = null;
        resetCDRAfterCard(appState.currentScanResult.file_name);
        setCDRPending(true);
        clearVisualDiff();
      }
    }
    if (!audit) {
      const attempt = { mode: cdrMode, previousAudit: appState.currentCDRAudit };
      const modeQuery = cdrMode === "full" && !attempt.previousAudit ? "" : `mode=${encodeURIComponent(cdrMode)}&`;
      try {
        const res = await fetch(`/api/disarm/${scanId}?${modeQuery}include_preview_images=false`, { method: "POST" });
        if (res.status === 404) throw new Error("Lượt quét đã hết hạn. Hãy chọn lại tệp PDF.");
        if (!res.ok && res.status < 500) {
          const err = await res.json().catch(() => ({}));
          throw new Error(_formatApiErrorVi(res.status, err.detail) || `Mã lỗi ${res.status}`);
        }
        if (!res.ok) throw new TypeError(`Mã lỗi ${res.status}`);
        audit = await res.json();
      } catch (err) {
        if (!(err instanceof TypeError || err instanceof SyntaxError)) throw err;
        appState.unconfirmedCDR.set(scanId, attempt);
        if (appState.currentScanResult?.scan_id !== scanId) return;
        const savedAudit = await readCDRStatus(scanId);
        if (confirmsCDRAttempt(savedAudit, attempt)) audit = savedAudit;
      }
    }
    if (appState.currentScanResult?.scan_id !== scanId) return;
    if (
      appState.currentCDRAudit &&
      audit?.scan_id === scanId &&
      (!audit.is_sanitized || audit.quarantine_recommended)
    ) {
      appState.currentCDRAudit = null;
      clearVisualDiff();
    }
    if (!audit?.is_sanitized || audit.quarantine_recommended || audit.scan_id !== scanId) {
      throw new Error("Chưa xác nhận được bản PDF đã làm sạch.");
    }
    appState.unconfirmedCDR.delete(scanId);
    applyCDRAuditToUI(audit);
    const remCount = Array.isArray(audit.removed_triggers) ? audit.removed_triggers.length : 0;
    const cdrDoneMsg =
      remCount > 0
        ? `Đã làm sạch tệp: gỡ ${remCount} khóa kích hoạt và giữ nguyên ${audit.sanitized_pages} trang.`
        : `Đã làm sạch tệp: không ghi nhận khóa kích hoạt cần gỡ, giữ nguyên ${audit.sanitized_pages} trang.`;
    showToast(cdrDoneMsg, "success");
    if (audit.ai_threat_explanation) renderAIExplainer(audit.ai_threat_explanation, false, appState.currentScanResult);
  } catch (err) {
    if (appState.currentScanResult?.scan_id === scanId) {
      if (!appState.currentCDRAudit) resetCDRAfterCard(appState.currentScanResult.file_name);
      showToast("Không thể làm sạch tệp: " + err.message, "error");
    }
  } finally {
    appState.disarmingScans.delete(scanId);
    if (appState.currentScanResult?.scan_id === scanId) {
      setCDRPending(false);
      if (previousAudit !== appState.currentCDRAudit) {
        appState.visualDiffCache.clear();
        if (appState.activeTab === "cdr") loadVisualDiff(appState.currentDiffPage);
      }
    }
    fetchScanHistory();
  }
}

function renderCDRDiffMatrix(audit) {
  const body = document.getElementById("cdr-diff-table-body");
  if (!body) return;
  body.replaceChildren();
  const removedList = Array.isArray(audit.removed_triggers) ? audit.removed_triggers : [];
  const summary = document.getElementById("cdr-diff-summary");
  if (summary) summary.textContent = `${removedList.length} mục đã gỡ bỏ`;
  const entries = audit.object_diff_matrix || [];
  const values = entries.map((item) => [
    item.object_id,
    item.object_type,
    item.diagnosis,
    item.cdr_action,
    item.status,
    item.visual_impact ?? "Chưa đo riêng",
  ]);
  values.push([
    "Các trang tài liệu",
    "Chữ viết, hình ảnh & bố cục",
    `${audit.sanitized_pages}/${audit.original_pages} trang`,
    audit.content_streams_preserved && audit.resources_preserved
      ? "Giữ nguyên luồng nội dung & tài nguyên"
      : "Chưa xác minh đầy đủ",
    "Đã giữ nguyên",
    audit.text_integrity_verified === true ? "Văn bản trích xuất khớp 100%" : "Chưa đối chiếu văn bản",
  ]);
  for (const cells of values) {
    const row = document.createElement("tr");
    cells.forEach((value, idx) => {
      const cell = document.createElement("td");
      cell.className = idx === cells.length - 1 ? "p-3 text-xs text-right" : "p-3 text-xs";
      cell.textContent = value ?? "--";
      row.appendChild(cell);
    });
    labelTableCells(body, row);
    body.appendChild(row);
  }
}

function downloadSanitizedPDF() {
  if (
    appState.currentCDRAudit?.is_sanitized &&
    appState.currentCDRAudit.scan_id === appState.currentScanResult?.scan_id
  ) {
    window.location.href = `/api/download/sanitized/${appState.currentCDRAudit.scan_id}`;
  }
}

async function loadMailGatewayHistory() {
  const spinner = document.getElementById("mail-spinner");
  if (spinner) spinner.hidden = false;
  try {
    const response = await fetch("/api/gateway/history");
    if (!response.ok) throw new Error(`Mã lỗi ${response.status}`);
    const data = await response.json();
    document.getElementById("mail-total").textContent = data.summary.total_emails;
    document.getElementById("mail-quarantined").textContent = data.summary.intercepted_threats;
    document.getElementById("mail-passed").textContent = data.summary.passed_clean;
    document.getElementById("mail-avg-latency").textContent = Number.isFinite(data.summary.avg_latency_ms)
      ? data.summary.avg_latency_ms.toFixed(1) + " ms"
      : "--";
    const body = document.getElementById("mail-stream-body");
    body.replaceChildren();
    for (const record of data.results) {
      const row = document.createElement("tr");
      row.className = "hover:bg-surface-container-low/50 transition";
      const actionVi =
        {
          SANITIZED_ATTACHMENT: "Đã làm sạch tệp đính kèm",
          DISARMED_AND_QUARANTINED: "Đã làm sạch tệp đính kèm",
          DELIVERED_CLEAN: "Đã kiểm tra (không có PDF vượt ngưỡng)",
          PASSED: "Đã kiểm tra (dưới ngưỡng)",
          HELD_FOR_REVIEW: "Cần kiểm tra thêm",
        }[record.action] || "Trạng thái khác";
      [
        record.msg_id,
        record.subject,
        record.sender_full || record.sender,
        record.attachment,
        actionVi,
        Number(record.latency_ms || 0).toFixed(1) + " ms",
      ].forEach((value, idx) => {
        const cell = document.createElement("td");
        cell.className = idx === 5 ? "p-3 text-xs text-right font-mono num" : "p-3 text-xs";
        cell.textContent = value;
        row.appendChild(cell);
      });
      const dlCell = document.createElement("td");
      dlCell.className = "p-3 text-right";
      if (record.eml_job_id && record.action !== "HELD_FOR_REVIEW") {
        dlCell.replaceChildren(
          dom(
            "a",
            {
              href: `/api/gateway/download/eml/${encodeURIComponent(record.eml_job_id)}`,
              class:
                "px-3 py-1 rounded-full text-[11px] font-bold bg-secondary/15 text-secondary hover:bg-secondary hover:text-white transition inline-flex items-center gap-1",
            },
            iconNode("download", "text-[13px]"),
            dom("span", {}, "Tải .eml sạch"),
          ),
        );
      } else {
        dlCell.textContent = "--";
      }
      row.appendChild(dlCell);
      labelTableCells(body, row);
      body.appendChild(row);
    }
    if (!data.results.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 7;
      cell.className = "p-5 text-center text-outline text-xs";
      cell.textContent =
        'Chưa có email nào được kiểm tra trong phiên này. Hãy bấm nút "Tải tệp .eml / .pdf lên kiểm tra" hoặc "Kiểm thử Email với tệp PDF hiện tại" ở góc trên.';
    }
  } catch (error) {
    showToast("Không đọc được lịch sử kiểm tra email: " + error.message, "error");
  } finally {
    if (spinner) spinner.hidden = true;
  }
}

async function fetchSiemLogs() {
  try {
    const res = await fetch("/api/audit/logs");
    const data = await res.json();
    document.getElementById("siem-total-events").textContent = data.stats.total_events;
    document.getElementById("siem-threats-flagged").textContent = data.stats.threats_flagged;
    document.getElementById("siem-files-disarmed").textContent = data.stats.files_disarmed;
    document.getElementById("siem-avg-lat").textContent = Number.isFinite(data.stats.avg_latency_ms)
      ? data.stats.avg_latency_ms.toFixed(1) + " ms"
      : "0.0 ms";

    const tbody = document.getElementById("siem-stream-body");
    tbody.replaceChildren();
    if (!data.logs || data.logs.length === 0) {
      tbody.replaceChildren(
        dom(
          "tr",
          {},
          dom(
            "td",
            { colspan: 7, class: "p-6 text-center text-outline text-xs" },
            "Chưa có hoạt động nào được ghi nhận.",
          ),
        ),
      );
      return;
    }

    const eventViMap = {
      SCAN_COMPLETED: "Kiểm tra tệp PDF",
      DISARM_COMPLETED: "Làm sạch tệp PDF (CDR)",
      QUARANTINE_ISOLATED: "Lưu bản gốc vào khu cách ly",
      XAI_ABLATION: "Gỡ thử thành phần trên bản sao",
      EML_INSPECTION: "Kiểm tra & làm sạch Email (.eml)",
      JOB_CREATED: "Tiếp nhận tệp tải lên",
      STATUS_CHANGED: "Cập nhật trạng thái xử lý",
      JOB_DELETED: "Xóa tệp khỏi danh sách",
      PDF_SCAN: "Kiểm tra tệp PDF",
      CDR_DISARM: "Làm sạch tệp PDF",
      EML_INSPECT: "Kiểm tra tệp Email",
      XAI_ABLATE: "Thử tách thành phần",
    };
    const verdictViMap = {
      MALICIOUS: "Vượt ngưỡng",
      BENIGN: "Dưới ngưỡng",
      PENDING: "Đang xử lý",
      UNAVAILABLE: "Chưa có điểm",
    };
    const siemActionViMap = {
      SANITIZED_ATTACHMENT: "Đã làm sạch tệp đính kèm",
      DISARMED_AND_QUARANTINED: "Đã làm sạch & cách ly bản gốc",
      DELIVERED_CLEAN: "Đã kiểm tra (dưới ngưỡng)",
      PASSED: "Đã kiểm tra (dưới ngưỡng)",
      HELD_FOR_REVIEW: "Giữ lại kiểm tra thêm",
      CREATED: "Đã tiếp nhận",
      SCANNING: "Đang kiểm tra",
      SCANNED: "Đã kiểm tra",
      DISARMING: "Đang làm sạch",
      DISARMED: "Đã làm sạch",
      ABLATED: "Đã gỡ thử thành phần",
      DELETED: "Đã xóa khỏi phiên",
    };

    data.logs.forEach((entry) => {
      const row = document.createElement("tr");
      row.className = "hover:bg-surface-container-low/50 transition";
      const detail = entry.details || {};
      const evLabel = eventViMap[entry.event] || entry.event || "--";
      const verLabel = verdictViMap[detail.verdict] || detail.verdict || "--";
      const rawOutcome = detail.action || detail.status || "";
      const outcomeLabel =
        siemActionViMap[rawOutcome] || (/^[A-Z0-9_]+$/.test(rawOutcome) ? "Hoàn tất" : rawOutcome || "Hoàn tất");
      const cols = [
        entry.event_id || "--",
        (entry.timestamp || "").replace("T", " ").substring(0, 19),
        evLabel,
        detail.file_name || detail.subject || detail.scan_id || "--",
        verLabel,
        outcomeLabel,
        Number.isFinite(detail.latency_ms) ? detail.latency_ms.toFixed(1) + " ms" : "--",
      ];
      cols.forEach((value, idx) => {
        const cell = document.createElement("td");
        cell.className = idx === 6 ? "p-3 text-xs text-right font-mono num" : "p-3 text-xs";
        if (idx === 6 && Number.isFinite(detail.latency_ms)) cell.dataset.sortValue = detail.latency_ms;
        cell.textContent = value;
        row.appendChild(cell);
      });
      labelTableCells(tbody, row);
      tbody.appendChild(row);
    });
    resortActiveTable(tbody);
  } catch (err) {
    console.error("Lỗi tải nhật ký hoạt động:", err);
  }
}

function exportForensicJSON() {
  const scanId = appState.currentScanResult?.scan_id;
  window.location.href = scanId ? `/api/report/export?scan_id=${encodeURIComponent(scanId)}` : "/api/report/export";
}

async function exportSiemJSON() {
  try {
    const res = await fetch("/api/audit/logs");
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nhat_ky_kiem_tra_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    showToast("Không thể tải xuống nhật ký: " + err.message, "error");
  }
}
async function loadHealthTelemetry() {
  const dotEl = document.getElementById("telemetry-dot");
  const statusLabelEl = document.getElementById("telemetry-status-label");
  const infoEl = document.getElementById("telemetry-model-info");
  const footerTorch = document.getElementById("footer-torch");
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    appState.gzipScanUpload = data.gzip_scan_upload === true;
    if (Number.isFinite(data.max_upload_bytes) && data.max_upload_bytes > 0) {
      appState.maxUploadBytes = data.max_upload_bytes;
      const hintEl = document.getElementById("upload-max-mb-hint");
      if (hintEl) hintEl.textContent = `${Math.max(1, Math.round(appState.maxUploadBytes / (1024 * 1024)))} MB`;
    }
    const ok = Boolean(data.prediction_available);
    if (dotEl) {
      dotEl.className = ok ? "w-2 h-2 rounded-full bg-tertiary" : "w-2 h-2 rounded-full bg-amber-500";
    }
    if (statusLabelEl) {
      statusLabelEl.textContent = ok ? "Sẵn sàng kiểm tra" : "Chế độ tĩnh";
      statusLabelEl.className = ok ? "text-tertiary font-bold" : "text-amber-700 font-bold";
    } else if (infoEl) {
      infoEl.replaceChildren(
        "Sẵn sàng kiểm tra • ",
        dom(
          "span",
          {
            id: "telemetry-latency",
            class: "num text-tertiary font-bold",
          },
          ok ? "Đang hoạt động" : "Chế độ tĩnh",
        ),
      );
    }
    const latEl = document.getElementById("telemetry-latency");
    if (latEl) latEl.textContent = ok ? "Đang hoạt động" : "Chưa nạp mô hình";
    if (footerTorch) {
      footerTorch.textContent = ok ? "Hệ thống hoạt động ổn định" : "Chế độ phân tích tĩnh (chưa chấm điểm mô hình)";
    }
  } catch (err) {
    if (dotEl) dotEl.className = "w-2 h-2 rounded-full bg-error";
    if (statusLabelEl) {
      statusLabelEl.textContent = "Mất kết nối máy chủ";
      statusLabelEl.className = "text-error font-bold";
    }
    if (footerTorch) footerTorch.textContent = "Không kết nối được máy chủ";
    console.warn("Health check unavailable:", err);
  }
}

async function fetchScanHistory() {
  const request = ++appState.historyRequest;
  try {
    const res = await fetch("/api/scans", { cache: "no-store" });
    if (!res.ok) return;
    const jobs = await res.json();
    if (request === appState.historyRequest) renderVerticalQueue(jobs);
  } catch (err) {
    console.warn("Failed to fetch scan history:", err);
  }
}

async function loadScanJob(scanId) {
  if (document.getElementById("dropzone")?.dataset.scanning) return;
  const scanToken = ++appState.activeScanToken;
  try {
    const res = await fetch(`/api/scans/${scanId}?include_preview_images=false`, { cache: "no-store" });
    if (!res.ok) throw new Error("Không tìm thấy kết quả này");
    const job = await res.json();
    if (scanToken !== appState.activeScanToken || !job.scan_result) return;
    const audit = job.has_sanitized && job.cdr_audit ? { ...job.cdr_audit, scan_id: job.scan_id } : null;
    renderScanResult({ ...job.scan_result, scan_id: job.scan_id }, audit);
  } catch (err) {
    if (scanToken === appState.activeScanToken) showToast("Không thể mở lại kết quả kiểm tra: " + err.message, "error");
  }
}

function clearVisualDiff() {
  appState.previewRequest?.abort();
  appState.previewRequest = null;
  appState.visualDiffCache.clear();
  appState.totalDiffPages = 1;
  appState.currentDiffPage = 0;
  document.getElementById("diff-page-indicator").textContent = "Trang 1 / 1";
  for (const id of ["diff-orig-img", "diff-clean-img", "diff-split-orig-img", "diff-split-clean-img"]) {
    document.getElementById(id).removeAttribute("src");
  }
  for (const id of ["diff-orig-img", "diff-clean-img", "diff-status", "diff-retry"]) {
    document.getElementById(id).classList.add("hidden");
  }
  for (const id of ["diff-orig-placeholder", "diff-clean-placeholder", "diff-split-placeholder"]) {
    document.getElementById(id).classList.remove("hidden");
  }
}

async function loadVisualDiff(page = 0) {
  const scanId = appState.currentScanResult?.scan_id;
  if (!scanId) return;
  appState.previewRequest?.abort();
  const controller = new AbortController();
  appState.previewRequest = controller;
  appState.currentDiffPage = page;
  const cleanVersion = appState.currentCDRAudit?.sha256_after;
  const cacheKey = `${scanId}:${page}:${cleanVersion || "original"}`;
  const status = document.getElementById("diff-status");
  const retry = document.getElementById("diff-retry");
  status.classList.add("hidden");
  retry.classList.add("hidden");
  try {
    let diff = appState.visualDiffCache.get(cacheKey);
    if (!diff) {
      const res = await fetch(`/api/diff/render/${scanId}?page=${page}`, {
        signal: controller.signal,
        cache: "no-store",
      });
      if (!res.ok) throw new Error(`Mã lỗi ${res.status}`);
      diff = await res.json();
      if (controller.signal.aborted) return;
      if (diff.scan_id !== scanId || !diff.original_render_uri || (cleanVersion && !diff.sanitized_render_uri)) {
        throw new Error("Preview chưa sẵn sàng");
      }
      const imageChars = diff.original_render_uri.length + (diff.sanitized_render_uri?.length || 0);
      if (imageChars <= 2_000_000) {
        if (appState.visualDiffCache.size >= 4)
          appState.visualDiffCache.delete(appState.visualDiffCache.keys().next().value);
        appState.visualDiffCache.set(cacheKey, diff);
      }
    }
    appState.totalDiffPages = Math.max(1, Number(diff.total_pages || 1));
    appState.currentDiffPage = Math.max(0, Math.min(appState.totalDiffPages - 1, Number(diff.page || 0)));

    const origImg = document.getElementById("diff-orig-img");
    const cleanImg = document.getElementById("diff-clean-img");
    const origPl = document.getElementById("diff-orig-placeholder");
    const cleanPl = document.getElementById("diff-clean-placeholder");
    const indicator = document.getElementById("diff-page-indicator");
    if (indicator) indicator.textContent = `Trang ${appState.currentDiffPage + 1} / ${appState.totalDiffPages}`;

    const splitOrig = document.getElementById("diff-split-orig-img");
    const splitClean = document.getElementById("diff-split-clean-img");
    const splitPl = document.getElementById("diff-split-placeholder");

    if (diff.original_render_uri) {
      if (origImg) {
        origImg.src = diff.original_render_uri;
        origImg.classList.remove("hidden");
      }
      if (origPl) origPl.classList.add("hidden");
      if (splitOrig) splitOrig.src = diff.original_render_uri;
    }
    if (diff.sanitized_render_uri) {
      if (cleanImg) {
        cleanImg.src = diff.sanitized_render_uri;
        cleanImg.classList.remove("hidden");
      }
      if (cleanPl) cleanPl.classList.add("hidden");
      if (splitClean) splitClean.src = diff.sanitized_render_uri;
      if (splitPl) splitPl.classList.add("hidden");
      updateSplitSliderPosition(appState.diffSplitPercent);
    } else {
      if (cleanImg) cleanImg.classList.add("hidden");
      if (cleanPl) cleanPl.classList.remove("hidden");
      if (splitClean) splitClean.removeAttribute("src");
      if (splitPl) splitPl.classList.remove("hidden");
    }
  } catch (_err) {
    if (controller.signal.aborted) return;
    status.textContent = `Chưa tải được ảnh xem trước trang ${page + 1}.`;
    status.classList.remove("hidden");
    retry.classList.remove("hidden");
  }
}

function changeDiffPage(delta) {
  loadVisualDiff(Math.max(0, Math.min(appState.totalDiffPages - 1, appState.currentDiffPage + delta)));
}
async function handleEMLUpload(file) {
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch("/api/gateway/inspect-eml", { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(_formatApiErrorVi(res.status, err.detail) || `Mã lỗi ${res.status}`);
    }
    const data = await res.json();
    renderEMLInspectionResult(data);
    const held = (data.unavailable_attachments || 0) > 0 || data.action_taken === "HELD_FOR_REVIEW";
    showToast(
      held
        ? `Thư "${data.subject || file.name}" có tệp chưa xác minh — cần kiểm tra thêm.`
        : `Đã kiểm tra thư "${data.subject || file.name}".`,
      held ? "warning" : "success",
    );
    loadMailGatewayHistory();
  } catch (err) {
    showToast("Không thể kiểm tra tệp email: " + err.message, "error");
  } finally {
    const f2 = document.getElementById("mail-tab-file-input");
    if (f2) f2.value = "";
  }
}

async function inspectActiveJobViaMailGateway() {
  const icon = document.getElementById("mail-active-job-icon");
  const text = document.getElementById("mail-active-job-text");
  const btn = document.getElementById("btn-inspect-active-job-mail");
  if (icon) {
    setIcon(icon, "progress_activity");
    icon.classList.add("animate-spin");
  }
  if (text) text.textContent = "Đang đóng gói & quét qua Cổng Email...";
  if (btn) btn.disabled = true;
  try {
    const scanId = appState.currentScanResult?.scan_id || appState.currentCDRAudit?.scan_id;
    const url = scanId ? `/api/gateway/inspect-job/${scanId}` : "/api/gateway/inspect-job";
    const res = await fetch(url, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(
        _formatApiErrorVi(res.status, err.detail) || "Hãy tải một tệp PDF lên trước khi kiểm thử Cổng Email",
      );
    }
    const data = await res.json();
    renderEMLInspectionResult(data);
    await loadMailGatewayHistory();
    const actionTaken = data.action_taken || data.action;
    if (actionTaken === "HELD_FOR_REVIEW") {
      showToast("Cổng Email đã giữ thư lại để kiểm tra thêm do có tệp chưa xác minh được.", "warning");
    } else if (actionTaken === "SANITIZED_ATTACHMENT") {
      showToast("Cổng Email đã quét và làm sạch tệp PDF đính kèm.", "success");
    } else {
      showToast("Cổng Email đã kiểm tra thư; không có PDF đính kèm vượt ngưỡng.", "success");
    }
  } catch (err) {
    showToast("Không thể kiểm thử Cổng Email: " + err.message, "warning");
  } finally {
    if (icon) {
      setIcon(icon, "forward_to_inbox");
      icon.classList.remove("animate-spin");
    }
    if (text) text.textContent = "Kiểm thử Email với tệp PDF hiện tại";
    if (btn) btn.disabled = false;
  }
}

function switchSiemSubTab(sub) {
  const btnFeed = document.getElementById("subtab-siem-feed");
  const btnVault = document.getElementById("subtab-siem-vault");
  updateTabs(document.getElementById("siem-tablist"), sub);
  if (sub === "vault") {
    btnFeed.className =
      "px-3.5 py-1.5 rounded-md text-xs font-bold text-on-surface-variant hover:text-on-surface transition";
    btnVault.className = "px-3.5 py-1.5 rounded-md text-xs font-bold bg-error text-white shadow-xs transition";
    fetchQuarantineVault();
  } else {
    btnFeed.className =
      "px-3.5 py-1.5 rounded-md text-xs font-bold bg-white text-primary-container shadow-xs border border-slate-200 transition";
    btnVault.className =
      "px-3.5 py-1.5 rounded-md text-xs font-bold text-on-surface-variant hover:text-on-surface transition";
    fetchSiemLogs();
  }
}

async function fetchQuarantineVault() {
  try {
    const res = await fetch("/api/quarantine/list");
    const list = await res.json();
    const tbody = document.getElementById("quarantine-stream-body");
    if (!tbody) return;
    tbody.replaceChildren();
    if (!list || list.length === 0) {
      tbody.replaceChildren(
        dom(
          "tr",
          {},
          dom(
            "td",
            { colspan: 5, class: "p-6 text-center text-outline text-xs" },
            "Hiện chưa có tệp đáng ngờ nào trong khu cách ly.",
          ),
        ),
      );
      return;
    }
    list.forEach((q) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-red-50/70 transition";
      tr.replaceChildren(
        dom("td", { class: "p-3 font-semibold text-on-surface" }, q.file_name),
        dom("td", { class: "p-3 text-error font-mono font-bold" }, `${q.sha256_prefix ?? ""}…`),
        dom(
          "td",
          { class: "p-3 text-right text-on-surface-variant font-mono num", dataset: { sortValue: q.size_bytes || 0 } },
          formatBytesVi(q.size_bytes || 0),
        ),
        dom("td", { class: "p-3 text-outline text-xs num" }, (q.quarantined_at || "").replace("T", " ").slice(0, 19)),
        dom(
          "td",
          { class: "p-3 text-right" },
          dom(
            "a",
            {
              href: `/api/quarantine/download/${encodeURIComponent(q.stored_name)}`,
              class:
                "px-3 py-1 rounded-md text-xs font-bold bg-red-50 text-error border border-red-200 hover:bg-error hover:text-white transition inline-flex items-center gap-1",
            },
            iconNode("download", "text-[14px]"),
            dom("span", {}, "Tải bản gốc (chưa làm sạch)"),
          ),
        ),
      );
      labelTableCells(tbody, tr);
      tbody.appendChild(tr);
    });
    resortActiveTable(tbody);
  } catch (err) {
    console.warn("Failed to fetch quarantine vault:", err);
  }
}

let graphModule;
let graphImport;
let tabTransition;
let tabRequest = 0;

function loadGraphModule() {
  graphImport ??= import("./dashboard-graph.js")
    .then((module) => {
      module.wireGraphControls();
      graphModule = module;
      return module;
    })
    .catch((error) => {
      graphImport = undefined;
      throw error;
    });
  return graphImport;
}

async function showCurrentGraph() {
  try {
    const graph = await loadGraphModule();
    if (appState.activeTab === "graph") await graph.showCurrentGraph();
  } catch {
    document.getElementById("graph-load-status").textContent =
      "Không tải được sơ đồ. Bấm lại tab Sơ đồ cấu trúc để thử lại.";
  }
}

async function inspectAndAblateNode(nodeId) {
  await switchTab("graph");
  if (appState.activeTab === "graph") await graphModule?.inspectAndAblateNode(nodeId);
}

async function switchTab(tab, { updateUrl = true, transition = true, fromTabButton = false } = {}) {
  const tabs = document.getElementById("primary-tablist");
  const button = document.getElementById("tab-" + tab);
  if (!tabs.contains(button)) return;
  const previous = appState.activeTab;
  const previousPanel = document.getElementById("view-" + previous);
  const request = ++tabRequest;
  tabTransition?.skipTransition();
  const apply = () => {
    if (request !== tabRequest) return;
    const restoreFocus = !fromTabButton && previous !== tab && previousPanel.contains(document.activeElement);
    if (previous === "graph" && tab !== "graph") {
      graphModule?._stopGraphCanvasAnimation();
      graphModule?.toggleGraphControlsPopover(false);
    }
    appState.activeTab = tab;
    if (tab !== "cdr") appState.previewRequest?.abort();
    updateTabs(tabs, tab);
    for (const item of tabs.querySelectorAll('[role="tab"]')) {
      item.classList.toggle("nav-tab-active", item === button);
      if (item === button) item.setAttribute("aria-current", "true");
      else item.removeAttribute("aria-current");
    }
    if (updateUrl) {
      const url = new URL(location.href);
      if (tab === "scan") url.searchParams.delete("tab");
      else url.searchParams.set("tab", tab);
      history.replaceState(history.state, "", url);
    }
    if (restoreFocus) button.focus({ preventScroll: true });
  };
  if (previous !== tab && transition && document.startViewTransition && !prefersReducedMotion()) {
    const viewTransition = document.startViewTransition(apply);
    tabTransition = viewTransition;
    await viewTransition.updateCallbackDone;
    if (tabTransition === viewTransition) tabTransition = undefined;
  } else apply();
  if (request !== tabRequest) return;
  if (tab === "graph") await showCurrentGraph();
  if (tab === "cdr") loadVisualDiff(appState.currentDiffPage || 0);
  if (tab === "mail") loadMailGatewayHistory();
  if (tab === "siem") {
    const selected = document.querySelector('#siem-tablist [aria-selected="true"]').dataset.tab;
    if (selected === "vault") fetchQuarantineVault();
    else fetchSiemLogs();
  }
}

function switchEvidenceTab(tab) {
  const tablist = document.getElementById("evidence-tablist");
  updateTabs(tablist, tab, true);
  for (const button of tablist.querySelectorAll('[role="tab"]')) {
    button.className =
      button.dataset.tab === tab
        ? "px-3.5 py-1 rounded-md bg-white text-primary-container shadow-xs border border-slate-200 transition flex items-center gap-1.5"
        : "px-3.5 py-1 rounded-md text-on-surface-variant hover:text-on-surface transition flex items-center gap-1.5";
  }
}

function wireTablist(tablistEl, onSelect, { activateOnFocus }) {
  const buttons = Array.from(tablistEl.querySelectorAll('[role="tab"]'));
  const tabFromEvent = (event) => event.target.closest('[role="tab"]');
  const select = (button) => {
    if (button && buttons.includes(button)) onSelect(button.dataset.tab);
  };
  tablistEl.addEventListener("click", (event) => {
    const button = tabFromEvent(event);
    if (!activateOnFocus || button?.getAttribute("aria-selected") !== "true") select(button);
  });
  if (activateOnFocus)
    tablistEl.addEventListener("focusin", (event) => {
      const button = tabFromEvent(event);
      if (button?.getAttribute("aria-selected") === "false") select(button);
    });
  tablistEl.addEventListener("keydown", (event) => {
    const current = tabFromEvent(event);
    const index = buttons.indexOf(current);
    if (index < 0) return;
    const positions = {
      ArrowLeft: (index + buttons.length - 1) % buttons.length,
      ArrowRight: (index + 1) % buttons.length,
      Home: 0,
      End: buttons.length - 1,
    };
    if (!Object.hasOwn(positions, event.key)) return;
    event.preventDefault();
    const next = buttons[positions[event.key]];
    for (const button of buttons) button.tabIndex = button === next ? 0 : -1;
    next.focus();
  });
}

function labelTableCells(tbody, row) {
  const headers = tbody.closest("table").tHead.rows[0].cells;
  row.setAttribute("role", "row");
  for (const cell of row.cells) {
    cell.setAttribute("role", "cell");
    const header = headers[cell.cellIndex];
    cell.dataset.label = header.dataset.colLabel || header.textContent.trim();
  }
}

const tableCollator = new Intl.Collator("vi", { numeric: true, sensitivity: "base" });

function numericSortValue(cell) {
  if (cell.dataset.sortValue !== undefined) return Number(cell.dataset.sortValue);
  const text = cell.textContent.trim();
  const value = Number.parseFloat(text.replace(/[^\d.-]/g, ""));
  const unit = text.slice(-2).toUpperCase();
  return value * (unit === "MB" ? 1024 ** 2 : unit === "KB" ? 1024 : 1);
}

function sortTableRows(tbody, th, direction) {
  const rows = Array.from(tbody.rows).filter((row) => row.cells.length > 1);
  if (rows.length <= 1) return;
  const columnIndex = th.cellIndex;
  const numeric = th.dataset.type === "number";
  const order = direction === "ascending" ? 1 : -1;
  const entries = rows.map((row) => {
    const cell = row.cells[columnIndex];
    return { row, value: numeric ? numericSortValue(cell) : cell.textContent.trim() };
  });
  entries.sort((a, b) => {
    if (!numeric) return order * tableCollator.compare(a.value, b.value);
    if (!Number.isFinite(a.value)) return Number.isFinite(b.value) ? 1 : 0;
    if (!Number.isFinite(b.value)) return -1;
    return order * (a.value - b.value);
  });
  const insertRow =
    typeof tbody.moveBefore === "function" ? (row) => tbody.moveBefore(row, null) : (row) => tbody.appendChild(row);
  for (const { row } of entries) insertRow(row);
}

function sortTableByHeader(table, th) {
  const nextDir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
  for (const header of table.tHead.querySelectorAll("th[aria-sort]")) header.removeAttribute("aria-sort");
  th.setAttribute("aria-sort", nextDir);
  sortTableRows(table.tBodies[0], th, nextDir);
  const direction = nextDir === "ascending" ? "tăng dần" : "giảm dần";
  document.getElementById("table-sort-status").textContent =
    `Đã sắp xếp bảng theo ${th.dataset.colLabel} (${direction})`;
}

function resortActiveTable(tbody) {
  const header = tbody.closest("table").tHead.querySelector("th[aria-sort]");
  if (header) sortTableRows(tbody, header, header.getAttribute("aria-sort"));
}

function wireSortableTables() {
  const hasInvokerCommands = "commandForElement" in HTMLButtonElement.prototype;
  for (const table of document.querySelectorAll("table[id]")) {
    const buttons = table.tHead?.querySelectorAll('button[command="--sort"]');
    if (!buttons?.length) continue;
    table.addEventListener("command", (event) => {
      if (event.command !== "--sort") return;
      const header = event.source?.closest("th");
      if (header?.closest("thead") === table.tHead) sortTableByHeader(table, header);
    });
    if (!hasInvokerCommands) {
      for (const button of buttons)
        button.addEventListener("click", () => sortTableByHeader(table, button.closest("th")));
    }
  }
}

function wireDeferredVisibilityObservers() {
  const sections = document.querySelectorAll(".deferred-below-fold");
  if (!sections.length) return;
  const supportsNativeVisibility =
    "contentVisibility" in document.documentElement.style &&
    ("oncontentvisibilityautostatechange" in sections[0] || "ContentVisibilityAutoStateChangeEvent" in window);
  if (supportsNativeVisibility) {
    for (const section of sections) {
      section.addEventListener("contentvisibilityautostatechange", (event) => {
        section.dataset.cvSkipped = String(Boolean(event.skipped));
      });
    }
  } else if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) entry.target.dataset.cvSkipped = String(!entry.isIntersecting);
    });
    for (const section of sections) observer.observe(section);
  }
}

function wireScrollFades() {
  if (CSS.supports("animation-timeline", "scroll()") || !("IntersectionObserver" in window)) return;
  for (const scroller of document.querySelectorAll(".scroller-fade")) {
    const start = dom("span", { class: "scroll-sentinel", "aria-hidden": "true" });
    const end = start.cloneNode();
    scroller.prepend(start);
    scroller.append(end);
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          scroller.classList.toggle(entry.target === start ? "more-start" : "more-end", entry.intersectionRatio < 1);
        }
      },
      { root: scroller, threshold: 1 },
    );
    observer.observe(start);
    observer.observe(end);
  }
}

function wireDashboardEvents() {
  const byId = (id) => document.getElementById(id);
  wireTablist(byId("primary-tablist"), (tab) => switchTab(tab, { fromTabButton: true }), { activateOnFocus: false });
  wireTablist(byId("evidence-tablist"), switchEvidenceTab, { activateOnFocus: true });
  wireTablist(byId("ai-tablist"), switchAITab, { activateOnFocus: true });
  wireTablist(byId("siem-tablist"), switchSiemSubTab, { activateOnFocus: true });
  for (const tab of ["components", "timeline"]) {
    byId("ev-view-" + tab).addEventListener("beforematch", () => switchEvidenceTab(tab));
  }
  wireAIChatEvents();
  wireScrollFades();
  wireSortableTables();
  wireDeferredVisibilityObservers();
  systemDarkScheme.addEventListener("change", updateThemeToggle);

  const dropzone = byId("dropzone");
  const input = byId("file-input");
  const selectPdf = () => {
    if (!dropzone.dataset.scanning) input.click();
  };
  byId("btn-select-pdf").addEventListener("click", selectPdf);
  dropzone.addEventListener("click", (event) => {
    if (!event.target.closest("button, input")) selectPdf();
  });
  input.addEventListener("change", () => handleFileList(input.files));
  byId("cdr-file-input").addEventListener("change", (event) => handleCDRFileUpload(event.target.files[0]));
  byId("cdr-mode-select").addEventListener("change", () => setCDRPending(false));
  byId("mail-tab-file-input").addEventListener("change", (event) => handleEMLUpload(event.target.files[0]));
  for (const name of ["dragenter", "dragover", "dragleave", "drop"]) {
    dropzone.addEventListener(name, (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (name === "drop" && !dropzone.dataset.scanning) handleFileList(event.dataTransfer?.files);
      const entering = name === "dragenter" || name === "dragover";
      dropzone.classList.toggle("dropzone-dragover", entering && !dropzone.dataset.scanning);
    });
  }

  const actions = {
    "btn-theme-toggle": toggleColorScheme,
    "btn-cancel-scan": cancelActiveScan,
    "btn-quick-disarm": quickSwitchAndDisarm,
    "btn-export-forensics": exportForensicJSON,
    "btn-toggle-analyzers": toggleAnalyzerGrid,
    "btn-select-cdr": () => byId("cdr-file-input").click(),
    "btn-execute-disarm": executeLiveCDR,
    "btn-download-sanitized": downloadSanitizedPDF,
    "diff-mode-side": () => setDiffViewMode("side"),
    "diff-mode-slider": () => setDiffViewMode("slider"),
    "btn-diff-prev": () => changeDiffPage(-1),
    "btn-diff-next": () => changeDiffPage(1),
    "diff-retry": () => loadVisualDiff(appState.currentDiffPage),
    "btn-select-mail": () => byId("mail-tab-file-input").click(),
    "btn-inspect-active-job-mail": inspectActiveJobViaMailGateway,
    "btn-refresh-mail": loadMailGatewayHistory,
    "btn-refresh-siem": () => {
      fetchSiemLogs();
      fetchQuarantineVault();
    },
    "btn-export-siem": exportSiemJSON,
  };
  for (const [id, listener] of Object.entries(actions)) byId(id).addEventListener("click", listener);
  document.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    const { switchTab: tab, copyTarget, scanJob, deleteScan, graphNode } = button.dataset;
    if (tab || graphNode) button.focus({ preventScroll: true });
    if (tab) switchTab(tab);
    if (copyTarget) copyText(copyTarget, button);
    if (scanJob) loadScanJob(scanJob);
    if (deleteScan) deleteScanJob(event, deleteScan);
    if (graphNode) inspectAndAblateNode(graphNode);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) graphModule?._stopGraphCanvasAnimation();
    else if (appState.activeTab === "graph") graphModule?._startGraphCanvasAnimation();
  });
  const graphPopover = byId("graph-controls-popover");
  const graphToggle = byId("btn-graph-controls-toggle");
  if (graphPopover) {
    graphPopover.addEventListener("toggle", (event) => syncGraphPopover(event.newState === "open"));
  }
  byId("btn-graph-controls-close")?.addEventListener("click", () =>
    requestAnimationFrame(() => {
      if (appState.activeTab === "graph") graphToggle?.focus({ preventScroll: true });
    }),
  );
}

function initDashboard() {
  initTrustedTypes();
  syncThemeMetaFromStorage();
  wireDashboardEvents();
  initSplitSliderEvents();
  const params = new URL(location.href).searchParams;
  setDiffViewMode(params.get("diff") === "slider" ? "slider" : "side", false);
  switchTab(params.get("tab") || "scan", { updateUrl: false, transition: false });
  loadHealthTelemetry();
  fetchScanHistory();
  initAmbientCyberCanvas();
}

window.__malpdfDebug = { switchTab, inspectAndAblateNode };
initDashboard();
