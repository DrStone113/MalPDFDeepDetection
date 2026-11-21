const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.MALPDF_PLAYWRIGHT_MODULE || 'playwright');

const origin = 'http://127.0.0.1:8765';
const root = path.resolve(__dirname, '..');
const fixture = path.join(root, 'tests', 'fixtures', 'real_benign_document.pdf');
const output = path.resolve(process.argv[2] || path.join(root, 'artifacts', 'web-p0-baseline'));
const repetitions = Number(process.argv[3] || 5);
const profiles = [
  { name: 'desktop', width: 1365, height: 900, cpuRate: 1 },
  { name: 'narrow_cpu4x', width: 390, height: 844, cpuRate: 4 },
];

const round = value => Math.round(value * 10) / 10;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function observePage() {
  window.perfProbe = { lcp: null, cls: 0, clicks: [] };
  new PerformanceObserver(list => {
    for (const entry of list.getEntries()) window.perfProbe.lcp = entry.startTime;
  }).observe({ type: 'largest-contentful-paint', buffered: true });
  new PerformanceObserver(list => {
    for (const entry of list.getEntries()) {
      if (!entry.hadRecentInput) window.perfProbe.cls += entry.value;
    }
  }).observe({ type: 'layout-shift', buffered: true });
  new PerformanceObserver(list => {
    for (const event of list.getEntries()) {
      if (event.name !== 'click' || !event.interactionId) continue;
      const button = event.target?.closest('button');
      window.perfProbe.clicks.push({
        start: event.startTime,
        target: button?.id || button?.getAttribute('onclick') || null,
        duration_ms: event.duration,
        delay_ms: event.processingStart - event.startTime,
        processing_ms: event.processingEnd - event.processingStart,
      });
    }
  }).observe({ type: 'event', buffered: true, durationThreshold: 16 });
}

async function snapshotLoad(page) {
  await page.evaluate(async () => {
    await Promise.race([document.fonts.ready, new Promise(resolve => setTimeout(resolve, 1500))]);
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  await page.waitForFunction(() => window.perfProbe.lcp !== null, undefined, { timeout: 1200 }).catch(() => {});
  return page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0];
    return {
      lcp_ms: window.perfProbe.lcp,
      layout_shift_sum: window.perfProbe.cls,
      ttfb_ms: nav.responseStart,
      load_ms: nav.loadEventEnd || null,
      document_transfer_bytes: nav.transferSize,
      document_decoded_bytes: nav.decodedBodySize,
    };
  });
}

async function writeTrace(cdp, destination) {
  const completed = new Promise(resolve => cdp.once('Tracing.tracingComplete', resolve));
  await cdp.send('Tracing.end');
  const { stream } = await completed;
  const file = await fs.open(destination, 'w');
  try {
    let part;
    do {
      part = await cdp.send('IO.read', { handle: stream });
      await file.write(Buffer.from(part.data, part.base64Encoded ? 'base64' : 'utf8'));
    } while (!part.eof);
  } finally {
    await file.close();
    await cdp.send('IO.close', { handle: stream });
  }
}

async function run(browser, profile, iteration) {
  const context = await browser.newContext({ viewport: { width: profile.width, height: profile.height } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await page.addInitScript(observePage);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: profile.cpuRate });
  const browserErrors = [];
  const failedRequests = [];
  page.on('pageerror', error => browserErrors.push(error.name));
  page.on('requestfailed', request => {
    if (request.failure()?.errorText === 'net::ERR_ABORTED') return;
    const url = new URL(request.url());
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      failedRequests.push({ origin: url.origin, error: request.failure()?.errorText });
    }
  });
  const trace = iteration === 0;
  if (trace) {
    await cdp.send('Tracing.start', {
      categories: 'devtools.timeline,blink.user_timing,loading,input,latencyInfo',
      transferMode: 'ReturnAsStream',
    });
  }
  const mark = () => performance.now();
  const api = (prefix, method = 'GET') => page.waitForResponse(
    response => new URL(response.url()).pathname.startsWith(prefix) && response.request().method() === method,
  );
  const recordApi = async (pending, started) => {
    const response = await pending;
    assert.equal(response.status(), 200);
    const bytes = await response.body();
    return { bytes: bytes.length, elapsed_ms: round(mark() - started), body: JSON.parse(bytes.toString()) };
  };
  try {
    await page.goto(origin, { waitUntil: 'load' });
    const cold = await snapshotLoad(page);
    await page.reload({ waitUntil: 'load' });
    const warm = await snapshotLoad(page);

    const scanRequest = api('/api/scan', 'POST');
    const scanStart = mark();
    await page.locator('#file-input').setInputFiles(fixture);
    const scan = await recordApi(scanRequest, scanStart);
    await page.locator('#results-panel').waitFor({ state: 'visible' });
    const scanVisible = round(mark() - scanStart);

    const graphStart = mark();
    await page.locator('#tab-graph').click();
    await page.waitForFunction(() => Number(document.querySelector('#graph-node-count')?.textContent) > 0);
    const graphReady = round(mark() - graphStart);
    await page.locator('#vis-container canvas').waitFor({ state: 'visible' });
    const graphCanvas = round(mark() - graphStart);
    await page.locator('#tab-scan').click();
    await page.locator('#tab-graph').click();
    await page.locator('#btn-graph-filter-threat').click();

    const beforeRequest = api('/api/diff/render/');
    const beforeStart = mark();
    await page.locator('#tab-cdr').click();
    const before = await recordApi(beforeRequest, beforeStart);
    assert.ok(before.body.original_render_uri);

    const cdrRequest = api('/api/disarm/', 'POST');
    const afterRequest = api('/api/diff/render/');
    const cdrStart = mark();
    await page.locator('#btn-execute-disarm').click();
    const cdr = await recordApi(cdrRequest, cdrStart);
    const audit = cdr.body;
    const integrity = audit.post_scan_verification.integrity_assertions;
    assert.equal(audit.scan_id, scan.body.scan_id);
    assert.equal(audit.is_sanitized, true);
    assert.ok(audit.sanitized_pages > 1 && audit.extracted_text_chars > 0);
    assert.deepEqual(Object.values(integrity), [true, true, true, true, true]);
    const after = await recordApi(afterRequest, cdrStart);
    assert.ok(after.body.sanitized_render_uri);
    await page.locator('#diff-clean-img').waitFor({ state: 'visible' });
    await page.locator('#diff-clean-img').evaluate(img => img.decode());
    const cleanPreview = round(mark() - cdrStart);

    const nextRequest = api('/api/diff/render/');
    const nextStart = mark();
    await page.locator('button[onclick="changeDiffPage(1)"]').click();
    const next = await recordApi(nextRequest, nextStart);
    assert.equal(next.body.page, 1);
    await page.locator('#diff-page-indicator').getByText(/Trang 2/).waitFor();
    await page.locator('#diff-clean-img').evaluate(img => img.decode());
    const nextVisible = round(mark() - nextStart);
    await page.locator('button[onclick="changeDiffPage(-1)"]').click();
    await page.locator('#diff-page-indicator').getByText(/Trang 1/).waitFor();
    await page.locator('#diff-mode-slider').click();

    const downloadPending = page.waitForEvent('download');
    await page.locator('#btn-download-sanitized').click();
    const download = await downloadPending;
    assert.equal(await download.failure(), null);
    const downloaded = await fs.readFile(await download.path());
    assert.equal(sha256(downloaded), audit.sha256_after);
    await page.locator('#tab-scan').click();
    const historyPending = api('/api/scans/');
    const historyStart = mark();
    await page.locator('#scan-history-items-vertical').getByText('real_benign_document.pdf', { exact: true }).first().click();
    const history = await recordApi(historyPending, historyStart);
    assert.equal(history.body.scan_id, audit.scan_id);

    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    return {
      cold,
      warm,
      clicks: await page.evaluate(() => window.perfProbe.clicks),
      browser_errors: browserErrors,
      failed_requests: failedRequests,
      scan_payload_bytes: scan.bytes,
      scan_response_ms: scan.elapsed_ms,
      scan_visible_ms: scanVisible,
      scan_backend_ms: scan.body.latency_ms ?? null,
      first_graph_ready_ms: graphReady,
      first_graph_canvas_ms: graphCanvas,
      graph_node_count: Number(await page.locator('#graph-node-count').textContent()),
      before_preview_bytes: before.bytes,
      cdr_payload_bytes: cdr.bytes,
      cdr_response_ms: cdr.elapsed_ms,
      cdr_backend_ms: audit.disarm_latency_ms,
      cdr_rescan_ms: audit.post_scan_verification.rescan_latency_ms,
      cdr_to_clean_preview_ms: cleanPreview,
      clean_preview_bytes: after.bytes,
      next_page_payload_bytes: next.bytes,
      next_page_visible_ms: nextVisible,
      download_verified_sha256: true,
      history_detail_response_ms: history.elapsed_ms,
      history_detail_response_bytes: history.bytes,
      page_count: audit.sanitized_pages,
      size_retention_pct: audit.size_retention_pct,
    };
  } finally {
    if (trace) await writeTrace(cdp, path.join(output, `${profile.name}.trace.json`));
    await context.close();
  }
}

(async () => {
  assert.ok(Number.isInteger(repetitions) && repetitions > 0);
  await fs.mkdir(output, { recursive: true });
  const health = await (await fetch(`${origin}/api/health`)).json();
  const html = Buffer.from(await (await fetch(origin)).arrayBuffer());
  const browser = await chromium.launch({ executablePath: process.env.MALPDF_CHROMIUM_EXE || undefined });
  try {
    const results = {
      chromium: browser.version(),
      fixture_sha256: sha256(await fs.readFile(fixture)),
      served_html_sha256: sha256(html),
      backend: { model: health.model, device: health.device, weights_loaded: health.weights_loaded },
      profiles,
      real_user_inp_p75_ms: null,
      runs: [],
    };
    for (const profile of profiles) {
      for (let iteration = 0; iteration < repetitions; iteration++) {
        const result = await run(browser, profile, iteration);
        results.runs.push({ profile: profile.name, iteration: iteration + 1, ...result });
        await fs.writeFile(path.join(output, 'measurements.json'), JSON.stringify(results, null, 2));
        console.log(`${profile.name} ${iteration + 1}/${repetitions}`);
      }
    }
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
