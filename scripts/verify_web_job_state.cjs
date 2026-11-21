const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require(process.env.MALPDF_PLAYWRIGHT_MODULE || 'playwright');

const origin = `http://127.0.0.1:${Number(process.env.MALPDF_TEST_PORT || 8765)}`;
const fixture = path.join(__dirname, '../tests/fixtures/real_benign_document.pdf');
const namedFixture = require('node:fs').readFileSync(fixture);

async function scan(page, name) {
  const response = page.waitForResponse(r => r.url() === origin + '/api/scan' && r.request().method() === 'POST');
  await page.locator('#file-input').setInputFiles({ name, mimeType: 'application/pdf', buffer: namedFixture });
  const job = await (await response).json();
  await page.locator('#status-subtext').getByText(name, { exact: false }).waitFor();
  return job.scan_id;
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.MALPDF_CHROMIUM_EXE || undefined });
  try {
    const page = await browser.newPage({ viewport: { width: 1365, height: 900 } });
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(origin);
    const styles = await page.request.get(origin + '/assets/dashboard.css');
    assert.equal(styles.status(), 200);
    assert.match(styles.headers()['content-type'], /text\/css/);
    assert.equal((await page.request.get(origin + '/api/scans')).headers()['cache-control'], 'no-store');
    assert.equal(await page.locator('script[src*="vis-network"], script[src*="marked"]').count(), 0);
    const first = await scan(page, 'A.pdf');
    await page.locator('#tab-cdr').click();
    const url = origin + '/api/disarm/' + first + '?include_preview_images=false';
    let requests = 0;
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    await page.route(url, async route => {
      requests++;
      const result = await route.fetch();
      await hold;
      await route.fulfill({ response: result });
    });
    await page.locator('#btn-execute-disarm').click();
    assert.equal(await page.locator('#btn-execute-disarm').isDisabled(), true);
    await page.locator('#tab-scan').click();
    const second = await scan(page, 'Bản B.pdf');
    const firstResponse = page.waitForResponse(r => r.url() === url);
    release();
    assert.equal((await firstResponse).status(), 200);
    await page.locator('#tab-cdr').click();
    assert.equal(await page.locator('#btn-download-sanitized').isDisabled(), true);
    assert.match(await page.locator('#cdr-clean-filename').textContent(), /B\.pdf/);
    assert.equal(requests, 1);
    const graphAsset = page.waitForResponse(r => new URL(r.url()).pathname === '/assets/vis-network-10.1.5.min.js');
    await page.locator('#tab-graph').click();
    const graph = await graphAsset;
    assert.equal(graph.status(), 200);
    assert.match(graph.headers()['cache-control'], /immutable/);
    await page.locator('#vis-container canvas').waitFor();
    await page.locator('#tab-cdr').click();

    const secondUrl = origin + '/api/disarm/' + second + '?include_preview_images=false';
    await page.route(secondUrl, async route => {
      assert.equal((await route.fetch()).status(), 200);
      await route.abort('failed');
    }, { times: 1 });
    await page.locator('#btn-execute-disarm').click();
    await page.locator('#btn-download-sanitized:enabled').waitFor();
    await page.locator('#diff-clean-img').waitFor();
    const download = page.waitForEvent('download');
    await page.locator('#btn-download-sanitized').click();
    const file = await download;
    assert.match(file.url(), new RegExp(second + '$'));
    assert.equal(file.suggestedFilename(), 'sanitized_Bản B.pdf');
    assert.equal(await file.failure(), null);

    const previewUrl = new RegExp('/api/diff/render/' + second + '\\?page=1');
    let sawPreview;
    let releasePreview;
    const sawPageRequest = new Promise(resolve => { sawPreview = resolve; });
    const holdPreview = new Promise(resolve => { releasePreview = resolve; });
    await page.route(previewUrl, async route => {
      sawPreview();
      const result = await route.fetch();
      await holdPreview;
      await route.fulfill({ response: result }).catch(() => {});
    }, { times: 1 });
    await page.locator('button[onclick="changeDiffPage(1)"]').click();
    await sawPageRequest;
    await page.locator('button[onclick="changeDiffPage(-1)"]').click();
    releasePreview();
    await page.locator('#diff-page-indicator').getByText(/Trang 1/).waitFor();

    await page.route(previewUrl, route => route.abort('failed'), { times: 1 });
    await page.locator('button[onclick="changeDiffPage(1)"]').click();
    await page.locator('#diff-retry').waitFor();
    assert.equal(await page.locator('#btn-download-sanitized').isEnabled(), true);
    await page.locator('#diff-retry').click();
    await page.locator('#diff-page-indicator').getByText(/Trang 2/).waitFor();

    await page.locator('#tab-scan').click();
    const expired = await scan(page, 'Expired.pdf');
    assert.equal((await page.request.delete(origin + '/api/scans/' + expired)).ok(), true);
    await page.locator('#tab-cdr').click();
    await page.locator('#btn-execute-disarm').click();
    await page.getByText(/chọn lại tệp PDF/i).first().waitFor();
    assert.equal(await page.locator('#btn-download-sanitized').isDisabled(), true);
    await page.locator('#tab-scan').click();
    const historyItem = page.locator('#scan-history-items-vertical > div').filter({ hasText: 'Bản B.pdf' }).first();
    await historyItem.getByText('Bản B.pdf', { exact: true }).click();
    await page.locator('#status-subtext').getByText('Bản B.pdf', { exact: false }).waitFor();
    await historyItem.getByTitle('Xóa khỏi danh sách').click();
    await page.locator('#results-panel').waitFor({ state: 'hidden' });
    assert.equal((await page.request.get(origin + '/api/scans/' + second)).status(), 404);
    await page.locator('#tab-cdr').click();
    assert.equal(await page.locator('#btn-download-sanitized').isDisabled(), true);

    await page.locator('#diff-mode-slider').click();
    await page.reload();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.locator('#tab-cdr').focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('#tab-cdr').getAttribute('aria-current'), 'true');
    assert.equal(await page.locator('#tab-cdr').evaluate(el => el === document.activeElement), true);
    assert.equal(await page.locator('#diff-mode-slider').getAttribute('aria-pressed'), 'true');
    const slider = page.locator('#diff-split-handle');
    await slider.focus();
    await page.keyboard.press('ArrowRight');
    assert.equal(await slider.getAttribute('aria-valuenow'), '55');
    const box = await page.locator('#diff-split-box').boundingBox();
    await page.mouse.move(box.x + box.width * 0.25, box.y + 20);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.75, box.y + 20, { steps: 5 });
    await page.mouse.up();
    await page.waitForFunction(() => Number(document.querySelector('#diff-split-handle').getAttribute('aria-valuenow')) >= 74);
    await page.context().setOffline(true);
    await page.locator('#diff-mode-side').click();
    assert.equal(await page.locator('#diff-mode-side').getAttribute('aria-pressed'), 'true');
    await page.context().setOffline(false);
    const storage = await page.evaluate(() => Object.keys(localStorage));
    assert.deepEqual(storage, []);
    await page.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('Storage blocked', 'SecurityError'); } });
      window.startViewTransition = undefined;
    });
    await page.reload();
    await page.locator('#tab-cdr').click();
    assert.equal(await page.locator('#diff-mode-side').getAttribute('aria-pressed'), 'true');
    await page.locator('#diff-mode-slider').click();
    assert.equal(await page.locator('#diff-mode-slider').getAttribute('aria-pressed'), 'true');
    assert.deepEqual(errors, []);
    console.log('PASS: scoped CDR, lost acknowledgement, preview retry, expired scan, Unicode download, local settings, keyboard and pointer');
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
