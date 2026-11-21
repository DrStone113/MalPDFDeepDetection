const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require(process.env.MALPDF_PLAYWRIGHT_MODULE || 'playwright');

const origin = `http://127.0.0.1:${Number(process.env.MALPDF_TEST_PORT || 8765)}`;
const fixture = path.resolve(__dirname, '../tests/fixtures/real_benign_document.pdf');
const question = 'Hồ sơ quét của tệp này cho biết gì?';
const sse = (event, payload) => `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
const screenshots = process.env.MALPDF_CHAT_SCREENSHOTS;

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.MALPDF_CHROMIUM_EXE || undefined });
  try {
    for (const profile of [{ width: 1365, height: 900 }, { width: 390, height: 844 }]) {
      const page = await browser.newPage({ viewport: profile, reducedMotion: profile.width === 390 ? 'reduce' : 'no-preference' });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(origin);
      await page.locator('#file-input').setInputFiles(fixture);
      await page.locator('#results-panel').waitFor();
      if (profile.width !== 390) {
        await page.locator('#tab-cdr').click();
        await page.locator('#btn-execute-disarm').click();
        await page.locator('#btn-download-sanitized:enabled').waitFor();
        await page.locator('#tab-scan').click();
      }
      await page.locator('#ai-tab-chat').click();

      let releaseReport;
      const reportGate = new Promise(resolve => { releaseReport = resolve; });
      await page.route(origin + '/api/ai/chat', async route => {
        const response = await route.fetch();
        assert.equal(response.status(), 200);
        await reportGate;
        return route.fulfill({ response });
      });
      // Use a controlled provider stream while keeping the actual report request.
      await page.evaluate(() => {
        clientAIState.selectedModel = 'cnb/minimax-m3.1-flash';
        const originalFetch = window.fetch.bind(window);
        window.fetch = (url, options) => {
          if (url !== '/api/ai/chat' || JSON.parse(options.body).mode !== 'cloud') return originalFetch(url, options);
          if (window.chatTestOffline) return Promise.resolve(new Response(null, { status: 503 }));
          const stream = new ReadableStream({ start(controller) { window.chatTestStream = controller; } });
          return Promise.resolve(new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } }));
        };
      });
      async function providerFrame(data, close = false) {
        await page.evaluate(({ data, close }) => {
          if (data) window.chatTestStream.enqueue(new TextEncoder().encode(data));
          if (close) window.chatTestStream.close();
        }, { data, close });
      }
      await page.locator('#ai-chat-input').fill(question);
      await page.locator('#ai-chat-send-btn').click();
      const activity = page.locator('.chat-activity').last();
      await activity.locator('[data-step="report"][data-state="active"]').waitFor({ timeout: 5000 });
      assert.equal(await page.locator('#ai-chat-send-btn').isDisabled(), true);
      assert.equal(await activity.locator('details').getAttribute('open'), '');
      if (profile.width === 390) {
        const animation = await activity.locator('[data-step="report"] .chat-activity-dot').evaluate(el => getComputedStyle(el).animationName);
        assert.equal(animation, 'none');
      }
      releaseReport();
      await activity.locator('[data-step="cloud"][data-state="active"]').waitFor({ timeout: 5000 });
      assert.equal(await activity.locator('[data-step="report"]').getAttribute('data-state'), 'done');
      assert.match(await activity.locator('[data-step="report"]').textContent(), /2 trang/);
      assert.match(await activity.locator('[data-step="evidence"]').textContent(), /vị trí kích hoạt/);
      if (profile.width !== 390) {
        assert.match(await activity.locator('[data-step="cdr"]').textContent(), /2\/2/);
      }
      await providerFrame(sse('ready', { mode: 'cloud' }));
      await activity.locator('summary').getByText('Đã kết nối Cloud AI').waitFor();
      if (screenshots) {
        await fs.mkdir(screenshots, { recursive: true });
        const toasts = page.locator('#toast-container button');
        for (let i = await toasts.count(); i > 0; i--) {
          await toasts.first().click({ timeout: 700 }).catch(() => {});
        }
        await activity.screenshot({ path: path.join(screenshots, `waiting-${profile.width}.png`) });
      }
      await providerFrame(sse('delta', { text: 'Đây là phần đầu câu trả lời kiểm thử.' }));
      await activity.locator('[data-step="output"][data-state="active"]').getByText(/Đã nhận \d+ ký tự/).waitFor();
      await providerFrame(profile.width === 390 ? '' : sse('done', { mode: 'cloud' }), true);
      await activity.locator('summary').getByText(profile.width === 390 ? 'Câu trả lời bị ngắt' : 'Đã trả lời').waitFor({ timeout: 5000 });
      assert.equal(await activity.locator('[data-step="output"]').getAttribute('data-state'), profile.width === 390 ? 'error' : 'done');
      await page.getByText('Đây là phần đầu câu trả lời kiểm thử.', { exact: true }).waitFor();
      assert.equal(await page.locator('#ai-chat-send-btn').isEnabled(), true);
      if (profile.width !== 390) {
        await activity.locator('summary').click();
        assert.equal(await activity.locator('details').getAttribute('open'), '');
        await page.evaluate(() => { window.chatTestOffline = true; });
        await page.locator('#ai-chat-input').fill('Kết quả kiểm tra của PDF này là gì?');
        await page.locator('#ai-chat-send-btn').click();
        const fallback = page.locator('.chat-activity').last();
        await fallback.locator('summary').getByText('Đã trả lời từ hồ sơ').waitFor();
        assert.equal(await fallback.locator('[data-step="fallback"]').getAttribute('data-state'), 'done');
        assert.equal(await fallback.locator('[data-step="cloud"]').getAttribute('data-state'), 'error');

        await page.unroute(origin + '/api/ai/chat');
        let releaseStale;
        const staleGate = new Promise(resolve => { releaseStale = resolve; });
        await page.route(origin + '/api/ai/chat', async route => {
          const response = await route.fetch();
          await staleGate;
          await route.fulfill({ response }).catch(() => {});
        });
        await page.locator('#ai-chat-input').fill('Câu hỏi cho lượt quét cũ');
        await page.locator('#ai-chat-send-btn').click();
        await page.locator('.chat-activity').last().locator('[data-step="report"][data-state="active"]').waitFor();
        const nextScan = page.waitForResponse(r => new URL(r.url()).pathname === '/api/scan');
        await page.locator('#file-input').setInputFiles(fixture);
        assert.ok((await nextScan).ok());
        await page.locator('#results-panel').waitFor();
        releaseStale();
        assert.equal(await page.locator('.chat-activity').count(), 0);
        assert.equal(await page.locator('#ai-chat-send-btn').isEnabled(), true);
      }
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log('PASS: real evidence and CDR, Cloud ready and delta, completion, interruption, fallback, job switch, reduced motion');
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
