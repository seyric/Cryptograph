const { chromium } = require('playwright');

const VIEWER_URL = 'http://localhost:5173/';
const AUDIT_URL = 'http://localhost:5174/';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

  const consoleLog = [];
  const netLog = [];
  page.on('console', (m) => consoleLog.push(`[console.${m.type()}] ${m.text()}`));
  page.on('pageerror', (e) => consoleLog.push(`[pageerror] ${e.message}`));
  page.on('response', (r) => {
    const u = r.url();
    if (u.includes('/api/')) netLog.push(`${r.status()} ${u.replace(/^http:\/\/127\.0\.0\.1:\d+/, '')}`);
  });

  console.log('=== VIEWER PROBE ===');
  await page.goto(VIEWER_URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);

  const daemonBadge = await page.textContent('.topbar, header').catch(() => '(no header)');
  console.log('header:', daemonBadge.replace(/\s+/g, ' ').trim().slice(0, 120));

  await page.click('#btn-decrypt');
  console.log('clicked #btn-decrypt — waiting up to 60s for doc card or error…');

  let outcome = 'TIMEOUT';
  for (let i = 0; i < 120; i++) {
    const hasDoc = await page.locator('.doc-frame, iframe.doc-frame').count();
    const hasErr = await page.locator('.alert.error').count();
    const cardCount = await page.locator('section.card').count();
    if (hasErr > 0) { outcome = 'ERROR'; break; }
    if (hasDoc > 0) { outcome = 'DOCUMENT RENDERED'; break; }
    await page.waitForTimeout(500);
  }

  const bodyText = (await page.textContent('body')).replace(/\s+/g, ' ').trim();
  console.log('outcome:', outcome);
  console.log('cards on page:', await page.locator('section.card').count());
  console.log('body text:', bodyText.slice(0, 500));
  await page.screenshot({ path: 'probe_viewer.png', fullPage: true });

  console.log('\n=== VIEWER NETWORK (api calls) ===');
  console.log(netLog.length ? netLog.join('\n') : '(none)');
  console.log('\n=== VIEWER CONSOLE ===');
  console.log(consoleLog.length ? consoleLog.join('\n') : '(clean)');

  console.log('\n=== AUDIT PROBE ===');
  netLog.length = 0; consoleLog.length = 0;
  await page.goto(AUDIT_URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2500);
  const badges = await page.locator('.badge').allTextContents();
  console.log('badges:', badges.join(' | '));
  const nodeHeights = await page.locator('.node .muted').allTextContents();
  console.log('node rows:', nodeHeights.join(' || ').slice(0, 300));
  await page.click('button:has-text("Blocks")');
  await page.waitForTimeout(2000);
  const rows = await page.locator('table tbody tr').allTextContents();
  console.log('block rows:', rows.map(r => r.replace(/\s+/g, ' ').trim()).join(' || '));
  await page.screenshot({ path: 'probe_audit.png', fullPage: true });

  console.log('\n=== AUDIT NETWORK ===');
  console.log(netLog.length ? netLog.slice(0, 20).join('\n') : '(none)');
  console.log('\n=== AUDIT CONSOLE ===');
  console.log(consoleLog.length ? consoleLog.join('\n') : '(clean)');

  await browser.close();
})().catch((e) => { console.error('probe failed:', e); process.exit(1); });
