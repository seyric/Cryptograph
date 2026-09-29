/**
 * Records the CANARY TRAP end-to-end demo through the real browser UIs.
 *
 * Unlike a screenshot tour, every step here is asserted: the recipient daemon
 * must come online, the decrypt must produce a rendered document (not just a
 * green progress bar), and the forensic pass must return an ATTRIBUTED verdict
 * naming the right recipient. If any of that fails, the run exits non-zero and
 * writes the reason to docs/demo/capture.log.
 *
 * Prerequisite:
 *   python gauntlet/stack.py up
 *   python gauntlet/stack.py bootstrap
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const OUT = __dirname;
const ROOT = path.resolve(__dirname, '..', '..');
const VIEWER_URL = 'http://127.0.0.1:5173/';
const AUDIT_URL = 'http://127.0.0.1:5174/';
const LEAK_FILE = path.join(ROOT, 'bench_data', 'alice_decrypted.pdf');

const LOG = [];
function say(line) {
  LOG.push(line);
  console.log(line);
}
function assert(condition, message) {
  if (!condition) throw new Error(`ASSERTION FAILED: ${message}`);
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  // Headful is not a cosmetic choice: bundled headless Chromium has no PDF
  // viewer plugin, so the decrypted document would render as an empty box and
  // the recording would show a green pipeline with no document behind it.
  const browser = await chromium.launch({ headless: false });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    recordVideo: { dir: OUT, size: { width: 1440, height: 900 } },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`));

  async function snap(name) {
    await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: false });
    say(`  snap ${name}.png`);
  }


  // ── PART 0: the recipient daemon must be online ───────────────────────
  say('== 1. Recipient viewer: identity and daemon state ==');
  await page.goto(VIEWER_URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  const headerText = await page.textContent('header');
  assert(/DAEMON ONLINE/i.test(headerText), `viewer header does not report DAEMON ONLINE: ${headerText}`);
  say('  daemon reported ONLINE');
  await snap('01_viewer_identity');

  await page.hover('section.card');
  await page.waitForTimeout(500);
  await snap('02_viewer_card_hover');

  // ── PART 1: log-before-key decryption; the document must render ───────
  say('== 2. Log-before-key decryption ==');
  await page.click('#btn-decrypt');
  await page.waitForTimeout(900);
  await snap('03_viewer_decrypting');
  await page.waitForSelector('ul.steps-list li', { timeout: 20000 });
  await page.waitForTimeout(2200);
  await snap('04_viewer_steps_progress');

  say('  waiting for the assembled document to render...');
  await page.waitForSelector('iframe.doc-frame', { timeout: 120000 });
  const docCardText = await page.locator('section.card').filter({ hasText: 'DECRYPTED_SUCCESS' }).textContent();
  const sessionMatch = /[0-9a-f]{64}/.exec(docCardText);
  assert(sessionMatch, 'session entry hash not shown on the decrypted document card');
  say(`  document rendered; session entry hash ${sessionMatch[0].slice(0, 32)}...`);
  await page.locator('iframe.doc-frame').scrollIntoViewIfNeeded();
  await page.waitForTimeout(3500);
  await snap('05_viewer_document_rendered');
  await page.locator('iframe.doc-frame').screenshot({ path: path.join(OUT, '05b_rendered_directive.png') });
  say('  snap 05b_rendered_directive.png (assembled, watermarked PDF)');

  const errorAlerts = await page.locator('.alert.error').allTextContents();
  assert(errorAlerts.length === 0, `viewer surfaced an error: ${errorAlerts.join(' | ')}`);

  // ── PART 2: capture the leaked copy from the daemon's own render ──────
  say('== 3. Capturing the leaked copy of that decrypted document ==');
  const renderUrl = await page.getAttribute('iframe.doc-frame', 'src');
  const pdfResponse = await context.request.get(renderUrl);
  assert(pdfResponse.status() === 200, `render endpoint returned ${pdfResponse.status()}`);
  const pdfBytes = await pdfResponse.body();
  assert(pdfBytes.slice(0, 5).toString() === '%PDF-', `leaked copy is not a PDF (${pdfBytes.slice(0, 16)})`);
  fs.writeFileSync(LEAK_FILE, pdfBytes);
  say(`  leaked copy written: bench_data/alice_decrypted.pdf (${pdfBytes.length} bytes)`);


  // ── PART 3: the audit console reads the live quorum ───────────────────
  say('== 4. Audit console: cluster status and block log ==');
  await page.goto(AUDIT_URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2500);
  const badges = await page.locator('.badge').allTextContents();
  assert(badges.some((b) => /4\/4 NODES/.test(b)), `cluster badge not 4/4: ${badges.join(' | ')}`);
  say(`  cluster badge: ${badges.find((b) => /NODES/.test(b))}`);
  await snap('06_audit_cluster_status');

  await page.hover('.node');
  await page.waitForTimeout(400);
  await snap('07_audit_node_detail');

  await page.click('button:has-text("Blocks")');
  await page.waitForTimeout(2000);
  const blockRows = await page.locator('table tbody tr').allTextContents();
  const entryCounts = [];
  for (const row of await page.locator('table tbody tr').all()) {
    const cells = await row.locator('td').allTextContents();
    entryCounts.push(Number(cells[3]));
  }
  const totalEntries = entryCounts.reduce((a, b) => a + b, 0);
  assert(totalEntries > 0, 'every block reported zero entries, expected the ledger entries');
  say(`  ${blockRows.length} blocks listed, ${totalEntries} entries in total (${entryCounts.join(', ')})`);
  await snap('08_audit_block_log');

  // ── PART 4: attribution against the live ledger ───────────────────────
  say('== 5. Forensic attribution of the leaked copy ==');
  await page.click('button:has-text("Forensics")');
  await page.waitForTimeout(1500);
  await snap('09_audit_forensics_input');

  await page.click('button:has-text("Attribute")');
  say('  attribution requested; waiting for a verdict...');
  await page.waitForFunction(
    () => {
      const dump = document.querySelector('pre.dump');
      return dump && /ATTRIBUTED|REQUEST_FAILED|NO_WATERMARK/.test(dump.textContent);
    },
    { timeout: 180000 }
  );
  const verdict = JSON.parse(await page.textContent('pre.dump'));
  assert(verdict.status === 'ATTRIBUTED', `verdict was ${verdict.status}: ${verdict.verdict}`);
  assert(verdict.culprit === 'ALICE', `culprit was ${verdict.culprit}, expected ALICE`);
  say(`  verdict: ${verdict.status} -> culprit ${verdict.culprit}`);
  say(`  match ${verdict.matchScore}, margin ${verdict.separation_margin}, p ${verdict.p_value}`);
  await page.waitForTimeout(1200);
  await snap('10_audit_attribution_verdict');

  // ── PART 5: closing shot on the recipient side ────────────────────────
  say('== 6. Closing shot ==');
  await page.goto(VIEWER_URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.evaluate(() => window.scrollTo({ top: 320, behavior: 'smooth' }));
  await page.waitForTimeout(1200);
  await snap('11_viewer_final');

  const videoPath = await page.video().path();
  await context.close();

  const finalVideo = path.join(OUT, 'canary_trap_demo.webm');
  if (fs.existsSync(finalVideo)) fs.unlinkSync(finalVideo);
  fs.renameSync(videoPath, finalVideo);

  say(consoleErrors.length
    ? `\n[!] browser console errors: ${consoleErrors.join(' | ')}`
    : '\n  browser console: clean');

  say('\nPASS - demo recorded');
  say(`  screenshots -> ${OUT}\\*.png`);
  say(`  video       -> ${finalVideo}`);
  fs.writeFileSync(path.join(OUT, 'capture.log'), LOG.join('\n') + '\n');

  await browser.close();
})().catch(async (err) => {
  LOG.push(`\nFAIL - ${err.message}`);
  try { fs.writeFileSync(path.join(OUT, 'capture.log'), LOG.join('\n') + '\n'); } catch {}
  console.error(`\nFAIL - ${err.message}`);
  process.exit(1);
});
