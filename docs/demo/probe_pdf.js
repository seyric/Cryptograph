/**
 * Probes whether the bundled Chromium actually paints a PDF in an iframe.
 * Headless Chromium ships without the PDF viewer plugin, which makes the
 * decrypted document look like an empty box even though the daemon returned
 * a valid document. Run this before trusting a recording.
 *
 *   node probe_pdf.js [headless|headful]
 */
const { chromium } = require('playwright');
const path = require('path');

const mode = (process.argv[2] || 'headless') === 'headful' ? false : true;
const PDF_URL = 'http://127.0.0.1:5001/api/document/DEFENCE_DIRECTIVE_2026/render';

(async () => {
  const browser = await chromium.launch({ headless: mode });
  const context = await browser.newContext({ viewport: { width: 1100, height: 800 } });
  const page = await context.newPage();
  await page.setContent(
    `<body style="margin:0;background:#111">
       <iframe src="${PDF_URL}" style="width:100%;height:760px;border:0"></iframe>
     </body>`
  );
  await page.waitForTimeout(5000);
  const out = path.join(__dirname, `probe_pdf_${mode ? 'headless' : 'headful'}.png`);
  await page.screenshot({ path: out });
  console.log(`mode=${mode ? 'headless' : 'headful'} -> ${out}`);
  await browser.close();
})().catch((err) => { console.error('FAIL', err.message); process.exit(1); });
