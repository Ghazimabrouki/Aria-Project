import { chromium } from 'playwright';

const BASE = 'http://localhost:3000';
const pages = [
  { path: '/', name: 'Dashboard' },
  { path: '/metrics', name: 'Metrics' },
  { path: '/monitoring', name: 'Monitoring' },
];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });

for (const p of pages) {
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', err => errors.push({ type: 'pageerror', message: err.message }));
  page.on('console', msg => {
    if (msg.type() === 'error') {
      errors.push({ type: 'console.error', text: msg.text() });
    }
  });

  console.log(`\n=== ${p.name} (${BASE}${p.path}) ===`);
  try {
    await page.goto(`${BASE}${p.path}`, { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(2000);
    await page.screenshot({ path: `/tmp/${p.name.toLowerCase().replace(/\s+/g, '-')}-screenshot.png`, fullPage: true });
    console.log('Loaded OK');
    if (errors.length) {
      console.log('Errors found:');
      errors.forEach(e => console.log(' -', e.type + ':', e.message || e.text));
    } else {
      console.log('No console/page errors');
    }
  } catch (e) {
    console.log('Navigation failed:', e.message);
  }
  await page.close();
}

await browser.close();
