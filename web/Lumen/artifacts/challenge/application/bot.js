const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const SELF = 'http://127.0.0.1:5000';
const QUEUE = process.env.QUEUE_FILE || '/tmp/lumen/queue';
const FLAG = (() => {
  try { return fs.readFileSync('/flag.txt', 'utf8').trim(); }
  catch (e) { return process.env.DYN_FLAG || 'BHFlagY{local_test_flag}'; }
})();

let browser;

function localise(url) {
  try {
    const u = new URL(url);
    return SELF + u.pathname + u.search + u.hash;
  } catch (e) { return SELF + '/'; }
}

async function visit(url) {
  const target = localise(url);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await page.goto(SELF + '/?p=home', { timeout: 20000, waitUntil: 'load' });
    await page.evaluate((f) => localStorage.setItem('flag', f), FLAG);
  } catch (e) { console.log('[bot] seed failed: ' + e.message); }
  try {
    await page.goto(target, { timeout: 20000, waitUntil: 'load' });
    await page.waitForTimeout(4000);
  } catch (e) { console.log('[bot] visit ' + target + ' failed: ' + e.message); }
  await ctx.close();
}

async function main() {
  browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  console.log('[bot] chromium up, watching ' + QUEUE);
  fs.mkdirSync(path.dirname(QUEUE), { recursive: true });
  if (!fs.existsSync(QUEUE)) fs.writeFileSync(QUEUE, '');
  let pos = fs.statSync(QUEUE).size;
  setInterval(async () => {
    let data;
    try { data = fs.readFileSync(QUEUE, 'utf8'); } catch (e) { return; }
    if (data.length <= pos) return;
    const chunk = data.slice(pos);
    pos = data.length;
    for (const line of chunk.split('\n')) {
      const url = line.trim();
      if (url && /^https?:\/\//i.test(url)) await visit(url);
    }
  }, 1000);
}
main().catch((e) => { console.log('[bot] fatal: ' + e.message); process.exit(1); });
