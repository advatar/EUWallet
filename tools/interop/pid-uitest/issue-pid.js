// Headless UI test: obtain a live authorization code from the EU reference PID issuer
// (issuer.eudiw.dev) by driving its web form ("Test Credentials Provider" -> FormEU -> Review &
// Send). Synthetic test data only, to the EU-operated test issuer. Retries through the reference
// backend's intermittent 500s. Prints the captured authorization code as JSON on success.
const { chromium } = require('playwright');
const crypto = require('crypto');

const ISSUER = 'https://issuer.eudiw.dev';
const CLIENT_ID = 'advatar-eudi-wallet';
const REDIRECT = 'https://example.com/cb';
const CONFIG = 'eu.europa.ec.eudi.pid_vc_sd_jwt';
const ATTEMPTS = Number(process.env.ATTEMPTS || 6);
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function attempt(browser) {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(12));
  const par = await fetch(`${ISSUER}/pushed_authorization`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT,
      code_challenge: challenge, code_challenge_method: 'S256', state, scope: CONFIG }),
  });
  const { request_uri } = await par.json();
  if (!request_uri) throw new Error('PAR failed: ' + par.status);

  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await page.goto(`${ISSUER}/oidc/authorization?client_id=${CLIENT_ID}&request_uri=${encodeURIComponent(request_uri)}`, { waitUntil: 'domcontentloaded' });
    // Country page -> FormEU (FC). Overlay blocks pointer clicks, so submit via JS.
    await page.waitForSelector('input[type=radio][value="FC"]', { timeout: 30000 });
    await page.evaluate(() => { const fc = document.querySelector('input[type=radio][value="FC"]'); fc.checked = true; (fc.form || document.querySelector('form')).submit(); });
    await page.waitForLoadState('domcontentloaded');

    // FormEU: fill mandatory PID attributes (+ place_of_birth, else the builder 500s).
    await page.waitForSelector('input[name="family_name"]', { timeout: 30000 });
    await page.evaluate(() => {
      const s = (n, v) => { const e = document.querySelector(`[name="${n}"]`); if (e) e.value = v; };
      s('family_name', 'Andersson'); s('given_name', 'Astrid'); s('birthdate', '1988-04-12');
      s('nationalities[0][country_code]', 'SE'); s('sex', '1');
      s('place_of_birth[0][country]', 'SE'); s('place_of_birth[0][region]', 'Stockholm'); s('place_of_birth[0][locality]', 'Stockholm');
      const p1 = document.querySelector('input[type=radio][name="picture"][value="Port1"]'); if (p1) p1.checked = true;
    });
    await page.evaluate(() => {
      const btn = [...document.querySelectorAll('button,input[type=submit]')].find((b) => /confirm/i.test(b.textContent || b.value || ''));
      const f = (btn && btn.form) || [...document.querySelectorAll('form')].find((x) => (x.action || '').includes('/dynamic/form'));
      if (f) (f.requestSubmit ? f.requestSubmit() : f.submit());
    });

    // Either the review page (success) or an error page (500). Wait for one of them.
    await page.waitForFunction(() => /authorize|internal server error|error_code/i.test(document.body.innerText), { timeout: 30000 });
    const body = await page.evaluate(() => document.body.innerText);
    if (/internal server error|error_code/i.test(body)) throw new Error('issuer 500 on /dynamic/form');

    // Review & Send -> Authorize -> redirect to REDIRECT with ?code=.
    const nav = page.waitForURL(/example\.com\/cb/, { timeout: 45000 }).catch((e) => '' + e);
    await page.evaluate(() => {
      const el = [...document.querySelectorAll('button,input[type=submit],a')].find((b) => /^\s*authorize\s*$/i.test((b.textContent || b.value || '').trim()));
      if (!el) return;
      if (el.form) (el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit()); else el.click();
    });
    await nav;
    const u = new URL(page.url());
    const code = u.searchParams.get('code');
    if (!code) throw new Error('no code; final=' + page.url() + ' err=' + u.searchParams.get('error'));
    return { code, state: u.searchParams.get('state'), verifier, redirect: REDIRECT, config: CONFIG, client_id: CLIENT_ID };
  } finally {
    await ctx.close();
  }
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (let i = 1; i <= ATTEMPTS; i++) {
      try {
        const r = await attempt(browser);
        console.log(JSON.stringify(r));
        process.exit(0);
      } catch (e) {
        console.error(`attempt ${i}/${ATTEMPTS}: ${e.message}`);
        await sleep(3000);
      }
    }
    console.error('exhausted attempts (reference issuer flakiness)');
    process.exit(2);
  } finally {
    await browser.close();
  }
})();
