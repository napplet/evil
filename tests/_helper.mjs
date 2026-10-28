// Shared harness-driving helpers for evil-napplet specs.
// Resolves playwright from a sibling Hyprgate checkout (no repo-local dep).
import { createRequire } from 'node:module';
const require = createRequire('/Users/sandwich/Develop/Hyprgate/');
export const { chromium } = require('playwright');

export const BASE = 'http://localhost:8787';

export function makeChecks() {
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok });
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (ok || !detail ? '' : ' — ' + detail));
  };
  check.finish = (exit = true) => {
    const failed = results.filter((r) => !r.ok);
    console.log('\n' + (failed.length === 0 ? 'ALL CHECKS PASSED (' + results.length + ')' : failed.length + ' FAILED of ' + results.length));
    if (exit) process.exit(failed.length === 0 ? 0 : 1);
  };
  return check;
}

export async function loadHarness(page, opts = {}) {
  await page.goto(BASE + '/harness/');
  if (opts.preset) await page.check('input[name="preset"][value="' + opts.preset + '"]');
  if (opts.csp === false) await page.uncheck('input[name="csp"]');
  if (opts.nostr === false) await page.uncheck('input[name="nostr"]');
  if (opts.sibling === true) await page.check('input[name="sibling"]');
  if (opts.runtime === true) await page.check('input[name="runtime"]');
  if (opts.policy) await page.selectOption('select[name="policy"]', opts.policy);
  if (opts.trustDeclared === true) await page.check('input[name="trustdeclared"]');
  if (opts.launcher) await page.check('input[name="launcher"][value="' + opts.launcher + '"]');
  const wantId = opts.napplet || await page.$eval('#nappletSel', (el) => el.value);
  if (opts.napplet) await page.selectOption('#nappletSel', opts.napplet);
  await page.click('#loadBtn');
  const f = await waitForNapplet(page, wantId);
  // let the auto-run demo sweep finish (statuses settle)
  await waitSettled(f, opts.settleMs || 4500);
  return f;
}

async function waitForNapplet(page, wantId) {
  for (let i = 0; i < 200; i++) {
    for (const f of page.frames()) {
      if (f === page.mainFrame()) continue;
      try {
        const ok = await f.evaluate((id) => window.__EVIL_ID__ === id && !!document.getElementById('rows'), wantId);
        if (ok) return f;
      } catch (_) { /* navigating / destroyed */ }
    }
    await page.waitForTimeout(150);
  }
  throw new Error('napplet frame not found for ' + wantId);
}

export async function waitSettled(f, ms) {
  await f.waitForFunction(() => {
    const rows = document.querySelectorAll('.attack');
    return rows.length > 0 && Array.from(rows).every((r) => r.dataset.status && r.dataset.status !== 'pending');
  }, null, { timeout: ms + 5000 });
}

export async function statuses(f) {
  return await f.evaluate(() => {
    const out = {};
    for (const el of document.querySelectorAll('.attack')) out[el.dataset.attack] = el.dataset.status;
    return out;
  });
}
export async function evidence(f, id) {
  return await f.evaluate((attackId) => {
    const el = document.querySelector('.attack[data-attack="' + attackId + '"] .evidence');
    return el ? el.textContent : '';
  }, id);
}

export async function armVeryEvil(f, collector, timeoutMs = 30000) {
  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 5000 });
  const dlg = f.locator('#confirmDlg');
  if (collector) await dlg.locator('#collectorInput').fill(collector);
  // stern gate: wrong phrase must not enable
  const disabledBefore = await dlg.locator('#confirmBtn').isDisabled();
  await dlg.locator('#confirmInput').fill('execute evil');
  const wrongCaseHeld = await dlg.locator('#confirmBtn').isDisabled();
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  const enabled = !(await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmBtn').click();
  await f.waitForFunction(() => (document.querySelector('#evilLog')?.textContent || '').includes('finished.'), null, { timeout: timeoutMs });
  return { disabledBefore, wrongCaseHeld, enabled };
}

export function collectExfil(page, out) {
  page.on('request', (r) => {
    const u = r.url();
    if (u.includes('/collect')) out.push({ url: u, body: r.postData() || '' });
  });
}
export async function shellLogIncludes(page, needle) {
  const lines = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
  return lines.includes(needle);
}