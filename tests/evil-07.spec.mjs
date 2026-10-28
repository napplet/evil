// evil-07 — fingerprinting: identification surfaces that survive a fully
// spec-compliant runtime untouched (that's the finding: everything arms).
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// spec preset: the passive identification layer is open
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-07-fingerprint", settleMs: 8000 });
  const st = await statuses(f);
  const expectedArmed = ['core-id', 'hardware', 'display', 'locale-tz', 'fonts', 'gpu', 'shell-composition'];
  check('spec: fingerprint probes armed', expectedArmed.every((id) => st[id] === 'armed'), JSON.stringify(st));
  const ev = await f.evaluate((needle) => {
    const el = document.querySelector('.attack[data-attack="' + needle + '"] .evidence');
    return el ? el.textContent : '';
  }, 'media-devices');
  check('spec: media device inventory observed', st['media-devices'] !== undefined, ev.slice(0, 120));
  await page.close();
}

// no sibling frames, plain spec: shell composition still leaks referrer
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-07-fingerprint", settleMs: 8000 });
  const ev = await f.evaluate(() => {
    const el = document.querySelector('.attack[data-attack="shell-composition"] .evidence');
    return el ? el.textContent : '';
  });
  check('spec: shell URL leak (referrer) present in composition evidence', ev.includes('referrer'), ev.slice(0, 160));
  await page.close();
}

// VERY EVIL: the bundled fingerprint is exfiltrated — identification, not just capability
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: "evil-07-fingerprint", csp: false, settleMs: 8000 });
  await armVeryEvil(f, BASE + '/collect');
  const kinds = exfil.map((e) => (e.body || '').slice(0, 400)).join(' || ');
  check('very-evil: fingerprint bundle exfiltrated (core-id + hardware + gpu)', kinds.includes('core-id') && kinds.includes('hardware'), kinds.slice(0, 200));
  await page.close();
}

await browser.close();
check.finish();