// Red-team verification: evil-01-sandbox-escape against the victim harness.
// Run: python3 -m http.server 8787 (repo root) && node tests/evil-01.spec.mjs
// Resolves playwright from a sibling Hyprgate checkout.
import { createRequire } from 'node:module';
const require = createRequire('/Users/sandwich/Develop/Hyprgate/');
const { chromium } = require('playwright');

const BASE = 'http://localhost:8787';
const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok });
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (ok || !detail ? '' : ' — ' + detail));
};

async function statuses(page) {
  const f = page.frames().find(fr => fr !== page.mainFrame() && fr.url() === 'about:srcdoc');
  if (!f) throw new Error('napplet frame not found');
  return await f.evaluate(() => {
    const out = {};
    for (const el of document.querySelectorAll('.attack')) out[el.dataset.attack] = el.dataset.status;
    return out;
  });
}
async function evilFrame(page) {
  return page.frames().find(fr => fr !== page.mainFrame() && fr.url() === 'about:srcdoc');
}

const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// ---- spec-compliant runtime: every escape probe must hold ----
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  await page.goto(BASE + '/harness/');
  await page.click('#loadBtn');
  await page.waitForTimeout(3000);
  const st = await statuses(page);
  const held = ['real-origin', 'shared-storage', 'service-worker', 'parent-dom', 'nip07', 'parent-nav', 'popup'];
  check('spec: escape probes all held', held.every(id => st[id] === 'blocked'), JSON.stringify(st));
  // Spec-gap findings (ROADMAP #2, #3): these arm even in a compliant runtime.
  check('spec: referrer leaks shell URL (ROADMAP #2)', st['referrer'] === 'armed', st['referrer']);
  check('spec: sibling-enum n/a without siblings', st['sibling-enum'] === 'na', st['sibling-enum']);
  const summary = await (await evilFrame(page)).locator('#summary').innerText();
  check('spec: exactly 1 armed (the referrer spec gap)', /1 armed/.test(summary), summary);
  check('spec: ARM enabled for the spec-gap channel', !(await (await evilFrame(page)).locator('#armBtn').isDisabled()));
  await page.close();
}

// ---- sloppy runtime (+allow-same-origin): escapes arm ----
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  await page.goto(BASE + '/harness/');
  await page.check('input[name="preset"][value="same-origin"]');
  await page.click('#loadBtn');
  await page.waitForTimeout(3000);
  const st = await statuses(page);
  const armed = ['real-origin', 'shared-storage', 'service-worker', 'parent-dom', 'nip07', 'parent-nav', 'referrer'];
  check('sloppy: escape probes all armed', armed.every(id => st[id] === 'armed'), JSON.stringify(st));
  check('sloppy: popup still held (no allow-popups)', st['popup'] === 'blocked');
  const summary = await (await evilFrame(page)).locator('#summary').innerText();
  check('sloppy: ARM enabled', !(await (await evilFrame(page)).locator('#armBtn').isDisabled()), summary);
  await page.close();
}

// ---- VERY EVIL mode: stern confirmation gate + real execution ----
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfilBodies = [];
  page.on('request', (r) => {
    const u = r.url();
    if (u.includes('/collect') || u.startsWith('https://evil.example.invalid')) {
      exfilBodies.push(u + ' :: ' + (r.postData() || '(no body)'));
    }
  });
  await page.goto(BASE + '/harness/');
  await page.check('input[name="preset"][value="no-sandbox"]');
  await page.uncheck('input[name="csp"]'); // no CSP: exfil channel open, so we can prove the payloads really fire
  await page.check('input[name="sibling"]');
  await page.click('#loadBtn');
  await page.waitForTimeout(3000);
  const f = await evilFrame(page);

  await f.locator('#armBtn').click();
  await f.waitForSelector('#confirmDlg[open]', { timeout: 3000 });
  const dlg = f.locator('#confirmDlg');
  // point the collector at the harness itself (local, 404, harmless) so egress is observable
  await dlg.locator('#collectorInput').fill(BASE + '/collect');
  check('confirm: dialog lists every armed payload', (await dlg.locator('#planList li').count()) >= 7, String(await dlg.locator('#planList li').count()));
  check('confirm: disabled before typing the phrase', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('execute evil');
  check('confirm: wrong case does not enable', await dlg.locator('#confirmBtn').isDisabled());
  await dlg.locator('#confirmInput').fill('EXECUTE EVIL');
  check('confirm: exact phrase enables', !(await dlg.locator('#confirmBtn').isDisabled()));
  await dlg.locator('#confirmBtn').click();

  // payloads execute in order; navigation is destructive and runs LAST,
  // so the shell defacement banner appears before the shell is navigated away
  await page.waitForFunction(() => !!document.querySelector('#__evil01_pwned_banner__'), null, { timeout: 20000 });
  check('evil: shell DOM defaced (parent-dom payload)', true);
  check('evil: storage theft exfiltrated the canary key', exfilBodies.some(b => b.includes('__harness_canary_nsec__')), exfilBodies.map(b => b.slice(0, 80)).join(' || '));
  check('evil: signature power exfiltrated', exfilBodies.some(b => b.includes('nip07-signing-power')));
  // destructive navigation (last): the shell is hijacked to the collector
  await page.waitForFunction(() => location.href.includes('/collect'), null, { timeout: 20000 });
  check('evil: shell hijacked to collector', page.url().includes('/collect'), page.url());
  await page.close();
}

await browser.close();
const failed = results.filter(r => !r.ok);
console.log('\n' + (failed.length === 0 ? 'ALL CHECKS PASSED (' + results.length + ')' : failed.length + ' FAILED of ' + results.length));
process.exit(failed.length === 0 ? 0 : 1);