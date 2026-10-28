// evil-05 — Nostr-level substitution: storage namespace policies. by-(dTag+hash)
// isolates; by-dTag lets a substituted heir inherit the victim's secrets; global
// shares everything.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// compliant namespace policy (by-(dTag+hash)): no inheritance
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-05-substitution', runtime: true, policy: 'by-dtag-hash', settleMs: 6000 });
  const st = await statuses(f);
  check('by-(dTag+hash): inheritance held (namespaced to artifact identity)', st['inherited-storage'] === 'blocked', JSON.stringify(st));
  check('by-(dTag+hash): cross-namespace read held', st['cross-namespace-read'] === 'blocked');
  await page.close();
}

// by-dTag policy: the substituted heir inherits the victim's stored secret
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-05-substitution', runtime: true, policy: 'by-dtag', settleMs: 6000 });
  const st = await statuses(f);
  check('by-dTag: inheritance ARMS (substitution = stored-data theft)', st['inherited-storage'] === 'armed', JSON.stringify(st));
  const ev = await evidence(f, 'inherited-storage');
  check('by-dTag: inherited the v1-victim-secret canary', ev.includes('INHERITED'), ev.slice(0, 160));
  await page.close();
}

// global policy: everything shared across napplets
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-05-substitution', runtime: true, policy: 'global', settleMs: 6000 });
  const st = await statuses(f);
  check('global: inheritance arms', st['inherited-storage'] === 'armed');
  check('global: cross-namespace read arms (other napplets keys visible)', st['cross-namespace-read'] === 'armed', JSON.stringify(st));
  await page.close();
}

// no runtime domain: nothing to inherit
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-05-substitution', settleMs: 6000 });
  const st = await statuses(f);
  check('no runtime: inheritance channel absent (na)', st['inherited-storage'] === 'na');
  await page.close();
}

// VERY EVIL under by-dTag: exfiltrates the inherited secret, poisons the namespace
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: 'evil-05-substitution', runtime: true, policy: 'by-dtag', csp: false, settleMs: 6000 });
  await armVeryEvil(f, BASE + '/collect');
  const leaked = exfil.some((e) => (e.body || '').includes('v1-victim-secret'));
  check('very-evil: inherited victim secret EXFILTRATED to collector', leaked, exfil.map((e) => (e.body || '').slice(0, 60)).join(' || '));
  const poisoned = await page.waitForFunction(() => {
    const s = window.__evilStore();
    return Object.entries(s).some(([ns2, kv]) => ns2.includes("evil-05") && Object.keys(kv).includes('__evil05_poison__'));
  }, null, { timeout: 10000 }).then(() => true).catch(() => false);
  check('very-evil: namespace POISONED for the next heir (__evil05_poison__)', poisoned);
  await page.close();
}

await browser.close();
check.finish();