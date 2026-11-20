// evil-06 — side-channel oracles: timing, quota, and error-taxonomy leaks
// through shell mediation, even under a compliant namespace policy.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// compliant runtime: the oracles still open (the finding)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-06-side-channels', runtime: true, settleMs: 9000 });
  const st = await statuses(f);
  check('spec: storage key-existence timing oracle ARMS', st['storage-timing'] === 'armed', JSON.stringify(st));
  check('spec: error taxonomy oracle arms', st['error-taxonomy'] === 'armed' || st['error-taxonomy'] === 'sent', st['error-taxonomy']);
  check('spec: shell scheduler RTT channel arms', st['shell-rtt'] === 'armed', st['shell-rtt']);
  {
    // NAP-STORAGE (napplet/naps#3): the probes must exercise getItem/keys, not the pre-spec get/set/remove
    const api = await f.evaluate(async () => {
      const s = window.napplet.storage;
      return { getItem: typeof s.getItem, keys: typeof s.keys, legacyGet: typeof s.get, miss: await s.getItem('__absent__' + Math.random()), listed: await s.keys() };
    });
    check('spec: injected storage is NAP-STORAGE shaped (getItem/keys, no legacy get)', api.getItem === 'function' && api.keys === 'function' && api.legacyGet === 'undefined', JSON.stringify(api));
    check('spec: getItem on a missing key resolves null; keys() lists the seeded key', api.miss === null && Array.isArray(api.listed) && api.listed.includes('__evil06_seeded__'), JSON.stringify(api));
    const ev = (await Promise.all(['storage-timing', 'error-taxonomy'].map((id) => evidence(f, id)))).join(' | ');
    check('spec: storage rows ran on the spec API (no "is not a function", no pre-spec na)', !/is not a function|not NAP-STORAGE shaped/.test(ev), ev.slice(0, 200));
  }
  await page.close();
}

// no runtime: nothing to mediate — oracles close
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-06-side-channels' });
  const st = await statuses(f);
  check('no runtime: timing oracle closed (na)', st['storage-timing'] === 'na');
  await page.close();
}

// VERY EVIL: the measured oracle model is exfiltrated
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: 'evil-06-side-channels', runtime: true, csp: false, settleMs: 12000 });
  await armVeryEvil(f, BASE + '/collect', 60000);
  const oracleOut = exfil.some((e) => (e.body || '').includes('storage-timing-oracle'));
  check('very-evil: timing-oracle model exfiltrated', oracleOut, exfil.map((e) => (e.body || '').slice(0, 80)).join(' || '));
  await page.close();
}

await browser.close();
check.finish();