// evil-06 — side-channel oracles: timing, quota, and error-taxonomy leaks
// through shell mediation, even under a compliant namespace policy.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil } from './_helper.mjs';

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