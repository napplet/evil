// evil-06 — side-channel oracles: timing, quota, and error-taxonomy leaks
// through shell mediation, even under a compliant namespace policy.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence, shellLogIncludes, untilPortSafeSettled, shellLogAt } from './_helper.mjs';

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

// port-bound shell (NIP-5D: any post-handoff window-level message is
// replacement evidence): window-level rows run LAST, so every port-safe row
// reaches a terminal status before the shell revokes (napplet/evil#3)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-06-side-channels', binding: 'port', runtime: true, settle: false });
  const snap = await untilPortSafeSettled(f);
  check('port/last: window-level rows marked (shell-rtt)', snap.windowLevel.join(',') === 'shell-rtt', snap.windowLevel.join(','));
  const portSafe = Object.keys(snap.statuses).filter((k) => !snap.windowLevel.includes(k));
  check('port/last: every port-safe row reached a terminal status', portSafe.length > 0 && portSafe.every((k) => snap.statuses[k] !== 'pending'), JSON.stringify(snap.statuses));
  check('port/last: window-level rows had not run yet (still pending)', snap.windowLevel.every((k) => snap.statuses[k] === 'pending'), JSON.stringify(snap.statuses));
  check('port/last: storage timing oracle ran over the port before revocation', snap.statuses['storage-timing'] === 'armed', snap.statuses['storage-timing']);
  await page.waitForFunction(() => (window.__evilLogLines || []).some((l) => l.includes('REVOKED')), null, { timeout: 15000 });
  const rev = await shellLogAt(page, 'REVOKED');
  check('port/last: shell REVOKED on the first window-level probe (evil.ping)', rev.line.includes('window-level NAP message after napplet.hello handoff (evil.ping)'), rev.line);
  check('port/last: revocation came only AFTER the port-safe rows finished', rev.at >= snap.at, rev.at + ' < ' + snap.at);
  const removed = await page.waitForFunction(() => !document.getElementById('frame'), null, { timeout: 5000 }).then(() => true).catch(() => false);
  check('port/last: revocation removed the frame (why ordering matters)', removed);
  await page.close();
}

// evil-window-level=skip: window-level rows report na in the sweep, no revocation
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-06-side-channels', binding: 'port', runtime: true, windowLevel: 'skip', settleMs: 9000 });
  const st = await statuses(f);
  const wl = 'shell-rtt'.split(',');
  check('port/skip: window-level rows na in the sweep', wl.every((k) => st[k] === 'na'), JSON.stringify(st));
  const ev = await evidence(f, wl[0]);
  check('port/skip: evidence names the skip parameter', ev.includes('skipped: window-level probe (evil-window-level=skip)'), ev.slice(0, 160));
  await page.waitForTimeout(500);
  check('port/skip: no revocation, frame still bound', !(await shellLogIncludes(page, 'REVOKED')) && await page.evaluate(() => !!document.getElementById('frame')));
  await f.locator('.attack[data-attack="' + wl[0] + '"] button[data-probe]').click();
  const manual = await page.waitForFunction(() => (window.__evilLogLines || []).some((l) => l.includes('REVOKED')), null, { timeout: 10000 }).then(() => true).catch(() => false);
  check('port/skip: manual probe button still runs the window-level row (shell revokes)', manual);
  await page.close();
}

await browser.close();
check.finish();