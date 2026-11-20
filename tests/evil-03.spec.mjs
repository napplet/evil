// evil-03 — transport forging: a compliant router binds to MessageEvent.source
// and ignores declared identity; a sloppy router trusts envelope fields.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, shellLogIncludes, evidence, untilPortSafeSettled, shellLogAt } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// compliant router: declared identity ignored (probe routed to own ns → error reply)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, settleMs: 6000 });
  const st = await statuses(f);
  check('spec: declared-identity spoof held (router source-bound)', st['declared-identity'] === 'blocked', JSON.stringify(st));
  check('spec: forged reply dispatched (sent — acceptance is runtime bug)', st['forged-reply'] === 'sent');
  check('spec: sequential-id storm dispatched (sent)', st['sequential-ids'] === 'sent');
  check('spec: unknown-source nested relay sent (srcdoc children exist)', st['unknown-source'] === 'sent', String(st['unknown-source']));
  check('spec: shell DROPS the unmapped nested frame (source check)', await shellLogIncludes(page, 'DROPPED message from UNKNOWN source'));
  await page.close();
}

// sloppy router (trust declared fields): the spoof arms
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, trustDeclared: true });
  const st = await statuses(f);
  check('sloppy: declared-identity spoof ARMS (router trusts envelope identity)', st['declared-identity'] === 'armed', JSON.stringify(st));
  await page.close();
}

// VERY EVIL: forged storm fires; unmapped nested frames are dropped by the shell
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, csp: false });
  await armVeryEvil(f, BASE + '/collect');
  const dropped = await shellLogIncludes(page, 'DROPPED message from UNKNOWN source');
  check('very-evil: unmapped nested frames messaged the shell and were DROPPED', dropped);
  const accepted = await shellLogIncludes(page, 'ACCEPTED');
  check('very-evil: storm envelopes reached the router (ACCEPTED lines)', accepted);
  await page.close();
}

// port-bound shell (NIP-5D: any post-handoff window-level message is
// replacement evidence): window-level rows run LAST, so every port-safe row
// reaches a terminal status before the shell revokes (napplet/evil#3)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', binding: 'port', runtime: true, settle: false });
  const snap = await untilPortSafeSettled(f);
  check('port/last: window-level rows marked (declared-identity,forged-reply,sequential-ids,unknown-source)', snap.windowLevel.join(',') === 'declared-identity,forged-reply,sequential-ids,unknown-source', snap.windowLevel.join(','));
  const portSafe = Object.keys(snap.statuses).filter((k) => !snap.windowLevel.includes(k));
  check('port/last: every port-safe row reached a terminal status', portSafe.length > 0 && portSafe.every((k) => snap.statuses[k] !== 'pending'), JSON.stringify(snap.statuses));
  check('port/last: window-level rows had not run yet (still pending)', snap.windowLevel.every((k) => snap.statuses[k] === 'pending'), JSON.stringify(snap.statuses));
  check('port/last: shell-broadcast harvest ran before revocation', snap.statuses['shell-broadcast'] !== 'pending', snap.statuses['shell-broadcast']);
  await page.waitForFunction(() => (window.__evilLogLines || []).some((l) => l.includes('REVOKED')), null, { timeout: 15000 });
  const rev = await shellLogAt(page, 'REVOKED');
  check('port/last: shell REVOKED on the first window-level probe (storage.get)', rev.line.includes('window-level NAP message after napplet.hello handoff (storage.get)'), rev.line);
  check('port/last: revocation came only AFTER the port-safe rows finished', rev.at >= snap.at, rev.at + ' < ' + snap.at);
  const removed = await page.waitForFunction(() => !document.getElementById('frame'), null, { timeout: 5000 }).then(() => true).catch(() => false);
  check('port/last: revocation removed the frame (why ordering matters)', removed);
  await page.close();
}

// evil-window-level=skip: window-level rows report na in the sweep, no revocation
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', binding: 'port', runtime: true, windowLevel: 'skip', settleMs: 9000 });
  const st = await statuses(f);
  const wl = 'declared-identity,forged-reply,sequential-ids,unknown-source'.split(',');
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