// evil-10 — port theft & lifecycle: attacks the #14 fix itself. The retained
// port is the identity; the spec's claims about its privacy (bootstrap
// conformance), its transferability (a platform claim), and its closure on
// revocation are each probed. The leak/sloppy harness knobs arm the red path;
// a conformant port shell holds every probe.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence, shellLogIncludes } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });
const ID = 'evil-10-port-theft';

async function shellLog(page) {
  return await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
}

// conformant port shell, no leak: the bootstrap conformance holds
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, sibling: true, settleMs: 6000 });
  const st = await statuses(f);
  check('port-bound: private port NOT reachable — bootstrap conformance held', st['port-reachability'] === 'blocked', JSON.stringify(st));
  check('port-bound: transfer primitive armed (platform fact, privacy is the only defense)', st['port-transfer'] === 'armed');
  check('port-bound: stolen-port detonation row READY (never auto-run)', st['stolen-port'] === 'ready');
  const ev = await evidence(f, 'port-reachability');
  check('port-bound: evidence names the load-bearing conformance', ev.includes('bootstrap'), ev.slice(0, 140));
  await page.close();
}

// window binding: pre-#14 transport, no port to steal
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, sibling: true, settleMs: 6000 });
  const st = await statuses(f);
  check('window-keyed: no port transport — honestly na (evil-09\'s world)', st['port-reachability'] === 'na', JSON.stringify(st));
  await page.close();
}

// leak knob: the dev-mode bootstrap bug arms the scan
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, leakport: true, settleMs: 6000 });
  const st = await statuses(f);
  check('leak: reachable MessagePort found — "MUST NOT be reachable" violated', st['port-reachability'] === 'armed', JSON.stringify(st));
  check('leak, no sibling: transfer honestly na (nowhere for the port to live)', st['port-transfer'] === 'na');
  const ev = await evidence(f, 'port-reachability');
  check('leak: scan names the parked port (masked)', ev.includes('__nap_debug') || ev.includes('REACHABLE'), ev.slice(0, 140));
  await page.close();
}

// DETONATE under conformant revoke: theft speaks, revocation kills the channel
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, sibling: true, leakport: true, settleMs: 6000 });
  await f.locator('.attack[data-attack="stolen-port"] button[data-probe]').click();
  await page.waitForTimeout(3500);
  const log = await shellLog(page);
  check('theft: shell SERVED the stolen port\'s request (PORT-ACCEPTED theft id)', /PORT-ACCEPTED \{"type":"storage.get","id":"theft-/.test(log), log.slice(-400));
  check('theft: mule spoke as the verified napplet from another frame (while-alive SERVED)', log.includes('"phase":"while-alive","got":"SERVED"'));
  check('theft: self-revocation triggered (window-level NAP = replacement evidence)', log.includes('REVOKED identity (dTag=evil-10-port-theft)'));
  const removed = await page.evaluate(() => !document.getElementById('frame'));
  check('theft: verified frame removed by the shell', removed);
  check('conformant revoke: channel died with the revocation (mule probe unanswered → CHANNEL-DEAD)', log.includes('"phase":"post-revoke","got":"CHANNEL-DEAD"'), log.slice(-300));
  check('conformant revoke: NO post-revocation service of the stolen port', !log.includes('"phase":"post-revoke","got":"CHANNEL-ALIVE"'));
  await page.close();
}

// DETONATE under sloppy revoke: the channel outlives the napplet's destruction
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, sibling: true, leakport: true, sloppyrevoke: true, settleMs: 6000 });
  await f.locator('.attack[data-attack="stolen-port"] button[data-probe]').click();
  const alive = await page.waitForFunction(() => (window.__evilLogLines || []).join('\n').includes('"phase":"post-revoke","got":"CHANNEL-ALIVE"'), null, { timeout: 10000 }).then(() => true).catch(() => false);
  const log = await shellLog(page);
  check('sloppy revoke: stolen channel ALIVE post-revocation — grants served after the napplet\'s destruction', alive, log.slice(-400));
  check('sloppy revoke: the mule got the grant value over the dead napplet\'s channel', log.includes('"phase":"post-revoke","got":"CHANNEL-ALIVE","value":"grant-data-spoken-by-a-STOLEN-PORT"'));
  check('sloppy revoke: revocation log names the skipped close', log.includes('SLOPPY: port left OPEN'));
  await page.close();
}

// VERY EVIL under sloppy revoke: post-revocation poison + exfil over the stolen port
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, sibling: true, leakport: true, sloppyrevoke: true, csp: false, settleMs: 6000 });
  await armVeryEvil(f, BASE + '/collect');
  // register the request listener first — the mule's exfil fires ~1.6s after detonation
  const navExfil = await page.waitForRequest((r) => r.url().includes('/collect') && (r.postData() || '').includes('evil10-stolen-port'), { timeout: 12000 }).then(() => true).catch(() => false);
  const poisoned = await page.waitForFunction(() => JSON.stringify(window.__evilStore()).includes('__evil10_poison__'), null, { timeout: 10000 }).then(() => true).catch(() => false);
  check('very-evil: namespace POISONED over the stolen port, post-revocation', poisoned);
  check('very-evil: grant exfiltrated to the collector over the stolen channel', navExfil, exfil.map((e) => (e.body || '').slice(0, 60)).join(' || '));
  await page.close();
}

await browser.close();
check.finish();
