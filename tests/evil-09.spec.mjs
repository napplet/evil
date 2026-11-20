// evil-09 — frame self-replacement & identity inheritance. Pre-#14 shells map
// (dTag, artifactHash) + grants to the iframe Window, which survives same-frame
// navigation: a napplet that replaces its own document passes the verified
// identity to unverified bytes, and the injected meta CSP dies with the verified
// document. The harness `binding: port` knob is the post-#14 green gate.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence, shellLogIncludes } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });
const ID = 'evil-09-self-replacement';

async function detonate(f) {
  await f.locator('.attack[data-attack="self-replace"] button[data-probe]').click();
  // stage-2 renders its own rows in the same frame (same Window, new document)
  await f.waitForFunction(() => !!document.querySelector('.attack[data-attack="url-disclosure"]'), null, { timeout: 10000 });
}

// window binding (pre-#14, default harness): the sweep proves the keying
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, settleMs: 6000 });
  const st = await statuses(f);
  check('window-keyed: NAP rides window-level postMessage (identity keyed to the Window)', st['window-keying'] === 'armed', JSON.stringify(st));
  check('window-keyed: replacement telemetry honestly na (shell-side watch)', st['replacement-watch'] === 'na');
  check('window-keyed: detonation row READY — armed by construction, never auto-run', st['self-replace'] === 'ready');
  const ev = await evidence(f, 'window-keying');
  check('window-keyed: evidence names the Window mapping', ev.includes('WINDOW-LEVEL') && ev.includes('Window'), ev.slice(0, 160));
  await page.close();
}

// DETONATE under window binding: unverified stage-2 bytes inherit everything
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, settleMs: 6000 });
  await detonate(f);
  const st = await statuses(f); // now reads stage-2's rows in the same frame
  check('detonated: stage-2 unverified bytes live in the frame (document replaced)', st['replaced-document'] === 'armed', JSON.stringify(st));
  check('detonated: raw NAP from UNVERIFIED bytes ACCEPTED — grants inherited', st['grant-inheritance'] === 'armed');
  check('detonated: injected meta CSP evaporated with the verified document', st['csp-evaporation'] === 'armed');
  check('detonated: navigation-URL carried data across the document boundary', st['url-disclosure'] === 'armed');
  const ev = await evidence(f, 'grant-inheritance');
  check('detonated: inherited the victim seed from the verified namespace', ev.includes('INHERITED-BY-EVIL-09'), ev.slice(0, 160));
  check('detonated: shell LOGGED the attacker document\'s report (it cannot tell)', await shellLogIncludes(page, 'ATTACKER DOCUMENT reported'));
  const order = await page.evaluate(() => {
    const lines = window.__evilLogLines || [];
    const s2 = lines.findIndex((l) => l.includes('ATTACKER DOCUMENT reported'));
    const accAfter = lines.findIndex((l, i) => i > s2 && l.includes('ACCEPTED {"type":"storage.get"'));
    return { s2, accAfter };
  });
  check('detonated: shell SERVED the replacement document (ACCEPTED storage.get after stage-2 booted)', order.s2 >= 0 && order.accAfter > order.s2, JSON.stringify(order));
  const alive = await page.evaluate(() => { const el = document.getElementById('frame'); return !!el && el.isConnected; });
  check('detonated: window-keyed shell left the attacker frame in place — no teardown', alive);
  await page.close();
}

// no runtime domain: transport unobservable
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, settleMs: 6000 });
  const st = await statuses(f);
  check('no runtime: NAP transport unobservable (na)', st['window-keying'] === 'na', JSON.stringify(st));
  await page.close();
}

// port binding (post-#14, the green gate): replies ride the port
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, settleMs: 6000 });
  const st = await statuses(f);
  check('port-bound: NO window-level NAP envelope — the green gate holds', st['window-keying'] === 'blocked', JSON.stringify(st));
  check('port-bound: detonation row still READY (primitive exists; the shell must hold it)', st['self-replace'] === 'ready');
  const ev = await evidence(f, 'window-keying');
  check('port-bound: evidence names the port handoff', ev.toLowerCase().includes('port'), ev.slice(0, 160));
  check('port-bound: verified document was port-bound (HELLO accepted)', await shellLogIncludes(page, 'HELLO accepted'));
  await page.close();
}

// DETONATE under port binding: the shell revokes and tears the frame down
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, binding: 'port', runtime: true, settleMs: 6000 });
  await f.locator('.attack[data-attack="self-replace"] button[data-probe]').click();
  await page.waitForFunction(() => (window.__evilLogLines || []).join('\n').includes('REVOKED'), null, { timeout: 10000 });
  check('port-bound detonate: replacement REVOKED (port close / second load → identity + grants torn down)', true);
  const removed = await page.waitForFunction(() => !document.getElementById('frame'), null, { timeout: 5000 }).then(() => true).catch(() => false);
  check('port-bound detonate: attacker frame REMOVED from the shell', removed);
  const logText = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
  check('port-bound detonate: revocation names the replacement evidence', /REVOKED identity \(dTag=evil-09-self-replacement\)/.test(logText), logText.slice(-300));
  await page.close();
}

// run parameter evil09-target (napplet/evil#3): the network replacement
// target comes from the host, never from document.referrer
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, settleMs: 6000 });
  const injected = await f.evaluate(() => window.__EVIL_PARAMS__ && window.__EVIL_PARAMS__['evil09-target']);
  check('param: harness injects window.__EVIL_PARAMS__ evil09-target = the same-host fixture', injected === BASE + '/harness/replace-target.html', String(injected));
  await detonate(f);
  const href = await f.evaluate(() => location.origin + location.pathname);
  check('param supplied: frame navigated to the network target named by evil09-target', href === BASE + '/harness/replace-target.html', href);
  const ev = await evidence(f, 'replaced-document');
  check('param supplied: stage-2 evidence names the target and its source (run parameter)', ev.includes('/harness/replace-target.html (from run parameter evil09-target)'), ev.slice(-200));
  await page.close();
}
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, evil09Target: '', settleMs: 6000 });
  await detonate(f);
  const st = await statuses(f);
  const proto = await f.evaluate(() => location.protocol);
  check('param cleared: no network target — scheme-local data: replacement', proto === 'data:', proto);
  check('param cleared: data: replacement still carries the marker in its URL', st['url-disclosure'] === 'armed', JSON.stringify(st));
  const ev = await evidence(f, 'replaced-document');
  check('param cleared: evidence says the target was scheme-local by host choice', ev.includes('target: scheme-local data: (evil09-target="")'), ev.slice(-160));
  await page.close();
}
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, evil09Target: 'javascript:alert(1)', settleMs: 6000 });
  await f.locator('.attack[data-attack="self-replace"] button[data-probe]').click();
  await f.waitForFunction(() => document.querySelector('.attack[data-attack="self-replace"]')?.dataset.status === 'na', null, { timeout: 5000 });
  await page.waitForTimeout(1500); // past the 800ms fallback watchdog: nothing may navigate
  const still = await f.evaluate(() => ({ id: window.__EVIL_ID__, keying: !!document.querySelector('.attack[data-attack="window-keying"]'), href: location.href }));
  check('param invalid scheme: javascript: target REJECTED (na), frame never navigated', still.id === ID && still.keying && still.href === 'about:srcdoc', JSON.stringify(still));
  const ev = await evidence(f, 'self-replace');
  check('param invalid scheme: evidence names the rejected value and the reason', ev.includes('rejected evil09-target') && ev.includes('javascript:'), ev.slice(0, 160));
  await page.close();
}
// shell strips the referrer: the probe still uses the param target
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: ID, runtime: true, noReferrer: true, settleMs: 6000 });
  const ref = await f.evaluate(() => document.referrer);
  check('no-referrer: the shell emptied document.referrer for the napplet', ref === '', JSON.stringify(ref));
  await detonate(f);
  const href = await f.evaluate(() => location.origin + location.pathname);
  check('no-referrer: network replacement still reaches the param target (not the data: fallback)', href === BASE + '/harness/replace-target.html', href);
  await page.close();
}

// VERY EVIL under window binding: stage-2 poisons the namespace and exfiltrates
// via the navigation URL — no CSP directive governs a location assignment
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: ID, runtime: true, csp: false, settleMs: 6000 });
  await armVeryEvil(f, BASE + '/collect');
  // the fixture's exfil navigation fires ~1.2s after its 'finished.' line
  const navUrl = await page.waitForRequest((r) => r.url().includes('evil09-nav-exfil'), { timeout: 10000 }).then((r) => r.url()).catch(() => null);
  const poisoned = await page.waitForFunction(() => JSON.stringify(window.__evilStore()).includes('__evil09_poison__'), null, { timeout: 10000 }).then(() => true).catch(() => false);
  check('very-evil: UNVERIFIED stage-2 bytes POISONED the verified namespace (__evil09_poison__)', poisoned);
  const navExfil = !!navUrl && navUrl.includes('victim-data-INHERITED-BY-EVIL-09');
  check('very-evil: navigation-URL exfil reached the collector with the seed', navExfil, navUrl || exfil.map((e) => e.url.slice(0, 90)).join(' || '));
  const fetchExfil = exfil.some((e) => (e.body || '').includes('victim-data-INHERITED-BY-EVIL-09'));
  check('very-evil: window-keying exfil captured (fetch channel, csp off)', fetchExfil);
  check('very-evil: both exfil channels fired (fetch + navigation URL)', exfil.length >= 2, exfil.length + ' requests');
  await page.close();
}

await browser.close();
check.finish();
