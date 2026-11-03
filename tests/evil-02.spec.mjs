// evil-02 — CSP & network egress: spec baseline closes every fetch directive;
// WebRTC is the spec-gap finding (arms even under the spec's own baseline), and
// the grandchild-frame battery (kehto/web#381) proves fresh nested realms carry
// a live RTCPeerConnection no CSP reaches. The harness nestedlock knob mirrors
// kehto/web#393 prevention — the green gate the battery must not survive.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence, shellLogIncludes } from './_helper.mjs';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// spec preset: everything held EXCEPT WebRTC (spec gap) and hints (na)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-02-csp-egress" });
  const st = await statuses(f);
  check('spec: fetch egress held', st['fetch'] === 'blocked', JSON.stringify(st));
  check('spec: xhr egress held', st['xhr'] === 'blocked');
  check('spec: websocket egress held', st['websocket'] === 'blocked');
  check('spec: eventsource egress held', st['eventsource'] === 'blocked');
  check('spec: beacon egress held', st['beacon'] === 'blocked');
  check('spec: img beacon egress held', st['img-beacon'] === 'blocked');
  check('spec: media beacon egress held', st['media-beacon'] === 'blocked');
  check('spec: eval canary held (CSP enforced)', st['eval-csp'] === 'blocked');
  check('spec: WebRTC DATA CHANNEL ARMS — no CSP directive covers it (spec gap)', st['webrtc'] === 'armed', st['webrtc']);
  check('spec: WebRTC GRANDCHILD ARMS — fresh nested realm, no CSP directive reaches it (kehto/web#381)', st['webrtc-grandchild'] === 'armed', st['webrtc-grandchild']);
  check('spec: prefetch hint unverifiable (na)', st['prefetch-hint'] === 'na');
  await page.close();
}

// no CSP: egress channels open
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-02-csp-egress", csp: false, settleMs: 16000 });
  const st = await statuses(f);
  check('no-csp: fetch egress arms', st['fetch'] === 'armed', JSON.stringify(st));
  check('no-csp: beacon egress arms', st['beacon'] === 'armed');
  check('no-csp: eval canary arms (no CSP)', st['eval-csp'] === 'armed');
  check('no-csp: WebRTC arms', st['webrtc'] === 'armed');
  check('no-csp: WebRTC grandchild arms (fresh realm regardless of CSP)', st['webrtc-grandchild'] === 'armed', st['webrtc-grandchild']);
  await page.close();
}

// nestedlock knob ON — kehto/web#393-style prevention (TT default policy +
// factory pins + byte scan): the grandchild battery must be HELD.
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-02-csp-egress", nestedlock: true });
  const st = await statuses(f);
  check('lock: grandchild battery HELD — zero nested contexts minted (#393 prevention)', st['webrtc-grandchild'] === 'blocked', st['webrtc-grandchild']);
  const len = await f.evaluate(() => window.length);
  check('lock: window.length 0 across the whole bypass battery', len === 0, String(len));
  const ev = await evidence(f, 'webrtc-grandchild');
  check('lock: evidence records the per-vector denials (TT sinks + factory pins)', /DENIED/.test(ev) && /16 battery vectors/.test(ev), ev.slice(0, 220));
  const tt = await f.evaluate(() => String(window.__evilLockTT));
  check('lock: TT default policy registered in the napplet realm', tt === 'default policy registered', tt);
  check('lock: top-realm webrtc unaffected (the lock prevents contexts, it does not neuter RTC)', st['webrtc'] === 'armed', st['webrtc']);
  check('lock: CSP egress rows unchanged (fetch still held)', st['fetch'] === 'blocked', st['fetch']);
  // byte scan layer: fail closed on static frame markup, before any document
  const fixture = 'napplets/evil-scan-fixture';
  mkdirSync(fixture, { recursive: true });
  writeFileSync(fixture + '/index.html', '<!doctype html><html><head><title>f</title></head><body><iframe srcdoc="x"></iframe></body></html>');
  try {
    await page.evaluate(() => { const s = document.getElementById('nappletSel'); const o = document.createElement('option'); o.value = 'evil-scan-fixture'; s.appendChild(o); });
    await page.selectOption('#nappletSel', 'evil-scan-fixture');
    const framesBefore = await page.evaluate(() => document.querySelectorAll('iframe').length);
    await page.click('#loadBtn');
    await page.waitForTimeout(600);
    const metaTxt = await page.evaluate(() => document.getElementById('meta').textContent);
    const refused = metaTxt.includes('REFUSED') && await shellLogIncludes(page, 'REFUSED load');
    const framesAfter = await page.evaluate(() => document.querySelectorAll('iframe').length);
    check('lock: byte scan REFUSES static frame markup (fail closed, no new frame)', refused && framesAfter === framesBefore, metaTxt.slice(0, 200));
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
  await page.close();
}

// VERY EVIL: armed egress channels actually fire toward the collector
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: "evil-02-csp-egress", csp: false, settleMs: 16000 });
  const gate = await armVeryEvil(f, BASE + '/collect');
  check('very-evil: exfil fired over open egress (fetch/beacon to collector)', exfil.length >= 2, exfil.map((e) => e.url).join(', '));
  check('very-evil: gate enforced (disabled before, wrong case held, exact enables)',
    gate.disabledBefore && gate.wrongCaseHeld && gate.enabled);
  await page.close();
}

await browser.close();
check.finish();