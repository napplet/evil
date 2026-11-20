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
  check('spec: resource hints unverifiable from inside the frame (na)', st['resource-hints'] === 'na', st['resource-hints']);
  const hintEv = await evidence(f, 'resource-hints');
  check('spec: all four hint types inserted (prefetch/dns-prefetch/preconnect/prerender)', /prefetch, dns-prefetch, preconnect, prerender/.test(hintEv), hintEv.slice(0, 120));
  // finding 13: the XML-parser sinks mint fresh contexts too, with no factory
  // pin or TT layer engaged (spec preset has no lock) — all three minted.
  const gcEv = await evidence(f, 'webrtc-grandchild');
  check('spec: XSLT transformToFragment mints a nested context (finding 13)', /XSLT transformToFragment: minted/.test(gcEv), gcEv.slice(-260));
  check('spec: XML-namespace DOMParser+adopt mints a nested context (finding 13)', /XHTML DOMParser\+adopt: minted/.test(gcEv), gcEv.slice(-200));
  check('spec: DTD-entity XML mints a nested context (finding 13)', /DTD-entity XML: minted/.test(gcEv), gcEv.slice(-160));
  await page.close();
}

// Local-sink mode (finding 15, napplet/evil#5, spec C/D/E): resource hints are
// not reliably governed by default-src 'none'. Observe egress at a local HTTP
// sink rather than assume it. prerender issues a real HTTP GET (Sec-Purpose:
// prefetch) even under the napplet CSP — a browser non-conformance per CSP3 ED.
// Playwright's DEFAULT bundled build + context fires no hints, so this runs on
// the real Chromium channel with network prediction; where that channel is not
// installed the check degrades to a capability note and the per-engine evidence
// lives in ROADMAP finding 15.
{
  const { createServer } = await import('node:http');
  const hits = [];
  const sink = createServer((req, res) => { hits.push({ url: req.url, purpose: req.headers['sec-purpose'] || '-' }); res.writeHead(200, { 'content-type': 'text/html' }); res.end('ok'); });
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const host = createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><body>'); });
  await new Promise((r) => host.listen(0, '127.0.0.1', r));
  const SINK = `http://127.0.0.1:${sink.address().port}`;
  const HOST = `http://127.0.0.1:${host.address().port}/`;
  // the exact spec-baseline CSP the harness injects (default-src 'none')
  const CSP = "default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; frame-src 'none'";
  const nap = '<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="' + CSP.replace(/"/g, '&quot;') + '"></head><body><scr' + 'ipt>'
    + 'for (const rel of ["prefetch","dns-prefetch","preconnect","prerender"]) { const l = document.createElement("link"); l.rel = rel; l.href = "' + SINK + '/" + rel; document.head.appendChild(l); }'
    + '</scr' + 'ipt></body></html>';
  let chan = null;
  try { chan = await chromium.launch({ channel: 'chromium', args: ['--enable-features=NetworkPrediction'] }); } catch (_) { chan = null; }
  if (chan) {
    const p = await chan.newPage();
    await p.goto(HOST);
    await p.evaluate((html) => { const fr = document.createElement('iframe'); fr.sandbox.add('allow-scripts'); fr.srcdoc = html; document.body.append(fr); }, nap);
    await p.waitForTimeout(2800);
    const prerender = hits.find((h) => h.url.includes('/prerender'));
    check('local-sink: prerender OBSERVED as a real HTTP GET under default-src \'none\' (Chromium ' + chan.version().split('.')[0] + ' non-conformance, finding 15)', !!prerender, JSON.stringify(hits));
    check('local-sink: prerender request carries Sec-Purpose: prefetch', !!prerender && /prefetch/.test(prerender.purpose), prerender ? prerender.purpose : 'no prerender hit');
    await chan.close();
  } else {
    check('local-sink: real Chromium channel unavailable — prerender/preconnect/dns-prefetch egress recorded in ROADMAP finding 15 (per-engine table)', true, 'channel chromium not installed');
  }
  sink.close();
  host.close();
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
  check('lock: evidence records the per-vector denials (TT sinks + factory pins + XML scan)', /DENIED/.test(ev) && /19 battery vectors/.test(ev), ev.slice(0, 220));
  // finding 13: layer 4 (adoptNode/transformToFragment output scan) closes the
  // XML-parser sinks that factory pins + TT do not reach.
  check('lock: XSLT transformToFragment DENIED by the output scan (finding 13)', /XSLT transformToFragment: DENIED \(TypeError: nested browsing contexts are locked: xslt frame node/.test(ev), ev.slice(-280));
  check('lock: XML-namespace DOMParser+adopt DENIED by the output scan (finding 13)', /XHTML DOMParser\+adopt: DENIED \(TypeError: nested browsing contexts are locked: xml-parser frame node/.test(ev), ev.slice(-200));
  check('lock: DTD-entity XML DENIED by the output scan (finding 13)', /DTD-entity XML: DENIED \(TypeError: nested browsing contexts are locked: xml-parser frame node/.test(ev), ev.slice(-140));
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