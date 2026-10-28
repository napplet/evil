// evil-02 — CSP & network egress: spec baseline closes every fetch directive,
// WebRTC is the spec-gap finding (arms even under the spec's own baseline).
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil } from './_helper.mjs';

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