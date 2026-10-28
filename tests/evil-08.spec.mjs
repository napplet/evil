// evil-08 — wasm timing & same-process gadgets: the spec baseline itself arms
// wasm in-process, and opaque-origin frames share the renderer main thread
// with the shell (starvation measurable shell-side).
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil, evidence } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// spec preset: wasm arms (baseline mandates it), same-thread contention arms
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: "evil-08-wasm-timing", settleMs: 8000 });
  const st = await statuses(f);
  check('spec: WebAssembly compiles under the spec baseline (arms)', st['wasm-compile'] === 'armed', JSON.stringify(st));
  check('spec: timer resolution measurable (arms)', st['timer-resolution'] === 'armed');
  const sameThread = st['same-thread'];
  check('spec: same-main-thread contention probe ran', sameThread === 'armed' || sameThread === 'na', String(sameThread));
  if (sameThread === 'armed') {
    const ev = await evidence(f, 'same-thread');
    check('spec: shell STARVED by napplet busy loop (not site-isolated)', ev.includes('STARVED'), ev.slice(0, 180));
  } else {
    console.log('NOTE same-thread probe reported na — shell appears isolated or echo contention unmeasurable');
  }
  check('spec: cache oracle honestly refused (na)', st['cache-oracle'] === 'na');
  await page.close();
}

// VERY EVIL: the storm runs for real — 1500ms main-thread freeze delivered
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: "evil-08-wasm-timing", csp: false, settleMs: 8000 });
  await armVeryEvil(f, BASE + '/collect', 60000);
  const wasmOut = exfil.some((e) => (e.body || '').includes('wasm-proof'));
  const stormOut = exfil.some((e) => (e.body || '').includes('same-thread-contention'));
  check('very-evil: wasm executed in-process and exfiltrated', wasmOut);
  check('very-evil: storm contention model exfiltrated', stormOut, exfil.map((e) => (e.body || '').slice(0, 60)).join(' || '));
  await page.close();
}

await browser.close();
check.finish();