# Attack ladder — evil napplets

Ordered from lowest hanging fruit (misconfigured / lazy runtimes) to the most nuanced
(assaults on well-hardened runtimes, and on the NIP-5D specification itself).
**All nine rungs are built and validated** — 169 automated checks against real
Chromium (`tests/`). Each rung names the spec clause it attacks, what arms it,
and what validation proved.

## Tier 0 — baseline misconfig (poorly implemented runtimes)

These attacks land whenever a runtime gets a *must* wrong. A well-implemented
runtime passes every probe (this is the security-lab's job); the evil napplet's
job is to show what each mistake costs, with a real payload behind the gate.

### ✅ `evil-01-sandbox-escape` — the load-bearing preconditions

Status: **built + validated** — 18/18 (`tests/evil-01.spec.mjs`)

Validated results:

- **spec-compliant runtime holds every escape probe** (origin, storage, SW,
  parent DOM, NIP-07, navigation, popups) — the suite is a runtime CI gate.
- **spec gap confirmed (findings #2):** the embedding URL leaks into the srcdoc
  frame three ways in the fully compliant preset — `document.referrer` (the
  shell URL), `document.baseURI` (the FULL embedding URL incl path/query/fragment
  for srcdoc), and `location.ancestorOrigins` (the embedding origin). No NIP-5D
  guidance on Referrer-Policy exists, and `no-referrer` only closes *one* of the
  three: a no-referrer iframe attr empties `document.referrer` (Chromium,
  Firefox; WebKit 26.4 ignores it for srcdoc) and a host `<meta name="referrer"
  content="no-referrer">` works in all three — but neither touches `baseURI`,
  which only a host-page `<base href>` changes, nor `ancestorOrigins`. A meta in
  the artifact also runs counter to the hashed-bytes rule, so this needs
  spec-level thought.
- **refinement:** `allow-same-origin` alone does **not** grant ancestor
  navigation — the browser's sandbox navigation flag held
  `parent.location.replace()` even in the sloppy preset. Full hijack needs a
  missing `sandbox` attribute; read access still escapes.
- **sibling enumeration** (findings #3) arms as soon as any sibling frame
  exists, from an opaque origin, in a compliant runtime — `parent.length`
  counts this frame too, so the probe reports `length − 1`.

Attacks every *must* in [NIP-5D §Security](../napplets/evil-01-sandbox-escape/index.html):

| # | Attack | Spec clause |
|---|--------|-------------|
| 1 | Opaque origin — `window.origin === 'null'`? | `sandbox="allow-scripts"` and **never** `allow-same-origin` |
| 2 | Direct browser storage on a real shared origin | "Napplets have no access to `localStorage`…" |
| 3 | Service-worker registration → persistent backdoor | same-origin grants SW on the shell origin |
| 4 | Parent DOM read (cookies, rendered secrets) | "The shell is trusted; the napplet is not" |
| 5 | Ambient `window.nostr` — sign as the user | "Shells MUST NOT provide `window.nostr`" |
| 6 | Parent navigation — shell hijack | sandbox must not permit ancestor navigation |
| 7 | embedding-URL leak (`referrer` / `baseURI` / `ancestorOrigins`) | *spec is silent — findings #2* |
| 8 | Popup escape via `window.open` | sandbox must not permit popups |
| 9 | Sibling napplet enumeration (`parent.length`) | *cross-origin-legal even in compliant runtimes — findings #3* |

Armed by: `allow-same-origin` on the iframe, a missing `sandbox` attribute, or a
NIP-07 extension injecting `window.nostr` into iframes (all_frames).

### ✅ `evil-02-csp-egress` — CSP & network egress

Status: **built + validated** — 34/34 (`tests/evil-02.spec.mjs`)

`connect-src 'none'` is the only thing between an opaque-origin frame and the
network (a srcdoc iframe has no HTTP response to carry a CSP *header*).

Validated results:

- Under the spec baseline **every fetch-directive channel is held** — fetch,
  XHR, WebSocket, EventSource, sendBeacon, img/media beacons — and the eval
  canary confirms `wasm-unsafe-eval` without `unsafe-eval` enforcement.
- **Spec gap confirmed (findings #1): `RTCPeerConnection` +
  `createDataChannel` succeed with no CSP violation, under the spec's own
  conservative baseline.** No directive covers WebRTC. Runtimes need a
  Permissions Policy or constructor neutering in the injected namespace;
  NIP-5D's advisory should say so.
- **Spec gap confirmed (findings #12, kehto/web#381): the grandchild-frame
  WebRTC vector.** The `webrtc` probe only measures the top napplet realm —
  a runtime that neuters `RTC*` there (kehto/web#384/#386) reports WebRTC
  closed while a child frame still buys a fresh realm with a live
  `RTCPeerConnection`. `webrtc-grandchild` runs a kehto/web#393-mirror
  bypass battery — createElement case variants, createElementNS,
  innerHTML/outerHTML/insertAdjacentHTML, DOMParser+adopt,
  createContextualFragment, setHTMLUnsafe, template clone, execCommand
  insertHTML, factory recovery (delete+reassign), fresh `Document`
  (implementation.createHTMLDocument+adopt), object/embed — and reports every
  per-vector result. Under the spec baseline multiple vectors mint
  `about:srcdoc` realms whose RTC is live (frame-src does not reach srcdoc
  children). `document.write` is documented, not executed: it destroys the
  probe UI — same Trusted Types string-sink class as innerHTML, which the
  battery does exercise. Only prevention closes the vector while no
  `webrtc` CSP directive exists — the #393 class — which the harness
  `nested-context lock` knob mirrors (Trusted Types default policy passing
  canonical HTML and rejecting frame-tag strings, non-configurable factory
  pins, fail-closed byte scan of the verified bytes, plus an
  adoptNode/transformToFragment output scan for the XML-parser sinks —
  findings #13). Lock OFF — the battery arms and the fresh realms report live
  RTC; lock ON — zero contexts minted, `window.length` stays 0 across all 19
  vectors. Both paths are CI-gated.
- **Spec gap confirmed (findings #13, napplet/evil#5): XML parsers mint nested
  contexts past a factory-pin + Trusted Types prevention layer.** Three vectors
  added to the `webrtc-grandchild` battery build a frame element without ever
  calling `createElement`/`createElementNS` or assigning a TrustedHTML string
  sink, then move it live with `adoptNode`/`transformToFragment`:
  `XSLTProcessor.transformToFragment` (`xsl:element name="iframe"`),
  prefixed-namespace XHTML via `DOMParser(…, 'application/xml')` + `adoptNode`,
  and DTD general-entity expansion. Each sets `srcdoc` via `setAttribute` on the
  parsed node (not a factory, not a TT sink). Under the harness lock's first
  three layers all three still mint `window.length > 0`; only a fourth layer —
  an output scan on `adoptNode`/`importNode`/`transformToFragment` — closes
  them. Measured minting in Chromium 147, Firefox 148, WebKit 26.4; CI-gated
  both ways (lock OFF → minted, lock ON → DENIED by the output scan).
- **Resource hints are not reliably governed by `default-src 'none'` (findings
  #15, napplet/evil#5).** The `resource-hints` row inserts prefetch,
  dns-prefetch, preconnect and prerender; all four are unverifiable from inside
  the frame (no violation/load/error event), so demo mode is honest `na`. The
  **local-sink mode** observes the egress out-of-frame instead of assuming it:
  pointed at a local HTTP sink on the real Chromium channel, `prerender` issues a
  real HTTP GET carrying `Sec-Purpose: prefetch` even under the napplet's
  `default-src 'none'` CSP — a browser non-conformance against CSP3 ED
  (`w3c/webappsec-csp@e3461f7`, which places these under `default-src`). CI-gated
  in `tests/evil-02.spec.mjs`; Playwright's default bundled build fires no hints,
  so the gate uses `channel: 'chromium'` + `--enable-features=NetworkPrediction`
  and degrades to a capability note where that channel is absent.

## Tier 1 — transport confusion (lazy runtimes)

### ✅ `evil-03-transport-forge` — envelope forging & reply injection

Status: **built + validated** — 19/19 (`tests/evil-03.spec.mjs`)

postMessage `'*'` is required (opaque origins have no origin to target), so the
**only** sender identity is `MessageEvent.source`. Attacks: forged reply
envelopes with guessed ids, sequential-id injection storms, declared-identity
spoofing (`windowId`/`dTag`/`artifactHash` fields), unknown-source nested
relays, and shell-broadcast harvesting.

Validated results:

- **A compliant router holds**: declared-identity spoofing gets routed to the
  *source* namespace (the trap key is absent there: NAP-STORAGE `value: null`,
  or a pre-spec `no such key` error), never the declared one.
- **A router that trusts declared fields arms**: the probe reads a value out
  of the declared sibling's namespace — any frame can act as any napplet.
- **New finding (validated): srcdoc child iframes are NOT blocked by
  `frame-src`.** An unmapped grandchild frame can message the shell directly;
  the only defense is the source check (conforming shells drop — the harness
  log shows `DROPPED`). NIP-5D's "messages from unknown sources MUST be
  silently dropped" is load-bearing here, and the CSP advisory's `frame-src
  'none'` is *not* the control it looks like.
- **Port-bound shells (napplet/evil#3)**: every probe except
  `shell-broadcast` posts window-level, so they are `windowLevel` rows and the
  sweep runs them last. Under `binding: port` the harvest finishes first, then
  the first window-level `storage.get` gets the frame REVOKED and removed;
  `evil-window-level=skip` reports them `na` with no revocation.

## Tier 2 — manifest & identity confusion

### ✅ `evil-04-manifest-confusion` — manifest attacks + launcher XSS

Status: **built + validated** — 6/6 (`tests/evil-04.spec.mjs`)

The manifest is attacker-authored input that *drives* runtime decisions. The
artifact probes what the runtime believed about it, and ships a kit of crafted
manifests (multi-`x`, hash-mismatch TOCTOU bait, XSS metadata, icon bomb) for
shell-side testing.

Validated results:

- **srcdoc vs src (TOCTOU)**: `location.href === 'about:srcdoc'` proves the
  running bytes are the verified bytes; a src-loaded frame reports its URL —
  re-fetch after verification means identity is broken.
- **Launcher metadata XSS**: rendering manifest `title`/`content` as HTML is
  script **in the shell origin** — no sandbox escape needed. Under the unsafe
  launcher the demo probe arms via a ping-back, and VERY EVIL mode defaces
  the shell and pings the collector from shell origin, end to end.
- The sandbox grant audit (origin/storage/popup inference) held under `spec`.

### ✅ `evil-05-substitution` — Nostr-level substitution & storage inheritance

Status: **built + validated** — 12/12 (`tests/evil-05.spec.mjs`)

Validated results, across three storage namespace policies:

- **`by-(dTag+artifactHash)` isolates**: no inherited secrets, no cross-namespace
  reads. This is the policy NAP-STORAGE should mandate (findings #7).
- **`by-dTag` arms**: a substituted/version-bumped napplet **inherits the
  victim's stored secrets** — the v1 canary came back through the frame.
- **`global` arms twice over**: inheritance plus reads of *other* napplets'
  namespace keys.
- VERY EVIL under `by-dTag` exfiltrated the inherited secret to the collector
  and **poisoned the namespace for the next heir**.
- The storage probes (evil-05, evil-06, evil-09) call the NAP-STORAGE names
  `getItem` / `setItem` / `removeItem` / `keys` (napplet/naps#3). A shell that
  only exposes the pre-spec `get` / `set` / `remove` gets an explicit `na`
  naming that shape, not a TypeError; the specs gate the spec shape in both
  window and port binding.
- The kit carries the unbound-dTag manifest (attacker key, victim dTag —
  findings #5) and a rollback/replay manifest (findings: no freshness rule).

## Tier 3 — side channels & spec loopholes (hardened runtimes)

NIP-5D explicitly does *not* protect against side-channel attacks
("Non-Guarantees"). These napplets measure exactly how much leaks anyway.

### ✅ `evil-06-side-channels` — oracles on shell mediation

Status: **built + validated** — 19/19 (`tests/evil-06.spec.mjs`)

Validated results:

- **Storage key-existence timing oracle ARMS under a fully compliant runtime**:
  hit vs miss latency separates cleanly (the harness backend answers ~40ms vs
  ~6ms) — key existence is readable through the ACL boundary by latency alone.
- **Error taxonomy oracle arms**: a `null` miss vs "value too large" vs
  "policy denied" map the runtime's ACL boundaries for free.
- **Shell scheduler RTT channel arms**: the parent echo round-trip is
  measurable from inside — recon for the same-process gadgets (see evil-08).
- Without an injected runtime the oracles close (`na`) — mediation is the
  leak surface.
- **Port-bound shells (napplet/evil#3)**: `shell-rtt` is the only
  window-level row (`evil.ping`), so it runs last; under `binding: port` the
  storage timing oracle and the error taxonomy complete over the port before
  the shell revokes on the first ping. `evil-window-level=skip` keeps the frame
  bound and reports `shell-rtt` as `na`.

### ✅ `evil-07-fingerprint` — identification that survives compliance

Status: **built + validated** — 4/4 (`tests/evil-07.spec.mjs`)

Validated results: under a fully spec-compliant preset, **every passive
identification probe arms** — UA/platform/languages, cores/RAM class, screen
geometry + DPR, timezone/locale, font enumeration (style-src is
`'unsafe-inline'`), GPU renderer strings (WebGL — no directive), media device
inventories (camera/mic *counts*, no permission), network class, plus the
cross-origin-legal shell composition channel (`parent.length`, referrer,
`window.name`). VERY EVIL bundles and exfiltrates the fingerprint —
identification, not just capability.

### ✅ `evil-08-wasm-timing` — wasm & same-process gadgets

Status: **built + validated** — 7/7 (`tests/evil-08.spec.mjs`)

Validated results:

- **WebAssembly compiles under the spec's own baseline** (`wasm-unsafe-eval`)
  and executes in-process: attacker native code in the shell's renderer, by
  spec (findings #4).
- **Same-main-thread contention VALIDATED**: a 300ms busy loop in the napplet
  starved the *shell's* message handler by the full storm duration (measured
  shell-side via wall-clock echo) — opaque-origin srcdoc frames are **not
  site-isolated**, so napplets can DoS the trusted shell from inside the
  sandbox.
- Timer resolution is measurable (~clamped 100µs) — timing side channels have
  fuel.
- `SharedArrayBuffer` correctly closed without `crossOriginIsolated`.
- The cross-origin cache oracle is **honestly refused** (`na`): no legible
  oracle exists from in-frame JS — that tier is reserved for genuine
  microarchitectural work.

### ✅ `evil-09-self-replacement` — frame self-replacement & identity inheritance

Status: **built + validated** — 50/50 (`tests/evil-09.spec.mjs`)

The pre-#14 spec mapped `(dTag, artifactHash)` — and every grant — to the
iframe **`Window`**. A Window survives same-frame navigation, and no sandbox
token or CSP fetch directive stops a frame from navigating *itself*: a napplet
can replace its own document with unverified bytes that the shell keeps
routing as the verified napplet. Fixed upstream by NIP-5D PR #14 (per-document
`MessagePort` binding + revoke-on-replacement); this rung and the harness
`identity binding: port` knob are the regression gate.

Validated results:

- **The primitive always exists**: `allow-scripts` does not stop self-
  navigation — DETONATE (operator-triggered, never auto-run) replaced the
  verified document in-place, same Window, via both the network path
  (`harness/replace-target.html`, the attacker-page stand-in) and a data: URL.
- **The network target is a run parameter** (napplet/evil#3): `evil09-target`
  names it, and the harness injects the same-host fixture by default. It used
  to come from `document.referrer`, so a shell that empties the referrer
  silently turned the probe into the data: path. Now an absent or empty value
  is an explicit scheme-local run, an http(s) URL is the network run, and any
  other scheme is rejected without navigating. The suite also proves the
  target holds with the iframe's referrer stripped (`referrerpolicy=no-referrer`).
- **Window-keyed shells hand over everything**: raw window-level NAP from the
  unverified stage-2 bytes was ACCEPTED and served the verified napplet's
  namespace seed (`victim-data-INHERITED-BY-EVIL-09`); the shell logged the
  attacker document's report and left the frame in place — no teardown, no
  clue.
- **CSP fate is path-dependent** (a refinement of the #14 text): on the
  *network* replacement the injected meta CSP evaporates — eval() was blocked
  in the verified document and runs in the replacement, exactly as the #14
  Security Considerations describe. But Chromium's policy-container inheritance
  carries the meta CSP through *data:/blob:* replacements — the CSP held there.
  The realistic attack (attacker's own page) is the CSP-free path; scheme-local
  replacements get Chromium's bonus hardening.
- **Navigation-URL disclosure survives the fix**: data the verified napplet
  legitimately read crossed the document boundary inside the navigation URL
  and arrived in the replacement's `location.search` — no directive governs a
  frame navigating itself, and post-#14 revocation cannot recall it.
- **The port-bound knob holds (the green gate)**: under `identity binding:
  port` the NAP roundtrip shows no window-level envelope to sniff, and
  detonation ends in `REVOKED` — the shell drops the replacement document's
  window-level NAP as replacement evidence, tears the identity, grants, and
  iframe down. No stage-2 write can land.
- VERY EVIL under window binding: unverified stage-2 bytes POISONED the verified
  namespace (`__evil09_poison__` for the next legit load to inherit) and
  exfiltrated the seed to the collector via the navigation URL — two egress
  channels, end to end.
- **Pre-load self-navigation (findings #14, napplet/evil#5)**: a napplet whose
  FIRST inline script self-navigates replaces its own document *before the
  frame's first load event fires*. Replacement-watch keyed on a second load or a
  second `napplet.hello` has no baseline — there was never a first load of the
  verified document to diff against. Measured with a pre-load fixture: under
  window binding the data: replacement's raw window-level `storage.get` is
  ACCEPTED and served the verified seed with no teardown; under the port binding
  it is `REVOKED` all the same, because post-handoff window-level NAP is
  replacement evidence whatever the timing — so the port binding is the gate.
  The target scheme (data:/blob:/https:) is governed only by the *embedding
  page's* frame navigation policy, not the napplet's own CSP — and that is the
  second gate: the harness `host frame-src 'none'` knob (`?hostframesrc=none`)
  puts `frame-src 'none'` on the embedding page; the shell's srcdoc napplet still
  loads and runs, but the pre-load self-navigation to data: or http(s): is
  blocked (`HOST CSP BLOCKED frame-src`, no request reaches the target) even
  under window binding. Without it the http(s) navigation lands. All paths
  CI-gated (`tests/evil-09.spec.mjs`).

| # | Attack | Spec clause |
|---|--------|-------------|
| 1 | identity keyed to this Window (passive window-level NAP sniff) | pre-#14 §Transport/§Identity: window-level postMessage + "map the iframe's Window" |
| 2 | frame self-replacement → identity & grant inheritance by unverified bytes | pre-#14 §Identity; #14: "a Window reference survives same-frame navigation" |
| 3 | injected meta CSP evaporation on network replacement | §Security CSP advisory; #14: "a meta CSP applies only to the document it was injected into" |
| 4 | navigation-URL data disclosure (survives the fix by design) | #14 §Security: "cannot recall what was already sent" |
| 5 | replacement telemetry (second hello / load / port close — shell-side, honestly `na`) | post-#14 §Identity: revoke-on-replacement evidence |

Armed by: every pre-#14-shaped shell (the spec's own model). Disarmed by: the
post-#14 port binding — bind identity to the port the verified document's
bootstrap hands over, revoke on a second `hello`/`load`/post-handoff
window-level message/port close, and never speak NAP over
`iframeWindow.postMessage`.

## Validated findings against the NIP-5D spec

Research notes for spec issues (to file upstream as the napplets validate them):

1. ✅ **WebRTC is outside CSP** — no directive governs `RTCPeerConnection`; the
   conservative baseline still allows data-channel egress (validated by
   evil-02).
2. ✅ **No Referrer-Policy guidance, and referrer is not the only channel** — a
   srcdoc napplet inherits the embedding URL/origin in a compliant runtime via
   three channels, not one: `document.referrer` (the shell URL),
   `document.baseURI` (the FULL embedding URL incl path/query/fragment for
   srcdoc), and `location.ancestorOrigins` (the embedding origin, where
   supported — Chromium/WebKit yes, Firefox no). Measured (Kehto Playwright
   probes): a no-referrer iframe attr empties `document.referrer` in Chromium
   and Firefox but **WebKit 26.4 ignores it for srcdoc**; a host-page `<meta
   name="referrer" content="no-referrer">` empties it in all three. Neither
   touches `baseURI` — only a host-page `<base href>` changes it — nor
   `ancestorOrigins`. So `no-referrer` guidance alone is insufficient; the spec
   should address `baseURI`/`ancestorOrigins` too (validated by evil-01/07).
3. ✅ **Cross-origin window accessibles** — `parent.length`/`parent.frames.length`
   are readable from an opaque-origin napplet → sibling enumeration channel
   (validated by evil-01/07).
4. ✅ **`wasm-unsafe-eval` is same-process by construction** — srcdoc frames with
   opaque origins are not site-isolated; the spec mandates Wasm compilation in
   the shell's own renderer process, and napplets can starve the shell's main
   thread (validated by evil-08).
5. 🔎 **`dTag` resolution is unbound** — "resolve the manifest and verify its
   signature" never says *whose* signature a named/replaceable napplet must
   carry (kit attack in evil-05; shell-side resolution needed to validate).
6. 🔎 **Reply routing is unspecified** — the wire format has `id` correlation but
   no rule that replies route only to the Window that sent the request
   (evil-03 probes dispatch; acceptance is runtime-side).
7. ✅ **Storage namespacing is unspecified** — `by-(dTag, artifactHash)` isolates;
   `by-dTag` lets substituted heirs inherit victim secrets; `global` shares
   everything (validated across all three policies by evil-05).
8. 🔎 **Icon decode caps unspecified** — PNG verification without pixel-area caps
   is a shell DoS (kit payload in evil-04; needs a launcher to validate).
9. ✅ **srcdoc children are not blocked by `frame-src`** — unmapped grandchild
   frames can message the shell directly; the `MessageEvent.source` check is
   the only defense (validated by evil-03: shells drop, but the CSP advisory
   implies more coverage than `frame-src 'none'` delivers).
10. 🔎 **Manifest metadata rendering** — "plain text, not HTML" is a MUST on
    clients; innerHTML launchers hand the shell to the attacker (validated
    against the unsafe launcher in evil-04).
11. ✅ **Window-keyed identity survives self-replacement** — pre-#14 NIP-5D
    mapped `(dTag, artifactHash)` + every grant to the iframe `Window`, which
    persists across same-frame navigation: a napplet that navigates its own
    frame hands the verified identity to unverified bytes (validated by
    evil-09 — grants, namespace, and shell log all served the replacement
    document). The injected meta CSP is per-document: it dies with the
    verified document on network navigations (eval re-opened in the
    replacement) but Chromium's policy-container inheritance carries it
    through data:/blob: replacements. Fixed upstream by NIP-5D #14
    (per-document MessagePort binding + revoke-on-replacement); the harness
    `identity binding: port` knob is the regression gate.
12. ✅ **Grandchild frames mint fresh un-neutered realms** — an
    `about:srcdoc`/`about:blank` child of a napplet is a fresh realm with a
    live `RTCPeerConnection` that NO CSP directive reaches (`frame-src` does
    not block srcdoc children), so top-realm `RTC*` neutering
    (kehto/web#384/#386) is invisible to it: a napplet mints a child frame and
    egresses from there (kehto/web#381 — the gap kehto/web#393's prevention
    closed in Kehto). While no `webrtc` CSP directive exists, only prevention
    closes it: the #393 class — Trusted Types default policy + pinned
    element factories + a fail-closed host byte scan (plus the XML-parser
    output scan of findings #13). Validated by evil-02's `webrtc-grandchild`
    battery; the harness `nested-context lock` knob is the green gate (arms
    off / holds on, both CI-gated).
13. ✅ **XML parsers are a nested-context sink past factory pins + Trusted
    Types** — a frame element built by an XML parser never passes through
    `createElement`/`createElementNS` or a TrustedHTML string sink, so a
    prevention layer made of pinned element factories plus a Trusted Types
    default policy (plus a static byte scan, which does not match runtime XML
    strings) does not reach it. Three vectors mint a live `about:srcdoc`
    grandchild past such a layer: `XSLTProcessor.transformToFragment` emitting
    `xsl:element name="iframe"`, prefixed-namespace XHTML via
    `DOMParser(…, 'application/xml')` + `adoptNode`, and DTD general-entity
    expansion; each sets `srcdoc` with `setAttribute` on the parsed node. Only
    an output scan on `adoptNode`/`importNode`/`transformToFragment` (a fourth
    layer) closes them. This is a completeness gap in the #393-class prevention
    (kehto/web#381 follow-up), not a browser non-conformance — no `webrtc` CSP
    directive governs any of it. Measured minting in Chromium 147, Firefox 148,
    WebKit 26.4; validated by evil-02's `webrtc-grandchild` battery (19 vectors)
    with the harness `nested-context lock` the green gate (arms off / holds on,
    both CI-gated). Supports treating `window.length > 0` as nested-context /
    replacement evidence at the spec level.
14. ✅ **Replacement-watch is blind to a pre-first-load self-navigation** — a
    napplet whose first inline script navigates the frame to data:/blob:/https:
    replaces its own document before the frame ever fires a first load event, so
    a shell that detects replacement by counting loads or waiting for a second
    `napplet.hello` has no baseline to diff against. Measured: under window
    binding the data: replacement's raw window-level `storage.get` is ACCEPTED
    and served the verified napplet's seed with no teardown; under the post-#14
    port binding it is `REVOKED` all the same, because treating any post-handoff
    window-level NAP as replacement evidence is timing-independent — that, not
    load-counting, is one control that holds. The other is the *embedding
    page's* frame navigation policy, which alone governs the target scheme: an
    embedding-page `frame-src 'none'` leaves the shell's srcdoc napplet loading
    normally but blocks its pre-load self-navigation to data: or http(s):
    (measured in Chromium here; Chromium 147, Firefox 148.0.2, WebKit 26.4 per
    the independent re-measurement). Validated by evil-09's pre-load fixture
    (window serves / port revokes / host `frame-src 'none'` blocks, all
    CI-gated);
    repro in the evil-09 kit. Supports the NIP-5D proposal that replacement
    evidence cannot be keyed on the first `load`. (napplet/evil#5)
15. ✅ **Resource hints are not reliably governed by `default-src 'none'`** — a
    srcdoc napplet under the spec baseline can still reach the network through
    `<link rel>` resource hints, which no fetch directive observes and which
    CSP3 ED (`w3c/webappsec-csp@e3461f7`) places under `default-src` — so a
    browser that lets them through under `default-src 'none'` is non-conformant.
    From inside the frame the loads are unverifiable (no violation/load/error
    event); the local-sink mode observes them out-of-frame. Measured per engine
    (Kehto Playwright probes; prerender reconfirmed on the Chromium channel in
    `tests/evil-02.spec.mjs`):

    | hint | Chromium 147 | Firefox 148 | WebKit 26.4 |
    |------|--------------|-------------|-------------|
    | `rel=prerender` | HTTP GET, `Sec-Purpose: prefetch` | — | — |
    | `rel=preconnect` | DNS + TCP (network prediction on) | — | TCP |
    | `rel=dns-prefetch` | DNS (network prediction on) | DNS (DNS prefetch enabled) | — |
    | `rel=prefetch` | governed by `default-src` here (CSP violation) | — | — |

    A dash is "not observed in that engine/config", not "closed" — these are
    prediction/flag-gated and build-dependent, which is itself the point: the
    napplet CSP is not the control. Playwright's default context disables network
    prediction, so preconnect/dns-prefetch need the real browser channel with
    prediction enabled; prerender's HTTP GET fires regardless and is the CI
    anchor. Closing this needs an embedding-page / Permissions-Policy control or
    a CSP directive the browser actually enforces for hints — a spec gap for the
    NIP-5D CSP advisory (C/D/E). (napplet/evil#5)
