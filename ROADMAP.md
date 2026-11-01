# Attack ladder — evil napplets

Ordered from lowest hanging fruit (misconfigured / lazy runtimes) to the most nuanced
(assaults on well-hardened runtimes, and on the NIP-5D specification itself).
**All ten rungs are built and validated** — 114 automated checks against real
Chromium (`tests/`). Each rung names the spec clause it attacks, what arms it,
and what validation proved.

## Tier 0 — baseline misconfig (poorly implemented runtimes)

These attacks land whenever a runtime gets a *must* wrong. A well-implemented
runtime passes every probe (this is the security-lab's job); the evil napplet's
job is to show what each mistake costs, with a real payload behind the gate.

### ✅ `evil-01-sandbox-escape` — the load-bearing preconditions

Status: **built + validated** — 16/16 (`tests/evil-01.spec.mjs`)

Validated results:

- **spec-compliant runtime holds every escape probe** (origin, storage, SW,
  parent DOM, NIP-07, navigation, popups) — the suite is a runtime CI gate.
- **spec gap confirmed (findings #2):** `document.referrer` inside the srcdoc
  frame is the shell URL even in the fully compliant preset. No NIP-5D guidance
  on Referrer-Policy exists; shells should inject `no-referrer` policy — but a
  meta in the artifact runs counter to the hashed-bytes rule, so this needs
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
| 7 | `document.referrer` leak of the shell URL | *spec is silent — findings #2* |
| 8 | Popup escape via `window.open` | sandbox must not permit popups |
| 9 | Sibling napplet enumeration (`parent.length`) | *cross-origin-legal even in compliant runtimes — findings #3* |

Armed by: `allow-same-origin` on the iframe, a missing `sandbox` attribute, or a
NIP-07 extension injecting `window.nostr` into iframes (all_frames).

### ✅ `evil-02-csp-egress` — CSP & network egress

Status: **built + validated** — 16/16 (`tests/evil-02.spec.mjs`)

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
- Prefetch / dns-prefetch hint loads are unverifiable from inside the frame —
  honest `na` ("treat the channel as open"): no directive governs them either.

## Tier 1 — transport confusion (lazy runtimes)

### ✅ `evil-03-transport-forge` — envelope forging & reply injection

Status: **built + validated** — 8/8 (`tests/evil-03.spec.mjs`)

postMessage `'*'` is required (opaque origins have no origin to target), so the
**only** sender identity is `MessageEvent.source`. Attacks: forged reply
envelopes with guessed ids, sequential-id injection storms, declared-identity
spoofing (`windowId`/`dTag`/`artifactHash` fields), unknown-source nested
relays, and shell-broadcast harvesting.

Validated results:

- **A compliant router holds**: declared-identity spoofing gets routed to the
  *source* namespace (reply carries `no such key`), never the declared one.
- **A router that trusts declared fields arms**: the probe reads a value out
  of the declared sibling's namespace — any frame can act as any napplet.
- **New finding (validated): srcdoc child iframes are NOT blocked by
  `frame-src`.** An unmapped grandchild frame can message the shell directly;
  the only defense is the source check (conforming shells drop — the harness
  log shows `DROPPED`). NIP-5D's "messages from unknown sources MUST be
  silently dropped" is load-bearing here, and the CSP advisory's `frame-src
  'none'` is *not* the control it looks like.

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

Status: **built + validated** — 9/9 (`tests/evil-05.spec.mjs`)

Validated results, across three storage namespace policies:

- **`by-(dTag+artifactHash)` isolates**: no inherited secrets, no cross-namespace
  reads. This is the policy NAP-STORAGE should mandate (findings #7).
- **`by-dTag` arms**: a substituted/version-bumped napplet **inherits the
  victim's stored secrets** — the v1 canary came back through the frame.
- **`global` arms twice over**: inheritance plus reads of *other* napplets'
  namespace keys.
- VERY EVIL under `by-dTag` exfiltrated the inherited secret to the collector
  and **poisoned the namespace for the next heir**.
- The kit carries the unbound-dTag manifest (attacker key, victim dTag —
  findings #5) and a rollback/replay manifest (findings: no freshness rule).

## Tier 3 — side channels & spec loopholes (hardened runtimes)

NIP-5D explicitly does *not* protect against side-channel attacks
("Non-Guarantees"). These napplets measure exactly how much leaks anyway.

### ✅ `evil-06-side-channels` — oracles on shell mediation

Status: **built + validated** — 5/5 (`tests/evil-06.spec.mjs`)

Validated results:

- **Storage key-existence timing oracle ARMS under a fully compliant runtime**:
  hit vs miss latency separates cleanly (the harness backend answers ~40ms vs
  ~6ms) — key existence is readable through the ACL boundary by latency alone.
- **Error taxonomy oracle arms**: "no such key" vs "value too large" vs
  "policy denied" map the runtime's ACL boundaries for free.
- **Shell scheduler RTT channel arms**: the parent echo round-trip is
  measurable from inside — recon for the same-process gadgets (see evil-08).
- Without an injected runtime the oracles close (`na`) — mediation is the
  leak surface.

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

Status: **built + validated** — 24/24 (`tests/evil-09.spec.mjs`)

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

### ✅ `evil-10-port-theft` — the port lifecycle after the handoff

Status: **built + validated** — 19/19 (`tests/evil-10.spec.mjs`)

Rung 9 attacked what #14 replaced; this rung attacks what #14 installed. The
port is now the identity, and the spec makes three load-bearing claims about
it — each probed:

1. **"it MUST NOT be reachable from napplet code"** — private-port privacy is
   bootstrap *conformance*, not a platform property. The reachable-graph
   scanner (postMessage/start/close trio, MessagePort constructor) finds the
   port wherever a sloppy bootstrap parks it — validated under the harness
   dev-mode leak knob, found at `window.__nap_debug.port`. A conformant
   bootstrap held the scan.
2. **"an opaque-origin sandboxed document cannot hand it to a context that
   outlives the document"** — false as a platform claim: transfer-list
   postMessage works cross-origin between frames (it is how `napplet.hello`
   itself travels). Validated: the frame handed one end of its own
   MessageChannel to the sibling, which echoed back over it. Only claim 1's
   conformance stands between a reached port and a surviving owner.
3. **"the shell MUST close the port"** — load-bearing, and skipping it is a
   realistic bug: a port transferred OUT of the document survives iframe
   removal. Validated both ways by the detonation — the stolen port speaks as
   the verified napplet from the sibling (two frames, one identity,
   concurrently: the shell log shows PORT-ACCEPTED for the mule's request and
   the grant served), then the napplet fires replacement evidence against
   itself. A conformant shell closes the channel and the mule's post-revocation
   probe goes unanswered (CHANNEL-DEAD — the fix holds). Under the sloppy-
   revoke knob the channel stays alive: the surviving frame was served the
   revoked identity's grants after its owner's destruction, and VERY EVIL
   poisoned the namespace and exfiltrated to the collector over the stolen
   port, post-revocation.

| # | Attack | Spec clause |
|---|--------|-------------|
| 1 | private port reachability scan | §Transport: "MUST NOT be reachable from napplet code" |
| 2 | cross-frame port transfer primitive | §Security: "cannot hand it to a context that outlives the document" |
| 3 | stolen-port lifecycle: concurrent identity sharing → self-revoke → channel survival | §Identity: "the shell MUST close the port" |

Armed by: a bootstrap that parks the private port anywhere reachable
(findings #12). Disarmed by: keep the port in the bootstrap closure — and
treat `close()` as the load-bearing step of teardown, because iframe removal
kills nothing that was transferred out (findings #13).

## Validated findings against the NIP-5D spec

Research notes for spec issues (to file upstream as the napplets validate them):

1. ✅ **WebRTC is outside CSP** — no directive governs `RTCPeerConnection`; the
   conservative baseline still allows data-channel egress (validated by
   evil-02).
2. ✅ **No Referrer-Policy guidance** — a srcdoc napplet inherits the shell URL
   as `document.referrer`, in a compliant runtime (validated by evil-01/07).
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
## Postmortem — why the ladder didn't find #11 first

Finding #11 was fixed upstream (NIP-5D #14) before this suite had a rung for
it. That is a ladder-design miss, and the near-misses are worth naming:

- **evil-01 probed navigation only outward.** Attacks #6/#8 ask whether the
  frame can hijack the *parent* or escape via popups. The one navigation that
  broke the model — a frame navigating *itself* — was excluded by the ROE
  itself ("no navigation" in demo mode), which treated navigation as an
  outward weapon rather than an identity event.
- **evil-03 validated the control and stopped.** It proved a compliant router
  binds to `MessageEvent.source` and ignores declared identity — then asked
  whether the envelope can lie, never what the *lifetime* of the source
  binding is. The check wasn't wrong; the thing it pointed at (the Window)
  outlived the document it was verified against.
- **evil-04 was one question away.** The TOCTOU probe uses
  `location.href === 'about:srcdoc'` as proof the running bytes are the
  verified bytes — and never asked the inverse: what happens to my grants when
  `location.href` changes? It treated document identity as a load-time
  property to verify, not a runtime invariant to attack.
- **evil-05 modeled substitution in the wrong direction.** The substituted
  heir inherits the victim's data — but as a *different napplet loading where
  the victim used to*, shell-side, pre-load. It never modeled the same frame
  swapping documents *after* verification: substitution from inside, at
  runtime.
- **The findings taxonomy had no temporal category.** Findings were keyed to
  clauses (unbound dTag, namespacing, WebRTC-vs-CSP). #11 is not a missing
  rule — it is an unstated *temporal assumption* (Window↔document is 1:1 for
  the life of the grant) that no rung existed to falsify.

The methodology fix, applied from rung 10 on — every rung is selected against
a **binding-lifetime checklist**. For every binding the spec establishes
(identity→Window, CSP→document, grants→session, dTag→pubkey, …):

1. What object is the binding keyed to?
2. What is the lifetime of that key, and what events can replace one side of
   the binding while the key persists (navigation, reload, `document.open`,
   port transfer, version bump, re-resolution)?
3. What invalidates the binding — and can the *bound party* trigger that
   event deliberately?
4. Which per-document controls silently expire, or persist, across the event?

Run against pre-#14, this produces evil-09 on day one: key = the Window, event
= self-navigation, invalidation = none in the text, per-document control = the
meta CSP. Run against post-#14 it produced rung 10: port privacy is bootstrap
conformance, not a platform property (findings #12), and a transferred port
outlives revocation unless `close()` is explicit (findings #13). Still open
under the same checklist: `hello` replay and port transfer into *nested*
frames (rung 9's kit; finding #9 says srcdoc children exist), per-document
control re-injection when a shell recreates a torn-down frame (the meta CSP
lives outside the hashed bytes — the recreate path must re-apply it), the
MAY-recreate reload loop (an untrusted party driving shell scheduling), the
in-flight revocation race (NAP already queued when close() lands), and the
sharpest open one — revocation retracts *access*, never *effects*: the VERY
evil namespace poison written before detection survives any teardown, which is
a store-revocation question NAP-STORAGE will eventually have to answer.
12. ✅ **The retained-port mitigation is bootstrap conformance, not a platform
    property** — §Security's "an opaque-origin sandboxed document cannot hand
    it to a context that outlives the document" is false as stated:
    transfer-list postMessage works cross-origin between frames (it is how
    `napplet.hello` itself travels). A reached port was handed to a sibling
    frame and spoke as the verified napplet from there (validated by evil-10
    under the dev-mode leak knob). What prevents theft is only the "MUST NOT
    be reachable" conformance of the bootstrap — and a reachable-port scanner
    belongs in every runtime's CI (evil-10's kit carries one).
13. ✅ **A transferred port outlives revocation unless the shell explicitly
    closes it** — "the shell MUST close the port" is the load-bearing step of
    teardown: removing the iframe kills nothing that was transferred out of
    the document. A shell that skips close() kept serving a revoked identity's
    grants to a surviving frame after the napplet's own destruction (validated
    by evil-10 under the sloppy-revoke knob, including post-revocation
    namespace poison and exfiltration over the stolen channel).
