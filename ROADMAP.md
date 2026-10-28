# Attack ladder — evil napplets

Ordered from lowest hanging fruit (misconfigured / lazy runtimes) to the most nuanced
(assaults on well-hardened runtimes, and on the NIP-5D specification itself).
**All eight rungs are built and validated** — 71 automated checks against real
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