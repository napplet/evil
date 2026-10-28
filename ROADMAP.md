# Attack ladder — evil napplets

Ordered from lowest hanging fruit (misconfigured / lazy runtimes) to the most nuanced
(assaults on well-hardened runtimes, and on the NIP-5D specification itself). Each
rung names the spec clause it attacks and what arms it.

## Tier 0 — baseline misconfig (poorly implemented runtimes)

These attacks land whenever a runtime gets a *must* wrong. A well-implemented runtime
passes every probe (this is the security-lab's job); the evil napplet's job is to show
what each mistake costs, with a real payload behind a confirmation gate.

### ✅ `evil-01-sandbox-escape` — the load-bearing preconditions

Status: **built + validated** (`tests/evil-01.spec.mjs`, 16/16 against the harness)

Validated results:

- **spec-compliant runtime holds every escape probe** (origin, storage, SW, parent DOM,
  NIP-07, navigation, popups) — the suite is a runtime CI gate.
- **spec gap confirmed (ROADMAP #2):** `document.referrer` inside the srcdoc frame
  is the shell URL even in the fully compliant preset. No NIP-5D guidance on
  Referrer-Policy exists; shells should inject `no-referrer` policy (meta in the
  artifact runs counter to the hashed-bytes rule — this needs spec-level thought).
- **refinement:** `allow-same-origin` alone does **not** grant ancestor navigation —
  the browser sandbox navigation flag holds `parent.location.replace()` even in the
  sloppy preset ("Unsafe attempt to initiate navigation"). Full hijack needs a
  missing `sandbox` attribute. Read access still escapes; nav is a separate,
  stronger failure.
- **sibling enumeration** (ROADMAP #3) arms as soon as any sibling frame exists,
  from an opaque origin, in a compliant runtime — `parent.length` counts this
  frame too, so the probe reports `length − 1`.

Attacks every *must* in [NIP-5D §Security](../napplets/evil-01-sandbox-escape/index.html):

| # | Attack | Spec clause |
|---|--------|-------------|
| 1 | Opaque origin — `window.origin === 'null'`? | `sandbox="allow-scripts"` and **never** `allow-same-origin` |
| 2 | Direct browser storage on a real shared origin | "Napplets have no access to `localStorage`…" |
| 3 | Service-worker registration → persistent backdoor | same-origin grants SW on the shell origin |
| 4 | Parent DOM read (cookies, rendered secrets) | "The shell is trusted; the napplet is not" |
| 5 | Ambient `window.nostr` — sign as the user | "Shells MUST NOT provide `window.nostr`" |
| 6 | Parent navigation — shell hijack | sandbox must not permit ancestor navigation |
| 7 | `document.referrer` leak of the shell URL | *spec is silent — see Tier 3 findings* |
| 8 | Popup escape via `window.open` | sandbox must not permit popups |
| 9 | Sibling napplet enumeration (`parent.length`) | *cross-origin-legal even in compliant runtimes — see Tier 3* |

Armed by: `allow-same-origin` on the iframe, a missing `sandbox` attribute, or a
NIP-07 extension injecting `window.nostr` into iframes (all_frames).

### 🔜 `evil-02` — CSP & network egress

`connect-src 'none'` is the only thing between an opaque-origin frame and the network
(a srcdoc iframe has no HTTP response to carry a CSP *header*). Probes, in order:
`fetch`, XHR, WebSocket, `sendBeacon`, `img`/`audio` beacons, prefetch/DNS hints.
Then — the one that works **even under the spec's own conservative CSP baseline** —
**WebRTC**: `RTCPeerConnection` data channels are not covered by any CSP directive
(`connect-src` does not apply), so a compliant runtime can still be exfiltrated
through. A hardened runtime needs a Permissions Policy (`webrtc` / relevant feature
policy) or `RTCPeerConnection` neutering in the injected runtime, none of which
NIP-5D currently suggests. This napplet bridges Tier 0 and Tier 3.

## Tier 1 — transport confusion (lazy runtimes)

### 🔜 `evil-03` — envelope forging & reply injection

postMessage `'*'` is required (opaque origins have no origin to target), so the
**only** sender identity is `MessageEvent.source`. Attacks:

- forge reply messages (`<domain>.<action>.result` types) with guessed/garbage ids —
  shells must bind each outstanding request id to the *Window* that sent the request
  and route replies there only. The spec is silent on id binding (see findings).
- spoof auxiliary fields the spec *does* name but doesn't trust-bind: `windowId`,
  `dTag`, `artifactHash` in envelopes — a runtime that maps messages by *declared*
  identity instead of `source` Window lets any frame become any napplet.
- cross-napplet confused deputy: if a shell broadcasts shell→napplet messages (events,
  theme changes) to *all* frames, a sibling can inject forged
  `relay.query.result`/`storage.get.result` payloads into a *legitimate* sibling's
  pending request ids (ids are often sequential — `storage.get.42`).
- send from a second, nested iframe the evil napplet manages to create (in sloppy
  runtimes where `frame-src` is not `'none'`) — an *unknown source* the shell must
  silently drop.

## Tier 2 — manifest & identity confusion

### 🔜 `evil-04` — manifest confusion

The manifest is attacker-authored input that *drives* runtime decisions:

- **multi-`x` ambiguity** — "a manifest that does not carry exactly one `x` tag MUST
  be rejected": probe runtimes that take the first/last `x` and serve a *different*
  artifact than the one they verified.
- **declaration-as-grant conflation** — `z`, `i`, `R`, `O` are routing hints and
  declarations that "MUST NOT widen what the shell exposes". A runtime that maps
  manifest `R` tags → injected NAP domains hands the attacker its own capability list.
- **`src` vs `srcdoc` TOCTOU** — the runtime MUST inject verified bytes via `srcdoc`;
  a runtime that navigates the iframe to the Blossom/gateway URL re-fetches from an
  *attacker-declared* `server` after verification — serve one artifact to the
  verifier, another to the frame.
- **manifest metadata XSS** — `content`/`title` MUST be plain text; a shell that
  `innerHTML`s them into launcher cards gives the attacker script in the *shell*
  origin (game over, no sandbox needed).
- **icon decompression bomb** — icon is PNG-verified but dimension-capped nowhere;
  a 65535×65535 PNG in the launcher is a shell-side memory DoS. Also probes runtimes
  that skip the "bytes decode as declared format" check (SVG re-labeled `image/png`).

### 🔜 `evil-05` — Nostr-level substitution

- **unbound `dTag` resolution** — the spec says "resolve the napplet manifest event
  and verify its signature" but never binds a named napplet (`kind 35129`) to *whose*
  pubkey. A runtime resolving by `dTag` alone takes whichever manifest a relay serves
  — attacker publishes `dTag: <legit>` from their own key → substitution.
- **replaceable replay/rollback** — `kind 15129`/`35129` are replaceable; no
  freshness rule (latest? created_at pinning?) means a hostile relay can feed an old
  — or planted — version. NIP-5D has no "last known good" guidance.
- **storage namespace squatting** — if NAP-STORAGE namespaces by `dTag` (not
  `(dTag, artifactHash)` or `(dTag, publisher)`), a substituted napplet **inherits the
  victim's stored user data**; an updated version inherits its predecessor's secrets
  across versions. This is the highest-impact combination on this ladder.

## Tier 3 — side channels & spec loopholes (hardened runtimes)

NIP-5D explicitly does *not* protect against side-channel attacks ("Non-Guarantees").
These napplets exist to measure exactly how much leaks anyway, so runtimes (and the
spec) know what to fix.

### 🔜 `evil-06` — side-channel oracles on shell mediation

- **storage timing oracle** — `storage.get` latency / presence distinguishes
  occupied vs empty keys → probe key *existence* across the ACL boundary.
- **quota oracle** — `navigator.storage.estimate()` reports total origin usage →
  aggregate of all napplets' and the shell's private data.
- **error taxonomy oracle** — shells leak *why* a relay/publish/storage call failed
  ("not registered" vs "policy denied" vs "no such key") → ACL oracle for free.
- **signing latency** — shell signing time correlates with event size/kind handling.

### 🔜 `evil-07` — fingerprinting & enumeration

Not blocked by any CSP directive or sandbox token — a fully compliant runtime still
exposes: `navigator.userAgent`, `hardwareConcurrency`, `deviceMemory`, screen metrics,
font enumeration (style-src is `'unsafe-inline'`), `Intl`/timezone, and battery/media
capacities. Plus the two cross-origin-legal leaks NIP-5D doesn't mention:
`parent.length` (sibling napplet count) and `document.referrer` (srcdoc inherits the
shell URL — query tokens included — unless the shell sets a strict Referrer-Policy).
Also `window.name` as a cross-reload channel.

### 🔜 `evil-08` — wasm timing & same-process gadgets

The spec's own CSP baseline *mandates* `script-src 'wasm-unsafe-eval'` — and a srcdoc
iframe with an opaque origin **cannot be site-isolated**, so attacker-controlled
Wasm runs in the same renderer process as the shell. Probes: spin-loop timers with
better resolution than `performance.now()`, cache-timing probes against parent-origin
object access, `SharedArrayBuffer` availability (`crossOriginIsolated` inherits from
the shell's policy), and Spectre-class gadget demonstrations. Everything the spec's
`'wasm-unsafe-eval'` baseline quietly assumes away.

## Candidate findings against the NIP-5D spec itself

Research notes for spec issues (to file upstream as the napplets validate them):

1. **WebRTC is outside CSP** — no directive governs `RTCPeerConnection`; the
   conservative baseline still allows data-channel egress (→ `evil-02`).
2. **No Referrer-Policy guidance** — a srcdoc napplet inherits the shell URL as
   `document.referrer`; shells carrying query tokens leak them to untrusted frames.
3. **Cross-origin window accessibles** — `parent.length`/`parent.frames.length` are
   readable from an opaque-origin napplet → sibling enumeration channel (→ `evil-07`).
4. **`wasm-unsafe-eval` is same-process by construction** — srcdoc frames with opaque
   origins are not site-isolated; the spec mandates Wasm compilation in the shell's
   own process (→ `evil-08`).
5. **`dTag` resolution is unbound** — "resolve the manifest and verify its
   signature" never says *whose* signature a named/replaceable napplet must carry
   (→ `evil-05`).
6. **Reply routing is unspecified** — the wire format has `id` correlation but no
   rule that replies route only to the Window that sent the request (→ `evil-03`).
7. **Storage namespacing is unspecified** — NAP-STORAGE must namespace by
   `(dTag, artifactHash)` (or publisher-bound) or versions/substitutions inherit
   secrets (→ `evil-05`).
8. **Icon decode caps unspecified** — PNG verification without pixel-area caps is a
   shell DoS (→ `evil-04`).