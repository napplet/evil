# evil-napplets

**A NIP-5D / napplet red team.** A suite of deliberately hostile napplets whose job
is to break out of — or prove the integrity of — Nostr applet runtimes. Every napplet
here is a legitimate, spec-shaped NIP-5D artifact (`sandbox="allow-scripts"`, opaque
origin, `srcdoc` loading) that attacks its host the way a real adversary would, so
runtimes can find and fix their gaps *before* an adversary does.

Each napplet targets one attack class, ordered from the lowest-hanging fruit
(misconfigured or lazy runtimes) up to attacks that exploit loopholes in the NIP-5D
specification itself (hardened runtimes). See [ROADMAP.md](ROADMAP.md).

## Rules of engagement

**Demo by default.** A loaded evil napplet only *probes* and *reports*. It proves each
attack primitive is available — with masked, non-actionable evidence — and then stops:

- no writes outside its own frame (demo mode may write one immediately-cleaned
  marker key to prove storage access, nothing more)
- no network egress (no fetch, no WebSocket, no beacons, no popups)
- no signing, no navigation, no persistence, no destruction

**"VERY EVIL" mode.** Each napplet can be armed from inside the napplet. Arming
requires a stern confirmation dialog that lists **every armed attack and exactly what
executing it will do** — payload, destination, and destructive consequences — and a
typed confirmation (`EXECUTE EVIL`, case-sensitive). Only after that does it actually
execute the evil payloads, in a safe order (destructive payloads last), logging what
happened as evidence.

Default exfiltration destination is `https://evil.example.invalid/collect` — a
non-resolving RFC-2606 host. Even in VERY EVIL mode nothing leaves the machine;
operators point it at their own collector to test real egress.

**Not a weapon.** These are QA tools for runtime authors. The evil payloads are
deliberately loud (marker keys, marker notes, visible defacement banner) rather than
quiet. They demonstrate harm; they don't optimize for it.

## The ladder

| Tier | Target | Napplets |
|------|--------|----------|
| 0 | Baseline misconfig — poorly implemented runtimes | `evil-01` sandbox escape, `evil-02` CSP / network egress |
| 1 | Transport confusion — lazy runtimes | `evil-03` envelope forging & reply injection |
| 2 | Manifest & identity confusion | `evil-04` manifest confusion, `evil-05` Nostr-level substitution |
| 3 | Side channels & spec loopholes — hardened runtimes | `evil-06`…`evil-08` |

**All eight rungs are built and validated** — 71 automated checks against real
Chromium (`tests/`). One napplet per rung, lowest fruit first. Per-rung status
and validated findings live in [ROADMAP.md](ROADMAP.md).

Each rung is a self-contained single-file NIP-5D artifact
(`napplets/<id>/index.html`) you can `srcdoc` into **any** runtime, or into the
included victim harness. Artifacts are built from `src/` (shared chrome +
per-napplet attack definitions) via `node build.mjs`.

## Running locally

```bash
python3 -m http.server 8787          # from the repo root
# open http://localhost:8787/harness/
```

The [harness](harness/index.html) is a deliberately misconfigurable victim shell —
every knob re-arms a different subset of the attacks:

- **runtime preset** — `spec` (`sandbox="allow-scripts"` + CSP), `same-origin`
  (+`allow-same-origin`), `no-sandbox` (no sandbox attr) — arms the evil-01
  escape tree; `spec` is the green gate your runtime's CI should hold.
- **CSP meta** — on/off. Off arms every evil-02 egress channel; on holds them
  (except WebRTC — the spec gap, see ROADMAP).
- **shell `window.nostr`** — a fake NIP-07 extension, arms ambient-signing probes.
- **sibling iframe** — arms `parent.length` enumeration.
- **fake NAP runtime** — injects a `window.napplet.storage` domain (pre-script,
  outside the hashed artifact bytes, like a real runtime) with a selectable
  **namespace policy**: `by-(dTag+hash)` (spec-safe), `by-dTag` (version
  substitution leaks), or `global` (everything shared) — arms the evil-05
  inheritance attacks, evil-06 oracles, and evil-03 router attacks.
- **trust DECLARED identity** — a sloppy message router that trusts envelope
  `windowId`/`dTag` fields over `MessageEvent.source` — arms the evil-03 spoof.
- **launcher** — `safe` (textContent) vs `unsafe` (innerHTML) manifest-metadata
  render — arms the evil-04 shell-origin XSS end to end.

It also seeds victim canaries (`nsec` marker in `localStorage`, inherited v1
  secrets per namespace policy), echoes `evil.ping` with a shell-side wall clock
  (so frames can measure shell starvation), logs every ACCEPTED/DROPPED
  message, and dumps the runtime store.

## Repo layout

```
src/
  chrome.template.html                # shared napplet chrome: probes UI, arm gate, report
  napplets/<id>/{attacks.js,meta.json} # the ONLY per-napplet code
build.mjs                             # assembles src → napplets/<id>/index.html
napplets/
  <id>/index.html                     # built single-file NIP-5D artifacts (committed)
harness/
  index.html                          # configurable victim shell
tests/
  _helper.mjs + evil-0[1-8].spec.mjs   # 71 Playwright checks vs real Chromium
ROADMAP.md                            # attack ladder + validated NIP-5D spec findings
```

Evil napplets use their own dark palette (a red-team tool must stay legible even in a
hostile runtime) and the napplet UI contract otherwise: no title header, tool density,
usable at any frame size.