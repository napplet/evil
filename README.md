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

`napplets/<id>/index.html` — each is a self-contained single-file NIP-5D artifact you
can `srcdoc` into **any** runtime, or into the included victim harness.

## Running locally

```bash
python3 -m http.server 8787          # from the repo root
# open http://localhost:8787/harness/
```

The [harness](harness/index.html) is a deliberately misconfigurable victim shell:

- **spec** — spec-compliant runtime (`sandbox="allow-scripts"`, CSP injected,
  source-checked messages). All evil-01 probes should report **blocked**.
- **sloppy** presets — `allow-same-origin`, missing sandbox attr, missing CSP,
  shell `window.nostr` — each preset re-arms different subsets of the attacks,
  which is exactly what you want your runtime's CI to run against.

## Repo layout

```
napplets/
  evil-01-sandbox-escape/index.html   # baseline escape probes + VERY EVIL payloads
harness/
  index.html                          # configurable victim shell for local testing
ROADMAP.md                            # attack ladder + candidate NIP-5D spec findings
```

Evil napplets use their own dark palette (a red-team tool must stay legible even in a
hostile runtime) and the napplet UI contract otherwise: no title header, tool density,
usable at any frame size.