// evil-03 — transport forging: a compliant router binds to MessageEvent.source
// and ignores declared identity; a sloppy router trusts envelope fields.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, shellLogIncludes } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// compliant router: declared identity ignored (probe routed to own ns → error reply)
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, settleMs: 6000 });
  const st = await statuses(f);
  check('spec: declared-identity spoof held (router source-bound)', st['declared-identity'] === 'blocked', JSON.stringify(st));
  check('spec: forged reply dispatched (sent — acceptance is runtime bug)', st['forged-reply'] === 'sent');
  check('spec: sequential-id storm dispatched (sent)', st['sequential-ids'] === 'sent');
  check('spec: unknown-source nested relay sent (srcdoc children exist)', st['unknown-source'] === 'sent', String(st['unknown-source']));
  check('spec: shell DROPS the unmapped nested frame (source check)', await shellLogIncludes(page, 'DROPPED message from UNKNOWN source'));
  await page.close();
}

// sloppy router (trust declared fields): the spoof arms
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, trustDeclared: true });
  const st = await statuses(f);
  check('sloppy: declared-identity spoof ARMS (router trusts envelope identity)', st['declared-identity'] === 'armed', JSON.stringify(st));
  await page.close();
}

// VERY EVIL: forged storm fires; unmapped nested frames are dropped by the shell
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-03-transport-forge', runtime: true, csp: false });
  await armVeryEvil(f, BASE + '/collect');
  const dropped = await shellLogIncludes(page, 'DROPPED message from UNKNOWN source');
  check('very-evil: unmapped nested frames messaged the shell and were DROPPED', dropped);
  const accepted = await shellLogIncludes(page, 'ACCEPTED');
  check('very-evil: storm envelopes reached the router (ACCEPTED lines)', accepted);
  await page.close();
}

await browser.close();
check.finish();