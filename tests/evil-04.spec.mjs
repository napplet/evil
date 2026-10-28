// evil-04 — manifest confusion: srcdoc vs src (TOCTOU), and launcher
// metadata XSS — innerHTML of manifest title = script in the SHELL origin.
import { chromium, BASE, loadHarness, statuses, makeChecks, armVeryEvil, collectExfil } from './_helper.mjs';

const check = makeChecks();
const browser = await chromium.launch({ viewport: { width: 1600, height: 1200 } });

// spec preset, safe launcher: everything inert
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-04-manifest-confusion' });
  const st = await statuses(f);
  check('spec: srcdoc loading verified (TOCTOU held)', st['loaded-via-src'] === 'blocked', JSON.stringify(st));
  check('spec: launcher XSS held (metadata rendered as text)', st['launcher-xss'] === 'blocked');
  const kitCount = await f.evaluate(() => document.querySelectorAll('#kit .kit-entry').length);
  check('kit: crafted manifests present', kitCount >= 3, String(kitCount));
  await page.close();
}

// unsafe launcher (innerHTML): the XSS channel arms
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const f = await loadHarness(page, { napplet: 'evil-04-manifest-confusion', launcher: 'unsafe' });
  const st = await statuses(f);
  check('unsafe launcher: XSS ARMS (ping-back from shell origin)', st['launcher-xss'] === 'armed', JSON.stringify(st));
  await page.close();
}

// VERY EVIL against the unsafe launcher: real XSS executes in shell origin
{
  const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
  const exfil = [];
  collectExfil(page, exfil);
  const f = await loadHarness(page, { napplet: 'evil-04-manifest-confusion', launcher: 'unsafe' });
  await armVeryEvil(f, BASE + '/collect');
  const banner = await page.waitForFunction(() => !!document.getElementById('__evil04_banner__'), null, { timeout: 15000 }).then(() => true).catch(() => false);
  check('very-evil: manifest-metadata XSS defaced the SHELL (banner in shell origin)', banner);
  await page.waitForTimeout(1500);
  check('very-evil: XSS payload pinged the collector from shell origin', exfil.some((e) => e.url.includes('ev=evil04-launcher-xss')), exfil.map((e) => e.url).join(', '));
  await page.close();
}

await browser.close();
check.finish();