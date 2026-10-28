#!/usr/bin/env node
// Assembles each napplet from the shared chrome template + per-napplet attacks.
// Zero dependencies. Output artifacts are the committed single-file NIP-5D
// napplets in napplets/<id>/index.html.
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const src = join(root, 'src');
const template = readFileSync(join(src, 'chrome.template.html'), 'utf8');
const outDir = join(root, 'napplets');

const MARK = '/*__ATTACKS__*/';
const IDS = { title: '__TITLE__', desc: '__DESC__', dtag: '__DTAG__' };

for (const id of readdirSync(join(src, 'napplets')).sort()) {
  const dir = join(src, 'napplets', id);
  if (!existsSync(join(dir, 'attacks.js'))) continue;
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  let attacks = readFileSync(join(dir, 'attacks.js'), 'utf8').trim();
  if (attacks.includes('</script>')) throw new Error(id + ': attacks.js contains </script>');
  if (!/\bconst ATTACKS\b/.test(attacks)) throw new Error(id + ': attacks.js must define const ATTACKS');
  const out = template
    .split(MARK).join(attacks + '\n')
    .split(IDS.title).join(meta.title)
    .split(IDS.desc).join(meta.description)
    .split(IDS.dtag).join(meta.dTag)
    .replace('(function () {', "(function () {\n  window.__EVIL_ID__ = '" + meta.dTag + "';");
  if (out.includes(MARK) || out.includes('__TITLE__') || out.includes('__DTAG__')) {
    throw new Error(id + ': unresolved marker');
  }
  const target = join(outDir, id);
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'index.html'), out);
  console.log('built', join('napplets', id, 'index.html'), '(' + out.length + ' bytes)');
}