#!/usr/bin/env node
import { existsSync, statSync } from 'fs';
import { join, resolve } from 'path';

const args = process.argv.slice(2);
const levelRaw = args.find((a) => a.startsWith('--level='))?.split('=')[1] || 'all';
const ROOT = resolve(process.cwd());
const PARENT = resolve(ROOT, '..');
const errors = [];

function nonEmpty(abs, label) {
  if (!existsSync(abs)) errors.push(`Missing: ${label}`);
  else if (statSync(abs).size < 20) errors.push(`Too empty: ${label}`);
}

function processLevel() {
  nonEmpty(join(PARENT, 'AGENTS.md'), 'parent AGENTS.md');
  nonEmpty(join(PARENT, 'scaffold', 'comms.md'), 'scaffold/comms.md');
}
function layoutLevel() {
  if (existsSync(join(ROOT, 'scaffold'))) errors.push('scaffold/ must be outside repo');
  if (!existsSync(join(PARENT, 'scaffold'))) errors.push('parent scaffold/ missing');
}
function appLevel() {
  for (const p of [
    'package.json',
    'README.md',
    'source/scan.js',
    'scripts/secgate-scan.mjs',
    'tests/scan.test.mjs',
  ]) {
    if (!existsSync(join(ROOT, p))) errors.push(`Missing: ${p}`);
  }
}

if (levelRaw === 'all' || levelRaw === 'process') processLevel();
if (levelRaw === 'all' || levelRaw === 'layout') layoutLevel();
if (levelRaw === 'all' || levelRaw === 'app') appLevel();

if (errors.length) {
  console.error('FAIL');
  errors.forEach((e) => console.error(' ·', e));
  process.exit(1);
}
console.log('PASS');
