#!/usr/bin/env node
/**
 * Secgate CLI — walk a project path and report hygiene findings.
 *
 *   node scripts/secgate-scan.mjs <path>
 *   node scripts/secgate-scan.mjs <path> --json
 *   node scripts/secgate-scan.mjs <path> --brief
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'fs';
import { join, relative, resolve, basename, extname } from 'path';
import { spawnSync } from 'child_process';
import {
  analyzeProject,
  shouldSkipDir,
  isProbablyTextFile,
  DISCLAIMER,
} from '../source/scan.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const briefOnly = args.includes('--brief');
const includeTests = args.includes('--include-tests');
const rootArg = args.find((a) => !a.startsWith('--'));
const root = resolve(rootArg || process.cwd());

const MAX_FILES = 500;
/** Large monoliths (e.g. mBT index.html ~0.9MB) still need pattern scan */
const MAX_BYTES = 1_500_000;
const MAX_DEPTH = 10;

if (!existsSync(root) || !statSync(root).isDirectory()) {
  console.error(`secgate: not a directory: ${root}`);
  process.exit(2);
}

/** @type {string[]} */
const allPaths = [];
/** @type {Record<string, string|null>} */
const files = {};

function walk(dir, depth) {
  if (depth > MAX_DEPTH) return;
  if (Object.keys(files).length >= MAX_FILES) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (Object.keys(files).length >= MAX_FILES) break;
    const name = ent.name;
    if (ent.isDirectory()) {
      if (shouldSkipDir(name)) continue;
      walk(join(dir, name), depth + 1);
      continue;
    }
    if (!ent.isFile()) continue;
    const abs = join(dir, name);
    const rel = relative(root, abs).replace(/\\/g, '/');
    allPaths.push(rel);
    if (!isProbablyTextFile(rel) && name !== '.env') continue;
    let st;
    try {
      st = statSync(abs);
    } catch {
      continue;
    }
    if (st.size > MAX_BYTES) {
      files[rel] = null;
      continue;
    }
    try {
      files[rel] = readFileSync(abs, 'utf8');
    } catch {
      files[rel] = null;
    }
  }
}

walk(root, 0);

/** @type {Set<string>|null} */
let trackedPaths = null;
if (existsSync(join(root, '.git'))) {
  const r = spawnSync('git', ['ls-files', '-z'], {
    cwd: root,
    encoding: 'buffer',
    maxBuffer: 20 * 1024 * 1024,
  });
  if (r.status === 0 && r.stdout) {
    trackedPaths = new Set(
      r.stdout
        .toString('utf8')
        .split('\0')
        .filter(Boolean)
        .map((p) => p.replace(/\\/g, '/')),
    );
  }
}

const report = analyzeProject({
  rootName: basename(root),
  files,
  paths: allPaths.length ? allPaths : Object.keys(files),
  includeTests,
  trackedPaths,
});

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else if (briefOnly) {
  process.stdout.write(report.briefing.endsWith('\n') ? report.briefing : report.briefing + '\n');
} else {
  console.log(report.summary);
  console.log('');
  console.log('--- briefing (paste-safe) ---');
  console.log(report.briefing);
}

// exit 1 if critical findings (CI-friendly); still not "secure")
if (report.metrics.bySeverity.critical > 0) process.exitCode = 1;
