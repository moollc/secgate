import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeFileContent,
  analyzePaths,
  analyzeProject,
  hygieneBand,
  DISCLAIMER,
  buildBriefing,
} from '../source/scan.js';

describe('secrets', () => {
  it('flags private key block', () => {
    const body = ['-----BEGIN RSA PRIVATE KEY-----', 'MII', '-----END RSA PRIVATE KEY-----'].join('\n');
    const f = analyzeFileContent('keys/x.pem', body);
    assert.ok(f.some((x) => x.id === 'private-key'));
  });
  it('flags service_role assignment', () => {
    const f = analyzeFileContent('cfg.js', 'const SERVICE_ROLE_KEY = "supersecretyvaluethatislong"');
    assert.ok(f.some((x) => x.id === 'service-role'));
  });
  it('skips test paths by default', () => {
    const f = analyzeFileContent('tests/evil.test.mjs', 'eval(user)');
    assert.equal(f.length, 0);
  });
});

describe('browser patterns', () => {
  it('flags postMessage star', () => {
    const f = analyzeFileContent('a.js', "w.postMessage({a:1}, '*');");
    assert.ok(f.some((x) => x.id === 'postmessage-star'));
  });
  it('flags eval', () => {
    const f = analyzeFileContent('a.js', 'eval(userInput)');
    assert.ok(f.some((x) => x.id === 'eval'));
  });
});

describe('paths', () => {
  it('flags tracked .env as critical', () => {
    const f = analyzePaths(['.env', '.env.example'], {
      trackedPaths: new Set(['.env']),
    });
    assert.ok(f.some((x) => x.id === 'env-file' && x.severity === 'critical'));
    assert.ok(f.some((x) => x.id === 'env-example'));
  });
  it('local untracked .env is info only', () => {
    const f = analyzePaths(['.env.local'], { trackedPaths: new Set() });
    assert.ok(f.some((x) => x.id === 'env-file-local' && x.severity === 'info'));
  });
});

describe('project report', () => {
  it('includes disclaimer and paste-safe briefing', () => {
    const r = analyzeProject({
      rootName: 'demo',
      files: {
        'app.js': "eval('x'); window.postMessage(1, '*');",
        'index.html': '<html><script src="http://evil/x.js"></script></html>',
      },
      paths: ['app.js', 'index.html', '.env'],
    });
    assert.equal(r.disclaimer, DISCLAIMER);
    assert.ok(r.findings.length >= 2);
    assert.ok(['A', 'B', 'C', 'D'].includes(r.hygieneBand));
    assert.ok(!/\n\n/.test(r.briefing));
    assert.match(r.briefing, /NOT a penetration test/i);
  });

  it('hygiene D on critical', () => {
    assert.equal(
      hygieneBand([{ severity: 'critical', id: 'x', title: '', detail: '', rec: '' }]),
      'D',
    );
  });
});
