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
    const f = analyzeFileContent('x.pem', '-----BEGIN RSA PRIVATE KEY-----\nMII\n');
    assert.ok(f.some((x) => x.id === 'private-key'));
  });
  it('flags service_role', () => {
    const f = analyzeFileContent('cfg.js', 'const k = process.env.SERVICE_ROLE_KEY || "x"');
    assert.ok(f.some((x) => x.id === 'service-role'));
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
  it('flags .env not example', () => {
    const f = analyzePaths(['.env', 'config/.env.local', '.env.example']);
    assert.ok(f.some((x) => x.id === 'env-file'));
    assert.ok(f.some((x) => x.id === 'env-example'));
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
