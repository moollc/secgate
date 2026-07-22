/**
 * Secgate pure scan logic — security hygiene on disk.
 * Not a pen test. Callers supply text maps or use the CLI walker.
 */

export const DISCLAIMER =
  'Secgate is NOT a penetration test, compliance certificate, or proof of security. ' +
  'Hygiene band is a coarse static signal only. Verify live auth, RLS, and runtime yourself.';

const SKIP_DIR = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.cache',
  'pipeline',
  'venv',
  '.venv',
  '__pycache__',
  'vendor',
  'target',
  '.turbo',
]);

const TEXT_EXT = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.html',
  '.htm',
  '.vue',
  '.svelte',
  '.css',
  '.json',
  '.md',
  '.env',
  '.yml',
  '.yaml',
  '.toml',
  '.sql',
  '.sh',
  '.ps1',
  '.py',
  '.rs',
  '.go',
  '.rb',
  '.php',
  '.xml',
  '.svg',
]);

/** @typedef {{ id: string, severity: 'critical'|'high'|'medium'|'low'|'info', title: string, detail: string, path?: string, rec: string }} Finding */

const SECRET_RULES = [
  {
    id: 'private-key',
    severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    title: 'Private key material in tree',
    rec: 'Remove from git history if committed; rotate key; use secret store / CI secrets.',
  },
  {
    id: 'aws-access-key',
    severity: 'critical',
    re: /\bAKIA[0-9A-Z]{16}\b/,
    title: 'AWS-style access key id pattern',
    rec: 'Rotate immediately if real; never commit cloud access keys.',
  },
  {
    id: 'service-role',
    severity: 'critical',
    // Prefer real assignments / embeds, not doc mentions of the concept
    re: /service_role['"\s]*[:=]\s*['"][^'"]{8,}['"]|SERVICE_ROLE_KEY\s*[:=]\s*['"][^'"]{8,}['"]|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+.*service_role/i,
    title: 'service_role / elevated key assignment pattern',
    rec: 'service_role must never ship in client apps. Keep server-only.',
  },
  {
    id: 'generic-api-key-assign',
    severity: 'high',
    re: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['"][^'"]{16,}['"]/i,
    title: 'Hardcoded API key / token assignment',
    rec: 'Move to env/user settings; rotate if this was a real secret.',
  },
  {
    id: 'slack-webhook',
    severity: 'high',
    re: /hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/,
    title: 'Slack webhook URL pattern',
    rec: 'Revoke webhook; store outside git.',
  },
  {
    id: 'github-pat',
    severity: 'critical',
    re: /\bghp_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    title: 'GitHub personal access token pattern',
    rec: 'Revoke token in GitHub; use fine-scoped CI secrets.',
  },
];

const CODE_RULES = [
  {
    id: 'eval',
    severity: 'high',
    re: /\beval\s*\(/,
    title: 'eval() usage',
    rec: 'Avoid eval on untrusted input; prefer JSON.parse / safe parsers.',
  },
  {
    id: 'new-function',
    severity: 'high',
    re: /\bnew\s+Function\s*\(/,
    title: 'new Function() usage',
    rec: 'Same class of risk as eval; remove or strictly constrain inputs.',
  },
  {
    id: 'document-write',
    severity: 'medium',
    re: /\bdocument\.write\s*\(/,
    title: 'document.write()',
    rec: 'Prefer DOM APIs; document.write is XSS-prone with untrusted data.',
  },
  {
    id: 'postmessage-star',
    severity: 'medium',
    re: /\.postMessage\s*\(\s*[^,]+,\s*['"]\*['"]\s*\)/,
    title: 'postMessage with targetOrigin "*"',
    rec: 'Use explicit origin (e.g. location.origin) for same-app tools; never broadcast secrets.',
  },
  {
    id: 'innerhtml-assign',
    severity: 'low',
    re: /\.innerHTML\s*=/,
    title: 'innerHTML assignment (review for XSS)',
    rec: 'Escape user/AI data (textContent or trusted sanitizer). Count is informational unless paired with untrusted data.',
  },
];

export function shouldSkipDir(name) {
  return SKIP_DIR.has(name) || name.startsWith('.') && name !== '.env' && name !== '.github';
}

export function isProbablyTextFile(filePath) {
  const base = filePath.split(/[/\\]/).pop() || '';
  if (base === '.env' || base.startsWith('.env.')) return true;
  const i = base.lastIndexOf('.');
  if (i < 0) return false;
  return TEXT_EXT.has(base.slice(i).toLowerCase());
}

/**
 * Run all content rules on a single file body.
 * @param {string} relPath
 * @param {string} text
 * @returns {Finding[]}
 */
/** Test fixtures intentionally contain bad patterns — skip by default */
export function isTestPath(relPath) {
  const p = relPath.replace(/\\/g, '/');
  return (
    /(^|\/)tests?\//i.test(p) ||
    /(^|\/)__tests__\//i.test(p) ||
    /\.(test|spec)\.(js|mjs|cjs|ts|tsx)$/i.test(p)
  );
}

export function analyzeFileContent(relPath, text, options = {}) {
  /** @type {Finding[]} */
  const findings = [];
  if (!text || typeof text !== 'string') return findings;
  if (!options.includeTests && isTestPath(relPath)) return findings;

  // skip minified vendor noise for some rules
  const isMin = /\.min\.(js|css)$/i.test(relPath) || /node_modules|\/lib\/|\\lib\\/.test(relPath);

  for (const rule of SECRET_RULES) {
    if (rule.re.test(text)) {
      findings.push({
        id: rule.id,
        severity: rule.severity,
        title: rule.title,
        detail: `Pattern matched in ${relPath}`,
        path: relPath,
        rec: rule.rec,
      });
    }
  }

  if (!isMin) {
    for (const rule of CODE_RULES) {
      if (rule.id === 'innerhtml-assign' && isMin) continue;
      const m = rule.re.exec(text);
      if (!m) continue;
      // Skip matches that are only rule-definition source (this scanner / similar)
      const lineStart = text.lastIndexOf('\n', m.index) + 1;
      const lineEnd = text.indexOf('\n', m.index);
      const line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
      if (/^\s*(re|pattern|id)\s*:/.test(line) || /rule\.re|CODE_RULES|SECRET_RULES/.test(line)) {
        continue;
      }
      findings.push({
        id: rule.id,
        severity: rule.severity,
        title: rule.title,
        detail: `Pattern matched in ${relPath}`,
        path: relPath,
        rec: rule.rec,
      });
    }
  }

  if (/\.html?$/i.test(relPath)) {
    if (!/http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(text) && !/Content-Security-Policy/i.test(text)) {
      findings.push({
        id: 'csp-meta-missing',
        severity: 'low',
        title: 'No Content-Security-Policy meta in HTML',
        detail: relPath,
        path: relPath,
        rec: 'Consider CSP (start report-only). Headers on the host count too — this check is HTML-only.',
      });
    }
    if (/<script[^>]+src=["']http:\/\//i.test(text)) {
      findings.push({
        id: 'script-http',
        severity: 'medium',
        title: 'Script loaded over http://',
        detail: relPath,
        path: relPath,
        rec: 'Use https:// and prefer SRI / self-host for integrity.',
      });
    }
  }

  return findings;
}

/**
 * Path-only rules (no file body required for all).
 * @param {string[]} relPaths
 * @returns {Finding[]}
 */
export function analyzePaths(relPaths) {
  /** @type {Finding[]} */
  const findings = [];
  const set = new Set(relPaths.map((p) => p.replace(/\\/g, '/')));

  for (const p of set) {
    const base = p.split('/').pop() || '';
    if (base === '.env' || /^\.env\./.test(base) || base.endsWith('.env')) {
      if (base.includes('example') || base.includes('sample') || base.includes('template')) {
        findings.push({
          id: 'env-example',
          severity: 'info',
          title: 'Env example/template present',
          detail: p,
          path: p,
          rec: 'Fine if no real secrets. Keep real .env out of git.',
        });
      } else {
        findings.push({
          id: 'env-file',
          severity: 'high',
          title: 'Environment file present in tree',
          detail: p + ' (contents not printed)',
          path: p,
          rec: 'Ensure .env is gitignored and never committed. Rotate if it was pushed.',
        });
      }
    }
  }

  return findings;
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Coarse hygiene band — NOT "secure".
 * @param {Finding[]} findings
 */
export function hygieneBand(findings) {
  const ranks = findings.map((f) => SEV_RANK[f.severity] ?? 0);
  const max = ranks.length ? Math.max(...ranks) : 0;
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  if (crit > 0) return 'D';
  if (high >= 3 || max >= 3 && high >= 1) return 'C';
  if (high >= 1 || findings.filter((f) => f.severity === 'medium').length >= 4) return 'B';
  return 'A';
}

/**
 * @param {{ rootName: string, files: Record<string, string|null>, paths?: string[] }} input
 */
export function analyzeProject(input) {
  const { rootName, files } = input;
  const paths = input.paths || Object.keys(files);
  /** @type {Finding[]} */
  let findings = [...analyzePaths(paths)];

  const includeTests = Boolean(input.includeTests);
  for (const [rel, text] of Object.entries(files)) {
    if (text == null) continue;
    findings = findings.concat(analyzeFileContent(rel, text, { includeTests }));
  }

  // dedupe by id+path
  const seen = new Set();
  findings = findings.filter((f) => {
    const k = `${f.id}::${f.path || ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  findings.sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));

  const band = hygieneBand(findings);
  const recs = [...new Set(findings.map((f) => f.rec))].slice(0, 12);

  const report = {
    rootName,
    disclaimer: DISCLAIMER,
    hygieneBand: band,
    findings,
    recommendations: recs,
    metrics: {
      filesScanned: Object.keys(files).filter((k) => files[k] != null).length,
      pathsSeen: paths.length,
      findingCount: findings.length,
      bySeverity: countBySev(findings),
    },
  };
  report.briefing = buildBriefing(report);
  report.summary = buildSummary(report);
  return report;
}

function countBySev(findings) {
  const o = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (o[f.severity] != null) o[f.severity]++;
  }
  return o;
}

export function buildSummary(report) {
  const lines = [];
  lines.push(`Secgate  ${report.rootName}  hygieneBand=${report.hygieneBand}`);
  lines.push(DISCLAIMER);
  lines.push('');
  const m = report.metrics.bySeverity;
  lines.push(
    `Findings: ${report.metrics.findingCount}  (critical ${m.critical}, high ${m.high}, medium ${m.medium}, low ${m.low}, info ${m.info})`,
  );
  lines.push(`Files scanned: ${report.metrics.filesScanned}`);
  lines.push('');
  for (const f of report.findings.slice(0, 40)) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  ${f.detail}`);
    lines.push(`  → ${f.rec}`);
  }
  if (report.findings.length > 40) {
    lines.push(`… ${report.findings.length - 40} more (use --json)`);
  }
  if (report.recommendations.length) {
    lines.push('');
    lines.push('Top recommendations:');
    report.recommendations.forEach((r, i) => lines.push(`  ${i + 1}. ${r}`));
  }
  return lines.join('\n');
}

/** Paste-safe single newlines */
export function buildBriefing(report) {
  const m = report.metrics.bySeverity;
  const lines = [];
  lines.push(`# Secgate briefing — ${report.rootName} (hygiene ${report.hygieneBand})`);
  lines.push(DISCLAIMER);
  lines.push(
    `Findings: ${report.metrics.findingCount} · critical ${m.critical} · high ${m.high} · medium ${m.medium} · low ${m.low} · info ${m.info}`,
  );
  lines.push('## Top issues');
  const top = report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 8);
  if (!top.length) {
    lines.push('- No critical/high static hygiene hits in scanned slice (still not an audit).');
  } else {
    top.forEach((f, i) => lines.push(`${i + 1}. [${f.severity}] ${f.title} — ${f.path || f.detail}`));
  }
  lines.push('## Do next');
  report.recommendations.slice(0, 5).forEach((r, i) => lines.push(`${i + 1}. ${r}`));
  lines.push('_Secgate — hygiene only. Scopegate is process. Neither certifies security._');
  return lines.join('\n');
}

export { SKIP_DIR, SECRET_RULES, CODE_RULES };
