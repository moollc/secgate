# Secgate

**Local security hygiene instrument** for app/repo folders.

Sibling of [Scopegate](https://github.com/moollc/scopegate) (multi-LM **process** pre-flight).  
Secgate answers a **different** question: static hygiene signals on disk.

## Hard disclaimer

```text
Secgate is NOT a penetration test, compliance certificate, or proof of security.
Hygiene band (A–D) is a coarse signal only. Live cloud policies (e.g. RLS),
auth, and runtime behavior require human / environment verification.
```

## Quick start

```bash
cd secgate
npm test
npm run scan -- /path/to/project
npm run scan -- /path/to/project --json
npm run scan -- /path/to/project --brief
```

## What v0.1 checks

| Area | Examples |
|------|----------|
| Secrets-shaped content | AWS-like keys, private key blocks, `service_role` **assignments**, common API key assignments |
| Browser / JS hazards | dynamic code execution APIs, `document.write`, `postMessage` with wildcard origin |
| HTML | Missing CSP meta (heuristic), `http://` script src |
| Repo hygiene | `.env` / `.env.local` present (path only — does not print secrets) |

Skips `node_modules`, `.git`, common build/cache dirs. Caps file count/size so monorepos do not hang.

## Output

- Severity findings: `critical` | `high` | `medium` | `low` | `info`
- Recommendations (action-oriented)
- Optional **hygiene band** A–D with disclaimer (not “secure”)

## Layout

| Path | Role |
|------|------|
| This folder (`secgate/`) | Product — git root |
| Parent `secgate-workspace/` | `AGENTS.md`, `scaffold/` — local |

## Relation to Scopegate

| Tool | Grades |
|------|--------|
| Scopegate | Workspace **process** cold-start |
| Secgate | App/repo **security hygiene** static signals |

Never merge into one letter. Process A ≠ hygiene A ≠ secure.
