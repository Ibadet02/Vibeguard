# VibeGuard scanner (v0.1)

Security scanner for AI-built ("vibe-coded") apps. Point it at a repo, get a plain-English report of what's exposed and how to fix it. No AI calls, no network needed except `npm audit` and git clones. Free to run, deterministic output.

## Run

```bash
node cli.js /path/to/repo                 # scan a local folder
node cli.js https://github.com/x/y        # shallow-clone and scan
node cli.js /path --out report.md         # choose report location
```

Exit code 1 when criticals are found (CI-friendly later).

## What it checks

- Hardcoded keys/tokens in source (Stripe, AWS, OpenAI, Anthropic, Google, GitHub, Slack), with "ships to the browser" detection
- Supabase service_role JWTs anywhere (decodes the token and reads the role claim)
- .env committed to git / missing .gitignore coverage
- Public-by-design env vars (VITE_/NEXT_PUBLIC_/REACT_APP_/EXPO_PUBLIC_) holding real secrets
- Supabase migrations creating tables without Row Level Security
- API routes with no visible auth check (higher severity when they write/delete)
- IDOR patterns (records looked up by client-supplied id with no ownership check)
- Dependency CVEs via `npm audit` (lockfile required)
- Missing security headers (CSP / X-Frame-Options / HSTS)
- CORS wildcard

## Concierge workflow (validation stage)

1. Someone drops a repo link in the free-scan thread.
2. `node cli.js <link> --out reports/<name>.md`
3. Read the report, sanity-check the findings (heuristic checks can misread unusual code), trim anything wrong.
4. Send the markdown. Ask afterwards: "would you pay for this to run on every deploy?"

Test fixture with planted vulns lives at /tmp/vg-fixture (recreate: see session notes).
