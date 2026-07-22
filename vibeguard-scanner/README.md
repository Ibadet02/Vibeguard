# VibeGuard scanner (v0.1)

Security scanner for AI-built ("vibe-coded") apps. Point it at a repo, get a plain-English report of what's exposed and how to fix it.

Two layers:

1. **Pattern checks** — fast, deterministic, no network except `npm audit` and git clones. Always run.
2. **AI reasoning pass** — optional. Give it your own LLM API key and it reads the code like a reviewer: follows data across files, finds logic bugs the patterns miss (broken access control, paid-feature bypasses, client-trusted data), and triages the pattern findings to correct false positives. **Bring your own key; your code is sent only to the provider you configure.**

## Run

```bash
node cli.js /path/to/repo                 # scan a local folder
node cli.js https://github.com/x/y        # shallow-clone and scan
node cli.js /path --out report.md         # choose report location

node server.js                            # local web UI at http://localhost:3488
```

Exit code 1 when criticals are found (CI-friendly later).

## Enable the AI reasoning pass (bring your own key)

```bash
cp .env.example .env      # then paste an OpenAI (or Anthropic) key into .env
node cli.js /path/to/repo # the report now includes an "AI reasoning pass: ran" line
```

Config lives in `.env` (auto-loaded, needs Node 20.12+ / 22) or plain environment variables:

| Variable | Purpose |
| --- | --- |
| `VIBEGUARD_LLM_API_KEY` | your provider key (required to turn the AI pass on) |
| `VIBEGUARD_LLM_API` | `openai` or `anthropic` (auto-detected from the base URL / key if unset) |
| `VIBEGUARD_LLM_MODEL` | model id, e.g. `gpt-4.1` or `claude-opus-4-8` |
| `VIBEGUARD_LLM_BASE_URL` | override for OpenAI-compatible gateways (Azure, OpenRouter, Ollama, ...) |
| `VIBEGUARD_AI=0` | force the AI pass off even with a key present |

Without a key the scanner runs pattern-only and says so in the report. The AI pass is non-fatal: if the provider is unreachable or refuses, you still get the deterministic findings.

> Anthropic note: Claude applies real-time "cyber safeguards" that may refuse security-review prompts unless your account is in their Cyber Verification Program. If you hit that, use an OpenAI-compatible provider.

## What it checks

- Hardcoded keys/tokens in source (Stripe, AWS, OpenAI, Anthropic, Google, GitHub, Slack), with "ships to the browser" detection
- Supabase service_role JWTs anywhere (decodes the token and reads the role claim)
- .env committed to git / missing .gitignore coverage
- Public-by-design env vars (VITE_/NEXT_PUBLIC_/REACT_APP_/EXPO_PUBLIC_) holding real secrets
- Supabase migrations creating tables without Row Level Security
- API routes with no visible auth check (higher severity when they write/delete)
- User identity trusted straight from a request header (e.g. `x-user-id`) with no token/session verification
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
