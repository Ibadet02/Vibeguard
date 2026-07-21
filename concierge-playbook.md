# VibeGuard: Concierge scan playbook

How to deliver a real, impressive security scan **by hand** (you + Claude + free tools) when someone signs up, before any product exists. Goal: find out if the output is good enough that people say "take my money," and learn exactly what to build.

Budget ~30–60 min per scan. Do the first 5–10 yourself.

---

## Step 0: Get access
Ask for a **public GitHub repo link** or a zip of the project. (Read-only, you only look.)

## Step 1: Run free scanners (the deterministic layer)
Install once: `npm i -g @secretlint/secretlint gitleaks` (or use `npx`). Then in their project folder:

```bash
# 1. Exposed secrets (API keys, tokens)
npx gitleaks detect --source . --no-git -v

# 2. Code security issues (injection, unsafe patterns): free tier
npx semgrep --config auto .

# 3. Vulnerable dependencies
npm audit --production        # or: npx audit-ci
```

These three catch a large share of real issues automatically.

## Step 2: Manually check the "big three" (what AI always breaks)
1. **Keys in the front-end**: grep the client code: `grep -rEi "sk_live|sk-|api[_-]?key|secret" src/ app/ --include=*.ts --include=*.tsx --include=*.js`. Anything in client-side code = critical.
2. **Open database**: if they use Supabase/Firebase, check whether Row Level Security / rules are enabled. RLS off = critical.
3. **Missing auth**: look at admin pages and API routes: is there a login/permission check, or can anyone hit them?

Also skim: CORS set to `*`, secrets committed to git history, error messages leaking stack traces, no rate limiting on public endpoints.

## Step 3: Turn raw findings into plain English (use Claude)
Paste the scanner output + code snippets to Claude with:
> "For each issue: explain in one plain-English sentence what it means for a non-technical founder, rate severity (critical/high/medium), and give the exact fix as a short instruction they can paste into their AI editor. No jargon."

## Step 4: Assemble the report (match the landing page)
Deliver a clean doc that mirrors the site's promise:

```
VibeGuard scan: <app name>
Scanned <date>

SUMMARY:  2 critical · 1 high · 14 checks passed

[CRITICAL] API key exposed in the browser
Where: src/config.js:42
What it means: Anyone who opens your site can read your OpenAI key and spend your money.
Fix: Move the key to a server environment variable; never reference it in client code.

[CRITICAL] Database open to the public
...

[HIGH] No login on /admin
...

WHAT'S FINE: auth tokens handled correctly, no vulnerable dependencies, HTTPS enforced...
```

Keep it scary-but-kind: they should feel relieved you caught it, not stupid.

## Step 5: Deliver + learn (the actual point)
Send the report, then ask two questions:
1. "Was this useful, did it catch anything you didn't know about?"
2. "Would you want this to run **automatically every time you deploy**? If it were $X/month, would you use it?"

Log every answer. Those two questions are the whole validation.

---

## What you're really testing
- Do people **want** the scan (did they send a repo)?
- Is the output **good enough to pay for** (do they say yes to #2)?
Enough yeses → build the automated version. Silence → the fear isn't strong enough yet; adjust the pitch or pivot.
