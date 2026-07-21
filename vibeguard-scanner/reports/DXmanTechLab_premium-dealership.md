# VibeGuard security report

**App:** https://github.com/DXmanTechLab/premium-dealership
**Scanned:** 2026-07-21 12:34 UTC

## The short version

- 🔴 **1** critical issue
- 🟠 **1** high issue
- 🟡 **1** medium issue
- 🔵 **2** good to know issues

Start with the critical items. Each one is the kind of thing that ends up as a "my app got hacked" post. All of them have step-by-step fixes below, most take under 30 minutes.

## 🔴 CRITICAL, fix today

### 1 dependency with known critical vulnerabilities

**Where:** `package-lock.json:1`

**What this means:** Packages with publicly documented critical security holes (CVEs): next. These are frozen at whatever version the AI generated. Attackers can look up exactly how to exploit each one.

**How to fix:** Run `npm audit fix` (safe upgrades), then `npm audit` again and review what remains. Re-test the app after upgrading.

## 🟠 HIGH, fix this week

### 6 dependencies with known high vulnerabilities

**Where:** `package-lock.json:1`

**What this means:** Packages with publicly documented high security holes (CVEs): @next/eslint-plugin-next, @typescript-eslint/parser, @typescript-eslint/typescript-estree, eslint-config-next, glob, minimatch. These are frozen at whatever version the AI generated. Attackers can look up exactly how to exploit each one.

**How to fix:** Run `npm audit fix` (safe upgrades), then `npm audit` again and review what remains. Re-test the app after upgrading.

## 🟡 MEDIUM, worth fixing

### No security headers configured

**What this means:** No Content-Security-Policy, X-Frame-Options, or Strict-Transport-Security found anywhere. The site works the same without them, but the browser runs with its guard down: easier clickjacking, script injection does more damage, and HTTP isn't forced to HTTPS.

**How to fix:** Add headers in your host config (vercel.json / netlify.toml / next.config headers()). Start with X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Strict-Transport-Security, then add a CSP once you know your script sources.

## 🔵 GOOD TO KNOW

### Supabase detected, but no migrations in the repo to verify RLS

**What this means:** The app uses Supabase but table definitions are not in the repo, so RLS can't be checked from code alone. Most 'my app got wiped' stories start with RLS disabled.

**How to fix:** In the Supabase dashboard: Database > Tables, confirm every table shows 'RLS enabled', and that policies exist. A table with RLS enabled but zero policies blocks everyone, one with RLS disabled allows everyone.

### 1 dependencies with moderate/low advisories

**Where:** `package-lock.json:1`

**What this means:** Lower-risk known issues in dependencies. Worth cleaning up but not urgent.

**How to fix:** Run `npm audit` for the list, upgrade when convenient.

---

*Scanned by [VibeGuard](https://vibeguard-6809.netlify.app), a security scanner for AI-built apps. Checks: hardcoded keys and tokens, secrets in frontend bundles, committed .env files, Supabase Row Level Security, unauthenticated API routes, IDOR patterns, dependency CVEs, security headers, CORS.*
