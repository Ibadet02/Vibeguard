import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { stat } from "node:fs/promises";
import path from "node:path";
import { lineOf } from "./walk.js";

const exec = promisify(execFile);

// A finding: { severity, title, file, line, detail, fix }
// severity: critical | high | medium | info

/* ---------------- secrets in code ---------------- */

const KEY_PATTERNS = [
  { name: "Stripe live secret key", re: /sk_live_[0-9a-zA-Z]{10,}/g, severity: "critical" },
  { name: "Stripe restricted key", re: /rk_live_[0-9a-zA-Z]{10,}/g, severity: "critical" },
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{16,}/g, severity: "critical" },
  { name: "OpenAI API key", re: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, severity: "critical" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/g, severity: "high" },
  { name: "GitHub token", re: /(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/g, severity: "critical" },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: "high" },
];

const PLACEHOLDER = /(xxx|example|your[-_]|changeme|placeholder|dummy|test[-_]?key|1234567890)/i;

const CLIENT_PATH = /^(src|public|app|pages|components|dist|build|out)\b/i;

function isClientFile(rel) {
  return CLIENT_PATH.test(rel) && !/^(pages\/api|app\/api|src\/server)/i.test(rel);
}

function isCodeFile(rel) {
  return /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro)$/.test(rel);
}

export function checkSecretsInCode(files) {
  const findings = [];
  for (const f of files) {
    if (f.rel === ".env" || f.rel.startsWith(".env.") || f.rel.endsWith(".md")) continue;
    for (const p of KEY_PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(f.content)) !== null) {
        if (PLACEHOLDER.test(m[0])) continue;
        // OpenAI pattern also matches Anthropic prefix; skip the overlap
        if (p.name.startsWith("OpenAI") && m[0].startsWith("sk-ant-")) continue;
        const client = isClientFile(f.rel);
        findings.push({
          severity: client ? "critical" : p.severity,
          title: `${p.name} hardcoded in ${client ? "frontend" : "source"} code`,
          file: f.rel,
          line: lineOf(f.content, m.index),
          detail: client
            ? `Found what looks like a real ${p.name} in a file that ships to the browser. Anyone who opens devtools can read it and use it as you, spend on your account, or pull your data.`
            : `Found what looks like a real ${p.name} committed in your source code. Anyone with repo access (including AI tools and anyone you share the code with) can use it.`,
          fix: `Revoke this key in the provider dashboard NOW, then create a new one. Store the new key in an environment variable on the server only, never in code. Add the value to your host's env settings (Vercel/Netlify/Railway settings page).`,
        });
      }
    }
    // Supabase service_role JWTs (decode payload and look at the role claim)
    const jwtRe = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
    let jm;
    while ((jm = jwtRe.exec(f.content)) !== null) {
      const payload = decodeJwtPayload(jm[0]);
      if (payload && payload.role === "service_role") {
        const client = isClientFile(f.rel);
        findings.push({
          severity: "critical",
          title: `Supabase service_role key ${client ? "exposed in frontend code" : "committed in source"}`,
          file: f.rel,
          line: lineOf(f.content, jm.index),
          detail:
            "The service_role key bypasses ALL Row Level Security. With it, anyone can read, change, or delete every row in your database. " +
            (client
              ? "This one is in code that ships to the browser, so it is effectively public."
              : "This one is committed in your repo."),
          fix: "Rotate the key in Supabase (Settings > API > Reset service_role). The service_role key must only ever live in server-side environment variables. In the browser, use the anon key and rely on RLS policies.",
        });
      }
    }
  }
  return findings;
}

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/* ---------------- hardcoded fallback secrets ---------------- */

// process.env.JWT_SECRET || "dev-secret" and friends. The app runs fine
// without the env var set, silently signing tokens with a value that is
// public in the repo. Matches both process.env.X and a destructured env.X,
// with || or ?? fallbacks. Placeholder-looking values are NOT skipped here:
// a guessable fallback is exactly the problem.
const FALLBACK_SECRET_RE =
  /\b(?:process\.env|env)(?:\.|\[\s*["'])([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|SALT|SIGNING_KEY|PRIVATE_KEY|API_KEY)[A-Z0-9_]*)(?:["']\s*\])?\s*(?:\|\||\?\?)\s*["'`]([^"'`\n]+)["'`]/g;

const TEST_PATH = /(^|\/)(test|tests|spec|specs|__tests__|__mocks__|e2e|fixtures)\//i;

export function checkFallbackSecrets(files) {
  const findings = [];
  for (const f of files) {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|py|rb|php)$/.test(f.rel)) continue;
    if (TEST_PATH.test(f.rel) || /\.(test|spec)\./.test(f.rel)) continue;
    FALLBACK_SECRET_RE.lastIndex = 0;
    let m;
    while ((m = FALLBACK_SECRET_RE.exec(f.content)) !== null) {
      const [, name, value] = m;
      if (value.includes("${")) continue; // dynamic value, not a hardcoded fallback
      const isAuthSecret = /JWT|SESSION|AUTH|COOKIE|SIGNING|REFRESH/i.test(name) || /SECRET/.test(name);
      findings.push({
        severity: "high",
        title: `Hardcoded fallback secret for ${name}`,
        file: f.rel,
        line: lineOf(f.content, m.index),
        detail:
          `When ${name} is missing from the environment, the code silently falls back to a value that is sitting in your repo for anyone to read. Deploy once without that env var set and the app works perfectly while running on a known secret.` +
          (isAuthSecret
            ? " For a JWT or session secret that means anyone who reads the repo can forge a valid login token for any user, full account takeover."
            : ""),
        fix:
          `Remove the fallback and fail loudly instead: if (!process.env.${name}) throw new Error("${name} is not set"). ` +
          "An app that refuses to boot gets fixed in minutes. An app quietly signing tokens with a default value gets hacked. Use a separate .env for local dev instead of a fallback in code.",
      });
    }
  }
  return findings;
}

/* ---------------- .env hygiene ---------------- */

export async function checkEnvFiles(files, root) {
  const findings = [];
  const envFiles = files.filter(
    (f) => (path.basename(f.rel) === ".env" || path.basename(f.rel).startsWith(".env.")) &&
      !f.rel.endsWith(".example") && !f.rel.endsWith(".sample") && !f.rel.endsWith(".template")
  );
  if (envFiles.length === 0) return findings;

  // Is the .env actually tracked by git?
  let tracked = new Set();
  try {
    const { stdout } = await exec("git", ["ls-files"], { cwd: root });
    tracked = new Set(stdout.split("\n").map((s) => s.trim()));
  } catch {}

  const gitignore = files.find((f) => f.rel === ".gitignore");

  for (const f of envFiles) {
    const inGit = tracked.has(f.rel);
    const ignored = await isEnvIgnored(root, f.rel, gitignore);
    if (inGit) {
      findings.push({
        severity: "critical",
        title: `${f.rel} is committed to git`,
        file: f.rel,
        line: 1,
        detail:
          "Your environment file (database passwords, API keys) is checked into the repository. If this repo is or ever becomes public, every secret in it is public too. Git also keeps it in history forever, deleting the file later is not enough.",
        fix: "1) Rotate every secret in this file. 2) `git rm --cached " + f.rel + "` and commit. 3) Add `.env*` to .gitignore. 4) If the repo was ever public, treat every value as leaked.",
      });
    } else if (!gitignore) {
      findings.push({
        severity: "high",
        title: "No .gitignore, your .env is one `git push` from leaking",
        file: f.rel,
        line: 1,
        detail:
          "There is a .env file with secrets but no .gitignore. The first time you (or your AI tool) run `git add .` and push, the secrets go with it.",
        fix: "Create a .gitignore that includes `.env*` and `node_modules/` before your next commit.",
      });
    } else if (!ignored) {
      findings.push({
        severity: "high",
        title: ".gitignore does not cover .env files",
        file: ".gitignore",
        line: 1,
        detail: `You have ${f.rel} but .gitignore never mentions .env, so a plain \`git add .\` will stage it.`,
        fix: "Add a line `.env*` to .gitignore.",
      });
    }

    // Public-by-design prefixes holding things that look secret
    for (const [i, line] of f.lines.entries()) {
      const m = line.match(/^\s*((?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*)\s*=\s*(.+)$/);
      if (!m) continue;
      const [, name, valueRaw] = m;
      const value = valueRaw.trim().replace(/^["']|["']$/g, "");
      const looksSecret =
        /SECRET|SERVICE|PRIVATE|PASSWORD|TOKEN/i.test(name) ||
        KEY_PATTERNS.some((p) => { p.re.lastIndex = 0; return p.re.test(value); }) ||
        (decodeJwtPayload(value)?.role === "service_role");
      if (looksSecret && !PLACEHOLDER.test(value)) {
        findings.push({
          severity: "critical",
          title: `${name} is public by design but holds a secret`,
          file: f.rel,
          line: i + 1,
          detail:
            `Anything prefixed ${name.split("_")[0]}_ gets baked into the frontend bundle at build time. It is readable by anyone who opens your site, this is how these frameworks work. The value here looks like a real secret.`,
          fix: "Move this value to a server-only variable (drop the public prefix) and access it from API routes or edge functions. Only truly public values (anon keys, public URLs) belong in public-prefixed vars. Then rotate the exposed secret.",
        });
      }
    }
  }
  return findings;
}

// Whether an env file is actually ignored. Ask git itself when we can,
// because gitignore glob rules are subtle: `*.env` DOES match `.env` (the *
// matches zero characters), which a naive "line starts with .env" regex calls
// uncovered. Fall back to a pattern check when there's no git repo.
async function isEnvIgnored(root, rel, gitignore) {
  try {
    await exec("git", ["check-ignore", "-q", rel], { cwd: root });
    return true; // exit 0: ignored
  } catch (e) {
    if (e && e.code === 1) return false; // exit 1: definitively not ignored
    // any other failure (not a git repo, git missing): fall through to regex
  }
  if (!gitignore) return false;
  // .env, .env*, .env.*, *.env, *.env*, **/.env and combinations
  return gitignore.content
    .split("\n")
    .map((l) => l.trim())
    .some((l) => /^(\*\*\/)?\*?\.env(\*|\.\*)?$/.test(l));
}

/* ---------------- Supabase RLS ---------------- */

// RLS only matters when the database is exposed directly to browsers via
// Supabase's anon key. In a classic three-tier app (browser -> API server ->
// Postgres via Prisma/Drizzle/etc.), auth lives in the API layer and a
// CREATE TABLE without RLS is normal, so this check must not fire there.
function usesSupabase(files) {
  for (const f of files) {
    // A real dependency on a Supabase client library.
    if (path.basename(f.rel) === "package.json" && /"@supabase\//.test(f.content)) return true;
    // A Supabase CLI project is wired up.
    if (f.rel === "supabase/config.toml" || f.rel.endsWith("/supabase/config.toml")) return true;
    // The client library is actually imported/required somewhere.
    if (/(?:from\s+|require\(\s*)['"]@supabase\//.test(f.content)) return true;
    // A SUPABASE_ env var is actually consumed by application code
    // (process.env / import.meta.env). We deliberately do NOT treat SUPABASE_
    // names appearing in .env / .env.example templates as evidence: those files
    // routinely list unused or explicitly deprecated vars with placeholder
    // values, and matching them fired 12 bogus RLS findings on a Prisma+Neon
    // app whose only Supabase trace was a "DEPRECATED" block in .env.example.
    if (isCodeFile(f.rel) && /(?:process\.env|import\.meta\.env)\.[A-Za-z_]*SUPABASE_[A-Za-z_]*/.test(f.content)) return true;
  }
  return false;
}

export function checkSupabaseRls(files) {
  const findings = [];
  if (!usesSupabase(files)) return findings;
  const sqlFiles = files.filter((f) => f.rel.endsWith(".sql"));
  const allSql = sqlFiles.map((f) => f.content).join("\n").toLowerCase();

  for (const f of sqlFiles) {
    const lower = f.content.toLowerCase();
    const tableRe = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?["']?([a-z0-9_]+)["']?/g;
    let m;
    while ((m = tableRe.exec(lower)) !== null) {
      const table = m[1];
      const rlsRe = new RegExp(`alter\\s+table\\s+(?:public\\.)?["']?${table}["']?\\s+enable\\s+row\\s+level\\s+security`);
      if (!rlsRe.test(allSql)) {
        findings.push({
          severity: "high",
          title: `Table "${table}" is created without Row Level Security`,
          file: f.rel,
          line: lineOf(f.content, m.index),
          detail:
            "In Supabase, a table without RLS is readable and writable by anyone holding your anon key, and the anon key is public by design. The app will look like it works perfectly, until someone opens the browser console and reads or wipes the whole table.",
          fix: `Add to your migration: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; then write policies for who can select/insert/update/delete. Test as a logged-in user AND as a logged-out visitor.`,
        });
      }
    }
  }

  // Supabase in use but table definitions not in the repo -> one reminder to verify RLS in dashboard
  if (sqlFiles.length === 0) {
    findings.push({
      severity: "info",
      title: "Supabase detected, but no migrations in the repo to verify RLS",
      file: null,
      line: null,
      detail:
        "The app uses Supabase but table definitions are not in the repo, so RLS can't be checked from code alone. Most 'my app got wiped' stories start with RLS disabled.",
      fix: "In the Supabase dashboard: Database > Tables, confirm every table shows 'RLS enabled', and that policies exist. A table with RLS enabled but zero policies blocks everyone, one with RLS disabled allows everyone.",
    });
  }
  return findings;
}

/* ---------------- API routes without auth ---------------- */

const AUTH_HINTS = /getServerSession|auth\(\)|requireAuth|verifyToken|jsonwebtoken|jwt\.verify|clerk|supabase\.auth|getToken|withAuth|session|authorization|api[_-]?key|bearer/i;
const MUTATING_HINT = /\b(insert|update|delete|create|write|post|put|patch|remove|destroy)\b/i;

export function checkUnprotectedRoutes(files) {
  const findings = [];
  const routes = files.filter((f) =>
    /^(pages\/api\/|app\/api\/).*\.(js|ts|jsx|tsx)$/.test(f.rel) ||
    /(^|\/)api\/.*route\.(js|ts)$/.test(f.rel)
  );
  for (const f of routes) {
    if (AUTH_HINTS.test(f.content)) continue;
    const mutates = MUTATING_HINT.test(f.content);
    findings.push({
      severity: mutates ? "high" : "medium",
      title: `API route ${f.rel} has no auth check that I can see`,
      file: f.rel,
      line: 1,
      detail:
        "This endpoint appears to accept requests from anyone on the internet, no session check, token check, or key check was found in the file." +
        (mutates ? " It also looks like it writes or deletes data, which makes an open endpoint riskier." : ""),
      fix: "If this route is meant to be public, you can ignore this. Otherwise add an auth check at the top (verify the user's session or token and return 401 if missing) before doing any work. Also make sure it validates its inputs.",
    });
  }
  return findings;
}

/* ---------------- IDOR-ish patterns ---------------- */

export function checkIdorPatterns(files) {
  const findings = [];
  const routes = files.filter((f) => /^(pages\/api\/|app\/api\/)/.test(f.rel));
  for (const f of routes) {
    // fetching by an id taken straight from params/query with no ownership filter
    const re = /\.(?:eq|match)\(\s*['"]?(?:id|user_id|owner_id)['"]?\s*,\s*(?:req\.query|params|searchParams)/g;
    let m;
    while ((m = re.exec(f.content)) !== null) {
      if (/session|auth|user\.id|userId/.test(f.content)) continue;
      findings.push({
        severity: "high",
        title: `Possible IDOR in ${f.rel}: record looked up by client-supplied id`,
        file: f.rel,
        line: lineOf(f.content, m.index),
        detail:
          "The route fetches a record using an id that comes straight from the request, without tying it to the logged-in user. Anyone can change the id in the URL (1002 to 1001) and read someone else's data.",
        fix: "After authenticating, filter by the session user too (e.g. .eq('user_id', session.user.id)) or verify ownership before returning the record.",
      });
    }
  }
  return findings;
}

/* ---------------- identity trusted from a client-supplied header ---------------- */

// A backend that decides *who the user is* by reading a plain request header
// (x-user-id and friends) is trusting the client. Whoever makes the request
// sets the headers, so unless the value is cryptographically bound (a verified
// JWT/session), anyone can send `x-user-id: <victim>` and act as that user.
// This is the "proxy injects the header after auth, but the backend is also
// reachable directly" multi-tenant bypass, the exact bug that a real Express
// service shipped (auth derived from req.headers['x-user-id'] with no verify).
//
// Fires on: server-side code that READS an identity header.
// Must NOT fire on:
//   - the proxy/edge layer that SETS the header after real auth (`.set(...)`),
//   - a file that verifies a real credential itself (JWT/session/Clerk/etc.),
//   - client-side code and tests.
const IDENTITY_HEADER = "x-(?:user-?id|user|uid|account-?id|tenant-?id|customer-?id|org-?id|auth-?user(?:-?id)?)";

const HEADER_READ_RE = new RegExp(
  // req.headers['x-user-id'] / request.headers["x-user-id"]
  `(?:\\breq|\\brequest|\\bctx|\\bevent)\\b[\\w.?]*\\.headers\\s*\\[\\s*['"\`](${IDENTITY_HEADER})['"\`]\\s*\\]` +
  // req.get('x-user-id') / req.header('x-user-id') / headers.get('x-user-id')
  `|(?:\\breq|\\brequest|\\bctx|\\bheaders|\\bhdrs)\\b[\\w.?]*\\.(?:get|header)\\s*\\(\\s*['"\`](${IDENTITY_HEADER})['"\`]\\s*\\)`,
  "gi"
);

// The file independently verifies a real credential, so the header is likely a
// value it derived after auth rather than the sole trust anchor.
const REAL_AUTH_RE =
  /jwt\.verify|jsonwebtoken|jwtVerify|createRemoteJWKSet|authenticateRequest|verifyToken|verifyIdToken|getServerSession|next-auth|@clerk\/backend|clerkClient|getAuth\s*\(|passport\.|verifySessionCookie|lucia/i;

export function checkTrustedIdentityHeader(files) {
  const findings = [];
  for (const f of files) {
    if (!isCodeFile(f.rel)) continue;
    if (isClientFile(f.rel)) continue;
    if (TEST_PATH.test(f.rel) || /\.(test|spec)\./.test(f.rel)) continue;
    if (REAL_AUTH_RE.test(f.content)) continue;
    HEADER_READ_RE.lastIndex = 0;
    let m;
    const seen = new Set();
    while ((m = HEADER_READ_RE.exec(f.content)) !== null) {
      const header = (m[1] || m[2] || "").toLowerCase();
      if (!header || seen.has(header)) continue;
      seen.add(header);
      findings.push({
        severity: "critical",
        title: `Auth bypass: user identity trusted from the "${header}" request header`,
        file: f.rel,
        line: lineOf(f.content, m.index),
        detail:
          `This code decides which user a request belongs to by reading the \`${header}\` header straight off the request. Request headers are set by whoever makes the call, so anyone can send \`${header}: <someone-elses-id>\` and be treated as that user. ` +
          "Nothing here checks a signed token or session, so if this service is reachable directly (its URL is usually public, and CORS does not stop non-browser calls like curl), an attacker can read and change every other user's data by changing one header. That is a full multi-tenant / account takeover.",
        fix:
          "Do not treat a plain header as proof of identity. Verify a real credential on this service and read the user id from it: check the session or JWT here (using your auth provider's server SDK) and take the user id from the verified token, never from a header. " +
          "If you must keep a trusted-proxy setup, require a strong shared secret between the proxy and this service (compared with crypto.timingSafeEqual), strip any inbound copy of this header at the proxy, block direct internet access to this service, and remove any `?userId=` / body `userId` fallbacks.",
      });
    }
  }
  return findings;
}

/* ---------------- dependency CVEs ---------------- */

// package-lock.json is not the only lockfile in the world. pnpm workspaces,
// yarn, and bun all pin versions just as well, and some of these files never
// make it into the walked file list (yarn.lock has an unknown extension,
// bun.lockb is binary), so we check the disk directly.
const LOCKFILES = [
  { file: "package-lock.json", pm: "npm" },
  { file: "npm-shrinkwrap.json", pm: "npm" },
  { file: "pnpm-lock.yaml", pm: "pnpm" },
  { file: "yarn.lock", pm: "yarn" },
  { file: "bun.lockb", pm: "bun" },
  { file: "bun.lock", pm: "bun" },
];

function detectPackageManager(files) {
  const pkg = files.find((f) => f.rel === "package.json");
  const m = pkg?.content.match(/"packageManager"\s*:\s*"([a-z]+)@/);
  if (m) return m[1];
  if (files.some((f) => f.rel === "pnpm-workspace.yaml")) return "pnpm";
  return "npm";
}

// Run `<tool> audit --json` (optionally scoped to prod deps) and bucket the
// vulnerable package names by severity. audit exits non-zero when vulns exist,
// so we read stdout off the thrown error too.
async function auditBuckets(tool, root, extraArgs) {
  const { stdout } = await exec(tool, ["audit", "--json", ...extraArgs], {
    cwd: root,
    maxBuffer: 20 * 1024 * 1024,
  }).catch((e) => ({ stdout: e.stdout || "" }));
  const data = JSON.parse(stdout);
  // A successful audit always includes a vulnerabilities (npm v7+) or
  // advisories (pnpm / npm v6) object, even when empty. If neither is present
  // the audit actually failed (offline, registry unreachable, EUSAGE) and
  // returned a JSON error object, so treat that as a failure rather than
  // silently reporting zero dependency issues.
  if (!data.vulnerabilities && !data.advisories) {
    throw new Error(data.error?.summary || data.error?.code || "audit returned no results");
  }
  const bySev = { critical: [], high: [], moderate: [], low: [] };
  if (data.vulnerabilities) {
    // npm v7+ format
    for (const [name, v] of Object.entries(data.vulnerabilities)) {
      if (bySev[v.severity] && !bySev[v.severity].includes(name)) bySev[v.severity].push(name);
    }
  } else if (data.advisories) {
    // pnpm / npm v6 format
    for (const a of Object.values(data.advisories)) {
      if (bySev[a.severity] && !bySev[a.severity].includes(a.module_name)) bySev[a.severity].push(a.module_name);
    }
  }
  return bySev;
}

export async function checkDependencies(root, files) {
  const findings = [];
  const hasPkg = files.some((f) => f.rel === "package.json");
  if (!hasPkg) return findings;

  let lock = null;
  for (const l of LOCKFILES) {
    try {
      await stat(path.join(root, l.file));
      lock = l;
      break;
    } catch {}
  }

  if (!lock) {
    const pm = detectPackageManager(files);
    const lockCmd = {
      npm: "npm install --package-lock-only",
      pnpm: "pnpm install --lockfile-only",
      yarn: "yarn install",
      bun: "bun install",
    }[pm] || "npm install --package-lock-only";
    findings.push({
      severity: "info",
      title: "No lockfile, dependency versions are not pinned",
      file: "package.json",
      line: 1,
      detail: "No package-lock.json, pnpm-lock.yaml, yarn.lock, or bun lockfile found. Without one, installs can pull different versions than you tested, and known-vulnerable versions can't be audited reliably.",
      fix: `Run \`${lockCmd}\` and commit the lockfile.`,
    });
    return findings;
  }

  if (lock.pm === "npm" || lock.pm === "pnpm") {
    const tool = lock.pm;
    try {
      const full = await auditBuckets(tool, root, []);
      // Second pass scoped to production dependencies. A CVE that only affects
      // local build/dev tooling (a test runner, a bundler plugin) is not
      // reachable in the deployed app, so it should not read as a "fix today"
      // critical. Best-effort: if this fails, treat everything as production.
      let prodSet = null;
      try {
        const prodArgs = tool === "npm" ? ["--omit=dev"] : ["--prod"];
        const prod = await auditBuckets(tool, root, prodArgs);
        prodSet = new Set([...prod.critical, ...prod.high, ...prod.moderate, ...prod.low]);
      } catch {}

      const fixCmd = tool === "npm"
        ? "Run `npm audit fix` (safe upgrades), then `npm audit` again and review what remains."
        : "Run `pnpm audit` for the full list, upgrade with `pnpm update <package>`, and use `pnpm audit --fix` (writes overrides) for anything that can't upgrade cleanly.";

      for (const sev of ["critical", "high"]) {
        const names = prodSet ? full[sev].filter((n) => prodSet.has(n)) : full[sev];
        if (names.length) {
          findings.push({
            severity: sev,
            title: `${names.length} ${names.length === 1 ? "dependency" : "dependencies"} with known ${sev} vulnerabilities`,
            file: lock.file,
            line: 1,
            detail:
              `Packages with publicly documented ${sev} security holes (CVEs): ${names.slice(0, 8).join(", ")}${names.length > 8 ? "..." : ""}. ` +
              "These are frozen at whatever version the AI generated. Attackers can look up exactly how to exploit each one.",
            fix: `${fixCmd} Re-test the app after upgrading.`,
          });
        }
      }

      // Critical/high advisories that only affect dev/build tooling: real, but
      // not exposed by the deployed app, so a cleanup note rather than a fire.
      const devHigh = prodSet
        ? [...full.critical, ...full.high].filter((n) => !prodSet.has(n))
        : [];
      if (devHigh.length) {
        findings.push({
          severity: "info",
          title: `${devHigh.length} dev-only ${devHigh.length === 1 ? "dependency has" : "dependencies have"} high/critical advisories`,
          file: lock.file,
          line: 1,
          detail:
            `These advisories are in build or dev tooling (${devHigh.slice(0, 8).join(", ")}${devHigh.length > 8 ? "..." : ""}) that runs on your machine or in CI, not in the app you deploy, so an attacker hitting your live site can't reach them. Still worth cleaning up so they don't ship if your build setup changes.`,
          fix: `Run \`${tool} audit\` to see them and upgrade the dev tool when convenient.`,
        });
      }

      const modLow = full.moderate.length + full.low.length;
      if (modLow > 0) {
        findings.push({
          severity: "info",
          title: `${modLow} dependencies with moderate/low advisories`,
          file: lock.file,
          line: 1,
          detail: "Lower-risk known issues in dependencies. Worth cleaning up but not urgent.",
          fix: `Run \`${tool} audit\` for the list, upgrade when convenient.`,
        });
      }
    } catch {
      findings.push({
        severity: "info",
        title: `Could not run ${tool} audit`,
        file: lock.file,
        line: 1,
        detail: `${tool} audit failed here (offline or ${tool} missing), so dependency CVEs were not checked.`,
        fix: `Run \`${tool} audit\` in the project folder yourself.`,
      });
    }
  } else {
    // yarn and bun pin versions fine, we just don't parse their audit output yet
    findings.push({
      severity: "info",
      title: `Dependency CVEs not checked automatically (${lock.file})`,
      file: lock.file,
      line: 1,
      detail: `Your versions are pinned by ${lock.file}, which is good. This scanner only runs automated CVE audits for npm and pnpm lockfiles, so known-vulnerable versions were not checked.`,
      fix: lock.pm === "yarn"
        ? "Run `yarn audit` (Yarn 1) or `yarn npm audit` (Yarn 2+) yourself and upgrade anything critical or high."
        : "Run `bun audit` yourself and upgrade anything critical or high.",
    });
  }
  return findings;
}

/* ---------------- security headers ---------------- */

// Figure out what actually serves the responses, so the fix advice points at
// the right place. "Add vercel.json" is useless advice for an Express app.
function serverFramework(files) {
  const deps = files
    .filter((f) => path.basename(f.rel) === "package.json")
    .map((f) => f.content)
    .join("\n");
  if (/"next"\s*:/.test(deps)) return "next";
  if (/"express"\s*:/.test(deps)) return "express";
  if (/"fastify"\s*:/.test(deps)) return "fastify";
  if (/"koa"\s*:/.test(deps)) return "koa";
  return null;
}

const HEADER_FIXES = {
  next: "Add a headers() function to next.config (see Next.js docs, 'headers'). Start with X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Strict-Transport-Security, then add a CSP once you know your script sources.",
  express: "Your responses come from Express, so set the headers there: `npm i helmet`, then `app.use(helmet())` near the top of your server setup, before your routes. That one line covers X-Frame-Options, nosniff, and HSTS; add a CSP once you know your script sources. If your frontend is deployed separately to a static host, set the same headers in that host's config too.",
  fastify: "Your responses come from Fastify, so set the headers there: `npm i @fastify/helmet`, then register it before your routes. That covers X-Frame-Options, nosniff, and HSTS; add a CSP once you know your script sources. If your frontend is deployed separately to a static host, set the same headers in that host's config too.",
  koa: "Your responses come from Koa, so set the headers there: `npm i koa-helmet`, then `app.use(helmet())` before your routes. That covers X-Frame-Options, nosniff, and HSTS; add a CSP once you know your script sources. If your frontend is deployed separately to a static host, set the same headers in that host's config too.",
  static: "Add headers in your host config (vercel.json / netlify.toml / _headers file). Start with X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Strict-Transport-Security, then add a CSP once you know your script sources.",
};

export function checkSecurityHeaders(files) {
  const framework = serverFramework(files);
  const isWebApp =
    framework !== null ||
    files.some((f) =>
      ["next.config.js", "next.config.mjs", "next.config.ts", "vite.config.js", "vite.config.ts", "index.html"].includes(path.basename(f.rel))
    );
  if (!isWebApp) return [];
  const hasHeaders = files.some(
    (f) =>
      /helmet/.test(f.content) ||
      (/headers\s*\(\)|headers\s*:/.test(f.content) && /(Content-Security-Policy|X-Frame-Options|Strict-Transport-Security)/i.test(f.content)) ||
      ["_headers", "vercel.json", "netlify.toml"].includes(path.basename(f.rel)) &&
        /(Content-Security-Policy|X-Frame-Options|Strict-Transport-Security)/i.test(f.content)
  );
  if (hasHeaders) return [];
  return [
    {
      severity: "medium",
      title: "No security headers configured",
      file: null,
      line: null,
      detail:
        "No Content-Security-Policy, X-Frame-Options, or Strict-Transport-Security found anywhere. The site works the same without them, but the browser runs with its guard down: easier clickjacking, script injection does more damage, and HTTP isn't forced to HTTPS.",
      fix: HEADER_FIXES[framework] || HEADER_FIXES.static,
    },
  ];
}

/* ---------------- CORS wildcard ---------------- */

export function checkCors(files) {
  const findings = [];
  const corsRe = /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/;
  for (const f of files) {
    const m = corsRe.exec(f.content);
    const hit = m ? m.index : -1;
    if (hit !== -1) {
      findings.push({
        severity: "medium",
        title: `CORS is wide open (*) in ${f.rel}`,
        file: f.rel,
        line: lineOf(f.content, hit),
        detail: "Any website can call this API from a visitor's browser. Fine for a truly public API, risky if responses depend on cookies or return private data.",
        fix: "Set Access-Control-Allow-Origin to your actual app domain(s) instead of *.",
      });
    }
  }
  return findings;
}
