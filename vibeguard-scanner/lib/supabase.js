// Live Supabase check.
//
// The repo-only scan cannot answer the question that actually matters for a
// vibe-coded app: is the database open to the internet right now? Table
// policies live in the Supabase dashboard, not in git, which is why a scan of a
// Lovable app so often comes back clean while the data is wide open.
//
// So we look from outside, the way an attacker would, using ONLY the anon key —
// which already ships in the app's JavaScript bundle and is public by design.
// VibeGuard never holds a database credential.
//
// Two rules this module exists to enforce:
//
//   1. READ ONLY, AND NEVER READ DATA. We prove a table is exposed with a HEAD
//      request that returns a row count in a header. Column names come from the
//      API's own OpenAPI description. No row value is ever fetched, so customer
//      PII never reaches our logs, our reports, or our disk.
//   2. THE URL IS UNTRUSTED. It is harvested from a repo we did not write, so a
//      malicious repo could point it at cloud metadata or an internal host and
//      turn this into an SSRF primitive. Only https://<ref>.supabase.co passes.
//
// Consent is the caller's job: server.js will not enable this without an
// explicit ownership affirmation from the user.

const REQUEST_TIMEOUT_MS = 10000;
const TOTAL_BUDGET_MS = 60000;
const MAX_TABLES = 40;
const PROBE_CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Target validation (SSRF guard)
// ---------------------------------------------------------------------------

// Supabase project refs are lowercase alphanumeric. Anything that is not
// exactly https://<ref>.supabase.co is refused: no self-hosted hosts, no IPs,
// no ports, no paths. Self-hosted support would need its own opt-in allowlist.
const PROJECT_REF_RE = /^[a-z0-9]{15,}$/;

export function parseProjectUrl(raw) {
  let u;
  try {
    u = new URL(String(raw || "").trim());
  } catch {
    return { error: "That doesn't look like a valid URL." };
  }
  if (u.protocol !== "https:") return { error: "The Supabase URL must start with https://." };
  if (u.port) return { error: "The Supabase URL must not include a port." };
  if (u.pathname !== "/" && u.pathname !== "") return { error: "Use the bare project URL, with no path." };

  const host = u.hostname.toLowerCase();
  const suffix = ".supabase.co";
  if (!host.endsWith(suffix)) {
    return { error: "Only hosted Supabase projects (https://<project>.supabase.co) can be checked." };
  }
  const ref = host.slice(0, -suffix.length);
  if (!PROJECT_REF_RE.test(ref)) {
    return { error: "That doesn't look like a Supabase project URL." };
  }
  return { origin: `https://${host}`, ref };
}

// ---------------------------------------------------------------------------
// Credential harvesting from the repo
// ---------------------------------------------------------------------------

const URL_RE = /https:\/\/([a-z0-9]{15,})\.supabase\.co/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
// Supabase's newer key format. The publishable key is the anon key's successor
// and is equally public; the secret one must never be used here.
const PUBLISHABLE_RE = /sb_publishable_[A-Za-z0-9_-]{20,}/g;
const PLACEHOLDER = /(your|example|xxx|placeholder|changeme|<|\.\.\.)/i;

function decodeJwtPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// Pull a project URL + anon key out of the repo. Lovable/Bolt/v0 apps hardcode
// both (VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY), so for most of our target
// repos the user has nothing to paste.
export function harvestCredentials(files) {
  let url = null;
  let anonKey = null;

  for (const f of files) {
    if (!url) {
      for (const m of f.content.matchAll(URL_RE)) {
        const parsed = parseProjectUrl(`https://${m[1]}.supabase.co`);
        if (parsed.origin) {
          url = parsed.origin;
          break;
        }
      }
    }
    if (!anonKey) {
      // A JWT whose role claim is "anon" is definitively the public key. This
      // also filters out .env.example placeholders for free: they don't decode.
      for (const m of f.content.matchAll(JWT_RE)) {
        const payload = decodeJwtPayload(m[0]);
        if (payload && payload.role === "anon") {
          anonKey = m[0];
          break;
        }
      }
    }
    if (!anonKey) {
      for (const m of f.content.matchAll(PUBLISHABLE_RE)) {
        if (!PLACEHOLDER.test(m[0])) {
          anonKey = m[0];
          break;
        }
      }
    }
    if (url && anonKey) break;
  }

  return { url, anonKey };
}

// Refuse anything that isn't a public key. A user pasting a service_role key
// would hand us total database access — exactly what this design avoids.
export function validateAnonKey(key) {
  const k = String(key || "").trim();
  if (!k) return { error: "Paste your Supabase anon (public) key." };
  if (k.startsWith("sb_secret_")) {
    return { error: "That's a secret key. Use the anon/publishable key — the one that's safe to ship in your app." };
  }
  if (k.startsWith("sb_publishable_")) return { key: k };
  const payload = decodeJwtPayload(k);
  if (!payload) return { error: "That doesn't look like a Supabase anon key." };
  if (payload.role === "service_role") {
    return {
      error:
        "That's your service_role key. Never paste it anywhere — it bypasses all your security rules. Use the anon (public) key instead, and rotate the service_role key if you've shared it.",
    };
  }
  if (payload.role !== "anon") return { error: "That key isn't an anon key." };
  return { key: k };
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

async function req(url, { method = "GET", headers = {}, deadline }) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new Error("time budget exhausted");
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), Math.min(REQUEST_TIMEOUT_MS, remaining));
  try {
    return await fetch(url, { method, headers, signal: ac.signal, redirect: "error" });
  } finally {
    clearTimeout(timer);
  }
}

function authHeaders(key) {
  return { apikey: key, authorization: `Bearer ${key}` };
}

// PostgREST publishes an OpenAPI description of everything it exposes. This is
// metadata (table and column names), not data.
async function listTables(origin, key, deadline) {
  const res = await req(`${origin}/rest/v1/`, { headers: { ...authHeaders(key), accept: "application/openapi+json" }, deadline });
  if (!res.ok) throw new Error(`the API returned HTTP ${res.status} for its schema`);
  const spec = await res.json();
  const defs = spec?.definitions || spec?.components?.schemas || {};
  const out = [];
  for (const [name, def] of Object.entries(defs)) {
    if (!def || typeof def !== "object") continue;
    const columns = Object.keys(def.properties || {});
    if (!columns.length) continue;
    out.push({ name, columns });
  }
  return out;
}

// Prove readability without reading anything: HEAD + count returns the row
// total in a header and no body at all.
async function countRows(origin, key, table, deadline) {
  const res = await req(`${origin}/rest/v1/${encodeURIComponent(table)}?select=*`, {
    method: "HEAD",
    headers: { ...authHeaders(key), prefer: "count=exact", range: "0-0" },
    deadline,
  });
  if (res.status === 401 || res.status === 403) return { blocked: true, rows: 0 };
  if (!res.ok && res.status !== 206) return { blocked: true, rows: 0, status: res.status };
  const range = res.headers.get("content-range") || "";
  const m = range.match(/\/(\d+)$/);
  return { blocked: false, rows: m ? Number(m[1]) : 0 };
}

async function mapLimited(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try {
        out[idx] = await fn(items[idx]);
      } catch {
        out[idx] = null;
      }
    }
  });
  await Promise.all(workers);
  return out;
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

// Columns that make an exposed table a breach rather than a leak.
const STRONG_PII = /^(email|email_address|phone|phone_number|mobile|password|password_hash|encrypted_password|token|access_token|refresh_token|api_key|secret|ssn|social_security(_number)?|dob|date_of_birth|birth_?date|credit_card|card_number|cvv|iban|account_number|address|street(_address)?|postal_code|zip(_code)?|stripe_customer_id|stripe_subscription_id|passport|license_number)$/i;

// Personal, but a step down from the list above.
const WEAK_PII = /^(full_name|first_name|last_name|display_name|username|ip_address|last_ip|latitude|longitude|user_id|owner_id|auth_id)$/i;

// Tables whose whole point is to be world-readable. Only used when nothing
// sensitive was found: a "reviews" table holding emails is still critical.
const PUBLIC_BY_DESIGN =
  /^(products?|posts?|blog_posts?|articles?|categor(y|ies)|pages?|tags?|faqs?|features?|plans?|pricing|testimonials?|menu(_items)?|services?|team(_members)?|locations?|stores?|events?|announcements?)$/i;

function classify(table) {
  const strong = table.columns.filter((c) => STRONG_PII.test(c));
  const weak = table.columns.filter((c) => WEAK_PII.test(c));
  if (strong.length) return { severity: "critical", why: strong };
  if (weak.length) return { severity: "high", why: weak };
  if (PUBLIC_BY_DESIGN.test(table.name)) return { severity: "info", why: [] };
  return { severity: "medium", why: [] };
}

// ---------------------------------------------------------------------------
// Entry point. Never throws: returns { findings, status, error?, ... }.
// ---------------------------------------------------------------------------

export async function checkSupabaseLive({ url, anonKey, log = () => {} }) {
  const parsed = parseProjectUrl(url);
  if (parsed.error) return { findings: [], status: "error", error: parsed.error };
  const keyCheck = validateAnonKey(anonKey);
  if (keyCheck.error) return { findings: [], status: "error", error: keyCheck.error };

  const deadline = Date.now() + TOTAL_BUDGET_MS;
  const origin = parsed.origin;

  let tables;
  try {
    tables = await listTables(origin, keyCheck.key, deadline);
  } catch (e) {
    const msg = e.name === "AbortError" ? "the project did not respond in time" : e.message;
    log(`supabase: could not read the API schema (${msg})`);
    return { findings: [], status: "error", error: `Could not reach the Supabase project: ${msg}` };
  }

  const truncated = tables.length > MAX_TABLES;
  const probing = tables.slice(0, MAX_TABLES);
  log(`supabase: ${tables.length} table(s) exposed by the API, probing ${probing.length}`);

  const results = await mapLimited(probing, PROBE_CONCURRENCY, async (t) => {
    const { blocked, rows } = await countRows(origin, keyCheck.key, t.name, deadline);
    return { ...t, blocked, rows };
  });

  // A table returning 0 rows is either empty or locked down — we cannot tell
  // which from outside, and guessing would invent findings. Only a table that
  // actually hands us rows is proof of exposure.
  const exposed = results.filter((r) => r && !r.blocked && r.rows > 0);
  log(`supabase: ${exposed.length} table(s) readable by anyone`);

  const findings = buildFindings({ exposed, scanned: probing.length, total: tables.length, truncated });
  return {
    findings,
    status: "ran",
    ref: parsed.ref,
    tablesExposedToApi: tables.length,
    tablesProbed: probing.length,
    tablesReadable: exposed.length,
  };
}

function buildFindings({ exposed, scanned, total, truncated }) {
  const findings = [];
  if (!exposed.length) {
    findings.push({
      severity: "info",
      title: "Live database check: no table returned data to an anonymous request",
      file: null,
      line: null,
      detail:
        `We asked your live Supabase project for data using only the public key from your app, the same way an attacker would, across ${scanned} table${scanned === 1 ? "" : "s"}. ` +
        `Nothing came back. That means your Row Level Security policies are doing their job for reading, which is the single most common way these apps get breached. ` +
        `Two caveats: we only tested reading, not writing or deleting, and a table that is simply empty looks the same from outside as one that is locked down.`,
      fix: "Nothing to do. Re-run this check after you add new tables, because a new table has RLS disabled until you turn it on.",
      source: "supabase",
    });
    return findings;
  }

  const bySev = { critical: [], high: [], medium: [], info: [] };
  for (const t of exposed) bySev[classify(t).severity].push(t);

  const describe = (t) => {
    const { why } = classify(t);
    const cols = why.length ? why.slice(0, 6).join(", ") : t.columns.slice(0, 6).join(", ");
    return `• ${t.name} — ${t.rows.toLocaleString("en-US")} row${t.rows === 1 ? "" : "s"} readable, columns include ${cols}`;
  };

  if (bySev.critical.length) {
    findings.push({
      severity: "critical",
      title: `${bySev.critical.length} database table${bySev.critical.length === 1 ? "" : "s"} with personal data readable by anyone`,
      file: null,
      line: null,
      detail:
        `We read these tables from your live database using only the public key that ships inside your app's JavaScript. Anyone who opens your site can do exactly the same:\n\n` +
        bySev.critical.map(describe).join("\n") +
        `\n\nWe deliberately did not fetch any actual rows, only the count and the column names, so no one's personal data passed through VibeGuard. An attacker would not be so polite. This is the failure behind essentially every "my AI-built app leaked its users" story.`,
      fix:
        "In the Supabase dashboard go to Authentication > Policies, and for each table above turn on Row Level Security, then add a policy so people only reach their own rows — typically `auth.uid() = user_id`. Turning RLS on with no policy blocks everyone, which is safe but breaks the app, so add the policy in the same sitting. Then re-run this scan and confirm the tables stop returning rows.",
      source: "supabase",
    });
  }

  if (bySev.high.length) {
    findings.push({
      severity: "high",
      title: `${bySev.high.length} database table${bySev.high.length === 1 ? "" : "s"} readable by anyone`,
      file: null,
      line: null,
      detail:
        `These tables hand their contents to anonymous visitors using the public key from your app:\n\n` +
        bySev.high.map(describe).join("\n") +
        `\n\nThey don't obviously hold contact details or credentials, but they do link records to people, which is enough to map out who your users are and what they did.`,
      fix: "Enable Row Level Security on each table in Supabase (Authentication > Policies) and add a policy scoping rows to their owner. If a table really is meant to be public, leave it and ignore this finding.",
      source: "supabase",
    });
  }

  if (bySev.medium.length) {
    findings.push({
      severity: "medium",
      title: `${bySev.medium.length} database table${bySev.medium.length === 1 ? "" : "s"} open to anonymous reads`,
      file: null,
      line: null,
      detail:
        `Readable by anyone with your app's public key:\n\n` +
        bySev.medium.map(describe).join("\n") +
        `\n\nNothing here looks like personal data, so this may well be intentional. Worth a look to confirm it is.`,
      fix: "If these tables aren't meant to be public, enable Row Level Security on them in Supabase and add an appropriate policy. If they are, no action needed.",
      source: "supabase",
    });
  }

  if (bySev.info.length) {
    findings.push({
      severity: "info",
      title: `${bySev.info.length} public-looking table${bySev.info.length === 1 ? "" : "s"} readable by anyone (probably intended)`,
      file: null,
      line: null,
      detail:
        `These are readable anonymously, but their names and columns suggest that's the point:\n\n` +
        bySev.info.map(describe).join("\n") +
        `\n\nListed so you can confirm rather than assume.`,
      fix: "No action needed if these are meant to be public content. If any of them isn't, enable Row Level Security on it in Supabase.",
      source: "supabase",
    });
  }

  if (truncated) {
    findings.push({
      severity: "info",
      title: `Only the first ${scanned} of ${total} tables were checked`,
      file: null,
      line: null,
      detail: `Your project exposes ${total} tables through its API and we checked ${scanned} of them to keep the scan quick. The unchecked ones may also be readable.`,
      fix: "Review the remaining tables in Supabase (Authentication > Policies) and confirm each has Row Level Security enabled.",
      source: "supabase",
    });
  }

  return findings;
}
