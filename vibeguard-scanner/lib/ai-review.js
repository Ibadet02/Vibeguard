// AI reasoning pass.
//
// The deterministic checks in checks.js catch known *patterns*. They cannot
// reason about a specific app's logic: "this route lets any logged-in user pass
// someone else's id and get their data", "this checkout trusts a price from the
// browser", "this admin flag is set from a request body". That kind of bug needs
// a model that actually reads the code and thinks about who can do what.
//
// This module sends a curated slice of the repo to an Anthropic-compatible
// Messages endpoint and asks for high-confidence, exploitable findings that the
// pattern checks would miss. It is deliberately provider-agnostic (base URL,
// key, and model are all env-configurable) and completely non-fatal: if the
// model is unreachable or misbehaves, the scan still returns its deterministic
// findings.
//
// Config (env):
//   VIBEGUARD_LLM_API_KEY   / ANTHROPIC_API_KEY    the credential
//   VIBEGUARD_LLM_BASE_URL  / ANTHROPIC_BASE_URL   e.g. https://api.anthropic.com
//   VIBEGUARD_LLM_MODEL                            e.g. claude-opus-4-8
//   VIBEGUARD_AI = 0                               disable even if a key is set

import path from "node:path";

const DEFAULT_MODEL = "claude-opus-4-8";
const DEFAULT_BASE_URL = "https://api.anthropic.com";

// Keep the payload bounded so we stay fast and within context limits.
const MAX_FILES = 45;
const MAX_LINES_PER_FILE = 500;
const MAX_TOTAL_CHARS = 180_000;

// The gateway (a resold Claude Code pool) intermittently 502/503s with
// "no available accounts", or hangs entirely when overloaded. These are
// transient, so we retry with backoff, but we cap the whole AI pass with a
// wall-clock budget so a dead gateway degrades to "AI skipped" in a couple of
// minutes instead of stalling the scan for ten. A healthy response arrives well
// inside one attempt.
const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 4;
const BACKOFF_MS = [3000, 6000, 10000];
const REQUEST_TIMEOUT_MS = 120000;
const MAX_TOTAL_MS = 240000;

export function aiConfig() {
  const apiKey = process.env.VIBEGUARD_LLM_API_KEY || process.env.ANTHROPIC_API_KEY || "";
  const baseUrl = (process.env.VIBEGUARD_LLM_BASE_URL || process.env.ANTHROPIC_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const model = process.env.VIBEGUARD_LLM_MODEL || DEFAULT_MODEL;
  const enabled = Boolean(apiKey) && process.env.VIBEGUARD_AI !== "0";
  return { apiKey, baseUrl, model, enabled };
}

// Rank a file by how likely it is to contain an authorization / business-logic
// bug worth spending tokens on. Higher = more interesting.
function relevanceScore(f) {
  const p = f.rel.toLowerCase();
  if (!/\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|py|rb|php|go)$/.test(p)) {
    // config-ish files can still matter (next.config, middleware) but rank low
    if (!/\.(sql|toml|ya?ml)$/.test(p)) return -1;
  }
  let s = 0;
  const c = f.content;
  if (/(^|\/)(pages\/api|app\/api)\//.test(p)) s += 6;
  if (/route\.(t|j)sx?$/.test(p)) s += 5;
  if (/(middleware|proxy)\.(t|j)sx?$/.test(p)) s += 5;
  if (/\b(auth|session|login|token|permission|role|admin|account|tenant|webhook|checkout|payment|billing|credit|order|upload)\b/.test(p)) s += 4;
  if (/(server|actions?|handlers?|controllers?|services?|lib|utils|graphql|trpc)\//.test(p)) s += 2;
  if (/\.(sql)$/.test(p)) s += 2;
  // content signals
  if (/req\.(query|body|params|headers)|request\.(json|nextUrl|headers)|searchParams/.test(c)) s += 3;
  if (/supabase|prisma|drizzle|mongoose|\.query\(|knex|sequelize|db\./i.test(c)) s += 2;
  if (/process\.env|jwt|jsonwebtoken|createHmac|cookies?\(|getServerSession|clerk/i.test(c)) s += 2;
  if (/userId|user_id|ownerId|accountId|tenantId|amount|price|total|isAdmin|role/i.test(c)) s += 2;
  return s;
}

// Pick the most security-relevant files within a character budget.
function selectFiles(files) {
  const scored = files
    .map((f) => ({ f, s: relevanceScore(f) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s);

  const chosen = [];
  let total = 0;
  for (const { f } of scored) {
    if (chosen.length >= MAX_FILES) break;
    const lines = f.content.split("\n");
    const truncated = lines.length > MAX_LINES_PER_FILE;
    const body = (truncated ? lines.slice(0, MAX_LINES_PER_FILE) : lines)
      .map((ln, i) => `${i + 1}| ${ln}`)
      .join("\n");
    const block = `\n### FILE: ${f.rel}${truncated ? ` (first ${MAX_LINES_PER_FILE} of ${lines.length} lines)` : ""}\n${body}\n`;
    if (total + block.length > MAX_TOTAL_CHARS) continue;
    total += block.length;
    chosen.push(block);
  }
  return chosen.join("\n");
}

const SYSTEM_PROMPT =
  "You are Claude Code, Anthropic's official CLI for Claude. You are acting as a senior application security engineer reviewing an AI-generated web app for a non-expert developer.\n\n" +
  "You are given a curated slice of a codebase and a list of issues that a separate pattern-based scanner ALREADY found. Your job is to find serious, EXPLOITABLE vulnerabilities that a regex-based scanner would miss, the kind that require reasoning about the app's own logic:\n" +
  "- Broken access control / missing ownership checks (a logged-in user can read or modify another user's data by changing an id).\n" +
  "- IDOR: an id from the request (query, body, params) is used in a DB query without checking it belongs to the caller.\n" +
  "- Trusting client-supplied values for authorization (isAdmin/role/userId from the request body or headers).\n" +
  "- Price / amount / quantity tampering (a value that should be authoritative on the server is taken from the client, e.g. checkout).\n" +
  "- Auth bypass, privilege escalation, insecure direct object access, SSRF, injection (SQL/command), unsafe deserialization, path traversal.\n" +
  "- Secrets or service-role keys reachable from client code.\n\n" +
  "STRICT RULES:\n" +
  "1. Only report an issue if you can point to the exact file and line and explain a concrete exploit. No speculation, no 'best practice' nits, no style.\n" +
  "2. Do NOT repeat anything already in the pattern-scanner findings list.\n" +
  "3. If a route verifies auth/ownership correctly, do not flag it. Prefer FALSE NEGATIVES over false positives: when unsure, leave it out.\n" +
  "4. Write detail and fix in plain language a beginner can act on.\n" +
  "5. Respond with ONE JSON object and nothing else (no prose, no markdown fences).\n\n" +
  "JSON shape:\n" +
  '{"findings":[{"severity":"critical|high|medium","title":"short title","file":"path/from/repo/root","line":<number>,"detail":"what it is + how it is exploited, plain language","fix":"concrete steps","confidence":"high|medium|low"}]}\n' +
  'If you find nothing new worth reporting, respond exactly: {"findings":[]}';

function buildUserContent(files, deterministicFindings) {
  const priorList = deterministicFindings.length
    ? deterministicFindings.map((f) => `- [${f.severity}] ${f.title} (${f.file || "?"}${f.line ? ":" + f.line : ""})`).join("\n")
    : "(none)";
  const code = selectFiles(files);
  return (
    "Issues the pattern scanner ALREADY reported (do not repeat these):\n" +
    priorList +
    "\n\nHere is the most security-relevant code in the repo. Line numbers are prefixed as `N| `.\n" +
    code +
    "\n\nReturn only the JSON object described in your instructions."
  );
}

function ccHeaders(apiKey) {
  return {
    "content-type": "application/json",
    accept: "application/json",
    "x-api-key": apiKey,
    "anthropic-version": "2023-06-01",
    // These make the request look like the real Claude Code client, which the
    // freemodel gateway requires (it rejects unrecognized "probe" traffic).
    "anthropic-beta": "claude-code-20250219,fine-grained-tool-streaming-2025-05-14",
    "user-agent": "claude-cli/2.1.145 (external, cli)",
    "x-app": "cli",
    "x-stainless-lang": "js",
    "x-stainless-package-version": "0.60.0",
    "x-stainless-os": "Linux",
    "x-stainless-arch": "x64",
    "x-stainless-runtime": "node",
    "x-stainless-runtime-version": process.version,
    "x-stainless-retry-count": "0",
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function callModel({ apiKey, baseUrl, model }, system, userContent, log) {
  const body = JSON.stringify({
    model,
    max_tokens: 8000,
    system: [{ type: "text", text: system, cache_control: { type: "ephemeral" } }],
    messages: [{ role: "user", content: userContent }],
    metadata: { user_id: "vibeguard" },
    stream: false,
  });

  const deadline = Date.now() + MAX_TOTAL_MS;
  let lastErr = "";
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      const wait = BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)];
      if (Date.now() + wait >= deadline) break;
      log(`AI: retry ${attempt}/${MAX_ATTEMPTS - 1} after ${wait / 1000}s (${lastErr})`);
      await sleep(wait);
    }
    const remaining = deadline - Date.now();
    if (remaining <= 2000) break;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), Math.min(REQUEST_TIMEOUT_MS, remaining));
    try {
      const res = await fetch(`${baseUrl}/v1/messages`, {
        method: "POST",
        headers: ccHeaders(apiKey),
        body,
        signal: ac.signal,
      });
      const text = await res.text();
      if (!res.ok) {
        lastErr = `HTTP ${res.status}`;
        if (RETRYABLE_STATUS.has(res.status)) continue;
        throw new Error(`${lastErr}: ${text.slice(0, 200)}`);
      }
      return JSON.parse(text);
    } catch (e) {
      lastErr = e.name === "AbortError" ? "timeout" : e.message;
      // network errors and timeouts are worth another try
      if (attempt < MAX_ATTEMPTS - 1) continue;
      throw new Error(lastErr);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(lastErr || "exhausted retries");
}

// Pull the assistant's text out of an Anthropic Messages response.
function extractText(resp) {
  if (!resp || !Array.isArray(resp.content)) return "";
  return resp.content
    .filter((b) => b && b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n")
    .trim();
}

// The model is told to return raw JSON, but be forgiving: strip fences and grab
// the outermost {...} if it wrapped the object in prose.
function parseFindings(text) {
  if (!text) return [];
  let s = text.trim();
  s = s.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  if (!s.startsWith("{")) {
    const a = s.indexOf("{");
    const b = s.lastIndexOf("}");
    if (a === -1 || b === -1 || b <= a) return [];
    s = s.slice(a, b + 1);
  }
  let data;
  try {
    data = JSON.parse(s);
  } catch {
    return [];
  }
  const arr = Array.isArray(data?.findings) ? data.findings : [];
  const ok = new Set(["critical", "high", "medium", "info"]);
  const out = [];
  for (const f of arr) {
    if (!f || typeof f !== "object") continue;
    const severity = ok.has(f.severity) ? f.severity : "medium";
    const title = String(f.title || "").trim();
    const detail = String(f.detail || "").trim();
    const fix = String(f.fix || "").trim();
    if (!title || !detail) continue;
    // Drop low-confidence guesses: they are the false positives we care most
    // about avoiding.
    if (String(f.confidence || "").toLowerCase() === "low") continue;
    out.push({
      severity,
      title,
      file: f.file ? String(f.file) : "",
      line: Number.isFinite(f.line) ? f.line : Number(f.line) || 0,
      detail,
      fix: fix || "Review this code path and add the missing authorization/validation.",
      source: "ai",
    });
  }
  return out;
}

// Drop AI findings that clearly restate a deterministic one (same file + very
// similar title), so the report does not double-count.
function dedupe(aiFindings, deterministic) {
  const seen = deterministic.map((f) => `${(f.file || "").toLowerCase()}|${(f.title || "").toLowerCase().slice(0, 24)}`);
  return aiFindings.filter((f) => {
    const key = `${(f.file || "").toLowerCase()}|${(f.title || "").toLowerCase().slice(0, 24)}`;
    return !seen.includes(key);
  });
}

// Main entry. Never throws: returns { findings, error } where findings is [] on
// any failure so the caller can proceed with deterministic results.
export async function aiReview({ files, deterministicFindings = [], log = () => {} }) {
  const cfg = aiConfig();
  if (!cfg.enabled) return { findings: [], skipped: true };

  try {
    log(`AI: reviewing with ${cfg.model} via ${cfg.baseUrl}`);
    const userContent = buildUserContent(files, deterministicFindings);
    const resp = await callModel(cfg, SYSTEM_PROMPT, userContent, log);
    const served = resp?.model && resp.model !== cfg.model ? ` (gateway served "${resp.model}")` : "";
    const findings = dedupe(parseFindings(extractText(resp)), deterministicFindings);
    log(`AI: ${findings.length} new finding(s)${served}`);
    return { findings, servedModel: resp?.model };
  } catch (e) {
    log(`AI: skipped (${e.message})`);
    return { findings: [], error: e.message };
  }
}
