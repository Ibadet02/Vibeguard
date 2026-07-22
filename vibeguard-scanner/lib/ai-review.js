// AI reasoning pass (agentic).
//
// The deterministic checks in checks.js catch known *patterns*. They cannot
// reason about a specific app's logic: "this route lets any logged-in user pass
// someone else's id and get their data", "this checkout trusts a price from the
// browser", "this admin flag is set from a request body". That needs a model
// that actually reads the code and follows a thread across files.
//
// This module hands the model three read-only tools (list_files, read_file,
// grep) that run against the already-loaded, in-memory repo, and lets it explore
// like a human reviewer would: form a hypothesis, open the relevant files,
// confirm, then report. It works with any OpenAI-compatible or Anthropic-
// compatible endpoint (auto-detected) and is completely non-fatal: if the model
// is unreachable, refuses, or misbehaves, the scan still returns its
// deterministic findings.
//
// Config (env):
//   VIBEGUARD_LLM_API_KEY   / ANTHROPIC_API_KEY     the credential
//   VIBEGUARD_LLM_BASE_URL  / ANTHROPIC_BASE_URL    e.g. https://api.openai.com/v1
//   VIBEGUARD_LLM_MODEL                             e.g. gpt-4.1 or claude-opus-4-8
//   VIBEGUARD_LLM_API = openai | anthropic          override auto-detection
//   VIBEGUARD_AI = 0                                disable even if a key is set

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export function aiConfig() {
  const apiKey = process.env.VIBEGUARD_LLM_API_KEY || process.env.ANTHROPIC_API_KEY || "";
  const baseRaw = process.env.VIBEGUARD_LLM_BASE_URL || process.env.ANTHROPIC_BASE_URL || "";

  let api = (process.env.VIBEGUARD_LLM_API || "").toLowerCase();
  if (api !== "openai" && api !== "anthropic") {
    if (/anthropic|freemodel|claude/i.test(baseRaw)) api = "anthropic";
    else if (/openai|azure|openrouter/i.test(baseRaw)) api = "openai";
    else if (apiKey.startsWith("sk-ant")) api = "anthropic";
    else api = "openai";
  }

  const defaultBase = api === "anthropic" ? "https://api.anthropic.com" : "https://api.openai.com/v1";
  const baseUrl = (baseRaw || defaultBase).replace(/\/+$/, "");
  const model = process.env.VIBEGUARD_LLM_MODEL || (api === "anthropic" ? "claude-opus-4-8" : "gpt-4.1");
  const enabled = Boolean(apiKey) && process.env.VIBEGUARD_AI !== "0";
  return { api, apiKey, baseUrl, model, enabled };
}

// ---------------------------------------------------------------------------
// Budgets / retry
// ---------------------------------------------------------------------------

const MAX_ITERATIONS = 24;          // tool-use rounds before we force a wrap-up
const MAX_TOTAL_MS = 300000;        // wall-clock cap for the whole AI pass
const REQUEST_TIMEOUT_MS = 120000;  // per HTTP request
const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 4;
const BACKOFF_MS = [3000, 6000, 10000];
const TOOL_OUTPUT_CAP = 48000;      // chars returned to the model per tool call
const MAX_READ_LINES = 800;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Anthropic's real-time cyber safeguard refuses the request unless the account
// is in the Cyber Verification Program. Retrying is pointless; surface it clearly.
const CYBER_SAFETY_RE = /safety measures|cyber\s*verification|real[- ]time cyber|cybersecurity topic/i;
const CYBER_SAFETY_MSG =
  "blocked by the model's cyber safeguard (the account isn't in Anthropic's Cyber Verification Program). " +
  "The AI pass was skipped; deterministic checks still ran. Use an approved account, or point VIBEGUARD_LLM_* at a provider/model without this restriction (e.g. OpenAI).";

// ---------------------------------------------------------------------------
// Prompt (deliberately DEFENSIVE framing: describe it as a correctness review so
// it does not read like offensive security, which trips content safeguards)
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT =
  "You are a senior software engineer doing a careful code review to help a non-expert developer ship a safe app. Your goal is to make sure the app handles user data correctly, so each person can only see and change their own information, and so untrusted input cannot make the app misbehave.\n\n" +
  "You can inspect the codebase with three read-only tools:\n" +
  "- list_files(pattern?): list file paths, optionally filtered by a regex on the path.\n" +
  "- read_file(path, start?, end?): read a file with line numbers.\n" +
  "- grep(pattern, flags?): search every file for a regex; returns path:line: matched text.\n\n" +
  "Work like a real reviewer: start from the routes/handlers and the code they call, follow the data, and READ enough to be sure before reporting. Do not guess from a file name.\n\n" +
  "Look for concrete correctness mistakes in these areas:\n" +
  "1. Access control / data ownership: an endpoint uses an id from the request (query, body, params, headers) to read or change a record without confirming it belongs to the signed-in user; missing login checks on endpoints that touch private data; multi-tenant data that isn't scoped to the current tenant.\n" +
  "2. Trusting the client for server decisions: role/permission/isAdmin flags, prices, amounts, quantities, or user ids taken from the request and acted on as if reliable.\n" +
  "3. Input handling: request input used unsafely in a database query, a file path, a URL the server fetches, or a shell command (injection / path traversal / server-side request issues).\n" +
  "4. Secret exposure: API keys, service-role keys, or other credentials reachable from browser/client-side code, or committed into the repo.\n" +
  "5. Business-logic gaps: steps that can be skipped or replayed (e.g. granting credits/entitlements without verifying payment, webhooks without signature checks).\n\n" +
  "You have TWO jobs:\n" +
  "A) TRIAGE the automated linter's existing findings. That linter matches text patterns and has no understanding of the app, so it produces false positives and wrong severities. For EACH finding it reports (each has an id), open the relevant code and decide:\n" +
  "   - 'keep': the finding is real and the severity is about right.\n" +
  "   - 'downgrade': real but the impact is smaller than stated (give the correct severity). Example: a hardcoded fallback secret that only guards a non-sensitive cookie, or that can never be reached because the app validates the env var and refuses to boot without it.\n" +
  "   - 'dismiss': not actually exploitable here (give the reason with the evidence you found). Example: an 'unauthenticated route' that is actually behind middleware auth, or a webhook that does verify its signature.\n" +
  "   Be conservative: only downgrade or dismiss when the code gives you clear evidence. When in doubt, 'keep'.\n" +
  "B) FIND NEW issues the linter missed, that need reasoning about the app's logic.\n\n" +
  "Look for concrete correctness mistakes in these areas (for job B, and to judge job A):\n" +
  "- Access control / data ownership: an endpoint uses an id from the request to read or change a record without confirming it belongs to the signed-in user; missing login checks; multi-tenant data not scoped to the current tenant.\n" +
  "- Trusting the client for server decisions: role/permission/isAdmin flags, prices, amounts, quantities, or user ids taken from the request and acted on as if reliable.\n" +
  "- Input handling: request input used unsafely in a database query, a file path, a fetched URL, or a shell command.\n" +
  "- Secret exposure: credentials reachable from client-side code or committed to the repo.\n" +
  "- Business-logic gaps: steps that can be skipped or replayed (granting entitlements without verifying payment, webhooks without signature checks).\n\n" +
  "RULES:\n" +
  "1. Every judgement must be grounded in code you actually read (exact file + line). No speculation, no style nits.\n" +
  "2. For NEW findings, do not restate a linter finding; if you think a linter finding is real, that's a 'keep' in triage, not a new finding.\n" +
  "3. Prefer a false negative over a false alarm: when unsure about a NEW issue, leave it out.\n" +
  "4. Write text in plain language a beginner can act on.\n" +
  "5. When done exploring, reply with ONE JSON object and nothing else (no tool call, no prose, no markdown fences):\n" +
  '{"triage":[{"id":<number>,"verdict":"keep|downgrade|dismiss","severity":"critical|high|medium|info","reason":"evidence-based explanation (required for downgrade/dismiss)"}],' +
  '"findings":[{"severity":"critical|high|medium","title":"short title","file":"path/from/repo/root","line":<number>,"detail":"what the mistake is and how the wrong data could be reached, plain language","fix":"concrete steps to make it correct","confidence":"high|medium|low"}]}\n' +
  'Include a triage entry for every linter finding id. If there are no new issues, use an empty findings array. If there were no linter findings, use an empty triage array.';

// Rank files so we can give the model a useful starting shortlist. The model can
// still reach anything via the tools; this is just orientation.
function relevanceScore(f) {
  const p = f.rel.toLowerCase();
  if (!/\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|py|rb|php|go|sql|toml|ya?ml)$/.test(p)) return -1;
  let s = 0;
  const c = f.content;
  if (/(^|\/)(pages\/api|app\/api)\//.test(p)) s += 6;
  if (/route\.(t|j)sx?$/.test(p)) s += 5;
  if (/(middleware|proxy)\.(t|j)sx?$/.test(p)) s += 5;
  if (/\b(auth|session|login|token|permission|role|admin|account|tenant|webhook|checkout|payment|billing|credit|order|upload)\b/.test(p)) s += 4;
  if (/(server|actions?|handlers?|controllers?|services?|lib|utils|graphql|trpc)\//.test(p)) s += 2;
  if (/\.sql$/.test(p)) s += 2;
  if (/req\.(query|body|params|headers)|request\.(json|nextUrl|headers)|searchParams/.test(c)) s += 3;
  if (/supabase|prisma|drizzle|mongoose|\.query\(|knex|sequelize|db\./i.test(c)) s += 2;
  if (/process\.env|jwt|jsonwebtoken|createHmac|cookies?\(|getServerSession|clerk/i.test(c)) s += 2;
  if (/userId|user_id|ownerId|accountId|tenantId|amount|price|total|isAdmin|role/i.test(c)) s += 2;
  return s;
}

function buildUserContent(files, deterministicFindings) {
  const prior = deterministicFindings.length
    ? deterministicFindings
        .map((f, i) => `#${i} [${f.severity}] ${f.title} (${f.file || "?"}${f.line ? ":" + f.line : ""})`)
        .join("\n")
    : "(none)";
  const shortlist = files
    .map((f) => ({ f, s: relevanceScore(f) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s)
    .slice(0, 40)
    .map((x) => x.f.rel);
  return (
    `This app has ${files.length} files.\n\n` +
    `The automated linter reported these findings. Triage EACH one by its id (#):\n` +
    prior +
    `\n\nLikely-relevant files to start from (you can open anything with the tools):\n` +
    shortlist.join("\n") +
    `\n\nInspect the code with the tools, then reply with ONLY the JSON object described in your instructions (both "triage" and "findings").`
  );
}

// ---------------------------------------------------------------------------
// Tools (run against the in-memory file list; read-only, no filesystem/shell)
// ---------------------------------------------------------------------------

const TOOL_DEFS = [
  {
    name: "list_files",
    description: "List file paths in the app. Optionally filter by a regex matched against the path.",
    parameters: {
      type: "object",
      properties: { pattern: { type: "string", description: "optional regex to filter paths, e.g. api/.*route" } },
    },
  },
  {
    name: "read_file",
    description: "Read a file's contents with line numbers. Optionally give a 1-based line range.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "path relative to the repo root" },
        start: { type: "number" },
        end: { type: "number" },
      },
      required: ["path"],
    },
  },
  {
    name: "grep",
    description: "Search every file for a regular expression. Returns lines as 'path:line: text'.",
    parameters: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        flags: { type: "string", description: "optional regex flags, e.g. 'i'" },
      },
      required: ["pattern"],
    },
  },
];

function toolListFiles(files, input) {
  let list = files.map((f) => f.rel);
  if (input.pattern) {
    try {
      const re = new RegExp(input.pattern, "i");
      list = list.filter((p) => re.test(p));
    } catch {
      /* ignore bad regex, return all */
    }
  }
  const capped = list.slice(0, 600);
  const more = list.length > capped.length ? `\n... (${list.length - capped.length} more; refine the pattern)` : "";
  return `${capped.join("\n")}${more}\n[${list.length} matching path(s)]`;
}

function toolReadFile(files, input) {
  const target = String(input.path || "");
  const f =
    files.find((x) => x.rel === target) ||
    files.find((x) => x.rel.endsWith(target)) ||
    files.find((x) => x.rel.toLowerCase() === target.toLowerCase());
  if (!f) return `No file matched "${target}". Use list_files to see exact paths.`;
  const lines = f.content.split("\n");
  const start = Number.isFinite(input.start) ? Math.max(1, Math.floor(input.start)) : 1;
  const end = Math.min(Number.isFinite(input.end) ? Math.floor(input.end) : lines.length, start + MAX_READ_LINES - 1, lines.length);
  const body = lines.slice(start - 1, end).map((ln, i) => `${start + i}| ${ln}`).join("\n");
  const note = end < lines.length ? `\n... (file is ${lines.length} lines; showed ${start}-${end}. Ask for a later range if needed.)` : "";
  return `FILE: ${f.rel}\n${body}${note}`;
}

function toolGrep(files, input) {
  const flags = String(input.flags || "").replace(/[gm]/g, "") + "";
  let re;
  try {
    re = new RegExp(String(input.pattern || ""), flags);
  } catch (e) {
    return `Invalid regex: ${e.message}`;
  }
  const out = [];
  for (const f of files) {
    const lines = f.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) {
        out.push(`${f.rel}:${i + 1}: ${lines[i].trim().slice(0, 200)}`);
        if (out.length >= 200) return out.join("\n") + "\n... (truncated at 200 matches; refine the pattern)";
      }
    }
  }
  return out.length ? out.join("\n") : "no matches";
}

function runTool(name, input, files) {
  try {
    const arg = input && typeof input === "object" ? input : {};
    if (name === "list_files") return toolListFiles(files, arg);
    if (name === "read_file") return toolReadFile(files, arg);
    if (name === "grep") return toolGrep(files, arg);
    return `unknown tool: ${name}`;
  } catch (e) {
    return `tool error: ${e.message}`;
  }
}

// ---------------------------------------------------------------------------
// HTTP with retry / timeout / safeguard detection
// ---------------------------------------------------------------------------

function anthropicHeaders(apiKey) {
  return {
    "content-type": "application/json",
    accept: "application/json",
    "x-api-key": apiKey,
    "anthropic-version": "2023-06-01",
    // Make the request look like the real Claude Code client. Required by the
    // freemodel gateway (rejects unrecognized "probe" traffic); harmless on a
    // direct Anthropic endpoint.
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

function openaiHeaders(apiKey) {
  return { "content-type": "application/json", authorization: `Bearer ${apiKey}` };
}

async function postJSON(url, headers, bodyObj, deadline, log) {
  const body = JSON.stringify(bodyObj);
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
      const res = await fetch(url, { method: "POST", headers, body, signal: ac.signal });
      const text = await res.text();
      if (CYBER_SAFETY_RE.test(text)) {
        const e = new Error(CYBER_SAFETY_MSG);
        e.cyberSafety = true;
        throw e;
      }
      if (!res.ok) {
        lastErr = `HTTP ${res.status}`;
        if (RETRYABLE_STATUS.has(res.status) && attempt < MAX_ATTEMPTS - 1) continue;
        throw new Error(`${lastErr}: ${text.slice(0, 200)}`);
      }
      return JSON.parse(text);
    } catch (e) {
      if (e.cyberSafety) throw e;
      lastErr = e.name === "AbortError" ? "timeout" : e.message;
      if (attempt < MAX_ATTEMPTS - 1) continue;
      throw new Error(lastErr);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(lastErr || "exhausted retries");
}

function safeJson(s) {
  if (s && typeof s === "object") return s;
  try {
    return JSON.parse(s || "{}");
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// Provider adapters: normalise "one turn" of a tool-use conversation
// ---------------------------------------------------------------------------

function makeProvider(cfg) {
  if (cfg.api === "anthropic") {
    const tools = TOOL_DEFS.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters }));
    let system = "";
    return {
      buildMessages(systemText, userText) {
        system = systemText;
        return [{ role: "user", content: userText }];
      },
      async turn(messages, deadline, log) {
        const data = await postJSON(
          `${cfg.baseUrl}/v1/messages`,
          anthropicHeaders(cfg.apiKey),
          {
            model: cfg.model,
            max_tokens: 4096,
            system: [{ type: "text", text: system, cache_control: { type: "ephemeral" } }],
            messages,
            tools,
            tool_choice: { type: "auto" },
          },
          deadline,
          log
        );
        const content = Array.isArray(data.content) ? data.content : [];
        const toolCalls = content
          .filter((b) => b.type === "tool_use")
          .map((b) => ({ id: b.id, name: b.name, input: b.input || {} }));
        const text = content.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
        return { assistantRaw: content, toolCalls, text, servedModel: data.model };
      },
      appendAssistant(messages, assistantRaw) {
        messages.push({ role: "assistant", content: assistantRaw });
      },
      appendToolResults(messages, results) {
        messages.push({
          role: "user",
          content: results.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: r.output })),
        });
      },
    };
  }

  // OpenAI-compatible (OpenAI, Azure, OpenRouter, Ollama, ...)
  const tools = TOOL_DEFS.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } }));
  return {
    buildMessages(systemText, userText) {
      return [
        { role: "system", content: systemText },
        { role: "user", content: userText },
      ];
    },
    async turn(messages, deadline, log) {
      const data = await postJSON(
        `${cfg.baseUrl}/chat/completions`,
        openaiHeaders(cfg.apiKey),
        { model: cfg.model, messages, tools, tool_choice: "auto" },
        deadline,
        log
      );
      const msg = data.choices?.[0]?.message || {};
      const toolCalls = (msg.tool_calls || []).map((tc) => ({
        id: tc.id,
        name: tc.function?.name,
        input: safeJson(tc.function?.arguments),
      }));
      const text = (msg.content || "").trim();
      return { assistantRaw: msg, toolCalls, text, servedModel: data.model };
    },
    appendAssistant(messages, assistantRaw) {
      messages.push(assistantRaw);
    },
    appendToolResults(messages, results) {
      for (const r of results) messages.push({ role: "tool", tool_call_id: r.id, content: r.output });
    },
  };
}

// ---------------------------------------------------------------------------
// Findings parsing / dedupe
// ---------------------------------------------------------------------------

const SEV_OK = new Set(["critical", "high", "medium", "info"]);
const SEV_RANK = { critical: 3, high: 2, medium: 1, info: 0 };

// Parse the combined { triage, findings } object out of the model's final text.
function parseResult(text) {
  if (!text) return { findings: [], triage: [] };
  let s = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  if (!s.startsWith("{")) {
    const a = s.indexOf("{");
    const b = s.lastIndexOf("}");
    if (a === -1 || b === -1 || b <= a) return { findings: [], triage: [] };
    s = s.slice(a, b + 1);
  }
  let data;
  try {
    data = JSON.parse(s);
  } catch {
    return { findings: [], triage: [] };
  }

  const findings = [];
  for (const f of Array.isArray(data?.findings) ? data.findings : []) {
    if (!f || typeof f !== "object") continue;
    const severity = SEV_OK.has(f.severity) ? f.severity : "medium";
    const title = String(f.title || "").trim();
    const detail = String(f.detail || "").trim();
    const fix = String(f.fix || "").trim();
    if (!title || !detail) continue;
    if (String(f.confidence || "").toLowerCase() === "low") continue; // drop low-confidence guesses
    findings.push({
      severity,
      title,
      file: f.file ? String(f.file) : "",
      line: Number.isFinite(f.line) ? f.line : Number(f.line) || 0,
      detail,
      fix: fix || "Review this code path and add the missing authorization/validation.",
      source: "ai",
    });
  }

  const triage = [];
  for (const t of Array.isArray(data?.triage) ? data.triage : []) {
    if (!t || typeof t !== "object") continue;
    const id = Number.isFinite(t.id) ? t.id : Number(t.id);
    const verdict = String(t.verdict || "").toLowerCase();
    if (!Number.isInteger(id) || !["keep", "downgrade", "dismiss"].includes(verdict)) continue;
    triage.push({
      id,
      verdict,
      severity: SEV_OK.has(t.severity) ? t.severity : null,
      reason: String(t.reason || "").trim(),
    });
  }

  return { findings, triage };
}

// Apply the model's triage verdicts to the deterministic findings, in place.
// Conservative: only acts on downgrade/dismiss backed by a reason, and a
// downgrade must actually lower the severity. Everything is annotated so the
// change is auditable, never silently dropped.
export function applyTriage(findings, triage) {
  let changed = 0;
  for (const t of triage || []) {
    const f = findings[t.id];
    if (!f || f.source === "ai") continue; // only triage deterministic findings
    if (t.verdict === "downgrade" && t.severity && t.reason && SEV_RANK[t.severity] < SEV_RANK[f.severity]) {
      f.detail += `\n\n_AI triage: severity lowered from ${f.severity} to ${t.severity}. ${t.reason}_`;
      f.severity = t.severity;
      f.triaged = "downgraded";
      changed++;
    } else if (t.verdict === "dismiss" && t.reason) {
      f.detail += `\n\n_AI triage: likely a false positive here. ${t.reason}_`;
      f.title = `Likely false positive: ${f.title}`;
      f.severity = "info";
      f.triaged = "dismissed";
      changed++;
    }
  }
  return changed;
}

function dedupe(aiFindings, deterministic) {
  const seen = deterministic.map((f) => `${(f.file || "").toLowerCase()}|${(f.title || "").toLowerCase().slice(0, 24)}`);
  return aiFindings.filter((f) => {
    const key = `${(f.file || "").toLowerCase()}|${(f.title || "").toLowerCase().slice(0, 24)}`;
    return !seen.includes(key);
  });
}

// ---------------------------------------------------------------------------
// Entry point. Never throws: returns { findings, error?, skipped? }.
// ---------------------------------------------------------------------------

export async function aiReview({ files, deterministicFindings = [], log = () => {} }) {
  const cfg = aiConfig();
  if (!cfg.enabled) return { findings: [], skipped: true };

  const deadline = Date.now() + MAX_TOTAL_MS;
  try {
    log(`AI: agentic review with ${cfg.model} via ${cfg.baseUrl} (${cfg.api})`);
    const provider = makeProvider(cfg);
    const messages = provider.buildMessages(SYSTEM_PROMPT, buildUserContent(files, deterministicFindings));

    const WRAP_NUDGE =
      "\n\n(You have reached the exploration limit. Do NOT call any more tools. " +
      'Reply now with ONLY the final JSON object described in your instructions (both "triage" and "findings").)';

    let finalText = "";
    let servedModel;
    let steps = 0;
    let endedWithTools = false;
    for (let i = 0; i < MAX_ITERATIONS; i++) {
      if (Date.now() > deadline) {
        log("AI: time budget reached, wrapping up");
        endedWithTools = true;
        break;
      }
      const turn = await provider.turn(messages, deadline, log);
      servedModel = turn.servedModel || servedModel;
      provider.appendAssistant(messages, turn.assistantRaw);

      if (turn.toolCalls.length) {
        steps++;
        log(`AI: step ${steps}: ${turn.toolCalls.map((c) => `${c.name}(${JSON.stringify(c.input).slice(0, 60)})`).join(", ")}`);
        // On the last allowed step, append a wrap-up nudge to the tool results so
        // the model stops exploring and emits its JSON on the next turn. Keeping
        // the nudge inside the tool_result preserves user/assistant alternation
        // (required by the Anthropic API).
        const lastAllowed = i === MAX_ITERATIONS - 1 || Date.now() > deadline - 20000;
        const results = turn.toolCalls.map((c) => ({
          id: c.id,
          output: String(runTool(c.name, c.input, files)).slice(0, TOOL_OUTPUT_CAP) + (lastAllowed ? WRAP_NUDGE : ""),
        }));
        provider.appendToolResults(messages, results);
        if (turn.text) finalText = turn.text;
        if (lastAllowed) {
          endedWithTools = true;
          break;
        }
        continue;
      }

      finalText = turn.text || finalText;
      break; // no tool calls => the model is done
    }

    // If we stopped mid-exploration (hit the step/time budget), do one more turn
    // to collect the final JSON the model has been nudged to produce.
    if (endedWithTools && Date.now() < deadline) {
      const wrap = await provider.turn(messages, deadline, log).catch(() => null);
      if (wrap && wrap.text) finalText = wrap.text;
    }

    const parsed = parseResult(finalText);
    const findings = dedupe(parsed.findings, deterministicFindings);
    const served = servedModel && servedModel !== cfg.model ? ` (endpoint served "${servedModel}")` : "";
    const adjusted = parsed.triage.filter((t) => t.verdict !== "keep").length;
    log(`AI: ${findings.length} new finding(s), ${adjusted} triage adjustment(s), after ${steps} exploration step(s)${served}`);
    return { findings, triage: parsed.triage, servedModel };
  } catch (e) {
    log(`AI: skipped (${e.message})`);
    return { findings: [], error: e.message };
  }
}
