import "./lib/env.js";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { runScan, isGitUrl } from "./lib/scan.js";
import { parseProjectUrl, validateAnonKey } from "./lib/supabase.js";
import { emailConfig, sendReportEmail, isValidEmail } from "./lib/email.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3488;

// PUBLIC mode is for hosting on the open internet. It disables local-filesystem
// scanning (otherwise anyone could scan the server's own files, including the
// provider key) and restricts clones to allowlisted git hosts (SSRF guard).
// Leave it off for local operator/CLI use where scanning a folder is fine.
const PUBLIC = process.env.VIBEGUARD_PUBLIC === "1";
const ALLOWED_GIT_HOSTS = (process.env.VIBEGUARD_ALLOWED_HOSTS || "github.com,gitlab.com,bitbucket.org")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const MAX_BODY_BYTES = 8 * 1024;
const RATE_MAX = Number(process.env.VIBEGUARD_RATE_MAX || 5); // scans per window per IP
const RATE_WINDOW_MS = Number(process.env.VIBEGUARD_RATE_WINDOW_MS || 60 * 60 * 1000);
const JOB_TTL_MS = 15 * 60 * 1000; // keep a finished result this long for polling

// How many scans actually run at once, and how many may wait for a slot. A scan
// is mostly wall-clock spent waiting on the model, so concurrency is bounded by
// the AI backend's rate limits rather than by this box. Raise CONCURRENCY once
// you are on a real provider account; a shared/personal gateway will throttle.
const CONCURRENCY = Math.max(1, Number(process.env.VIBEGUARD_CONCURRENCY || 2));
const MAX_QUEUE = Math.max(1, Number(process.env.VIBEGUARD_MAX_QUEUE || 20));

const ipHits = new Map(); // ip -> timestamp[]
const jobs = new Map(); // jobId -> { status, queuedAt, startedAt?, finishedAt?, result?, error?, code? }

// Waiting jobs, FIFO. Everything queued here has a matching entry in `jobs`.
const queue = []; // [{ jobId, run }]
let active = 0;

// Rolling average of recent scan durations, used to give waiting users an ETA
// instead of an unexplained spinner.
const recentSeconds = [];
const DEFAULT_SCAN_SECONDS = 180;

function recordDuration(seconds) {
  recentSeconds.push(seconds);
  if (recentSeconds.length > 10) recentSeconds.shift();
}

function avgScanSeconds() {
  if (!recentSeconds.length) return DEFAULT_SCAN_SECONDS;
  return Math.round(recentSeconds.reduce((a, b) => a + b, 0) / recentSeconds.length);
}

function enqueue(jobId, run) {
  queue.push({ jobId, run });
  pump();
}

// Start queued jobs until every worker slot is busy. Called on enqueue and again
// whenever a scan finishes, so a freed slot is filled immediately.
function pump() {
  while (active < CONCURRENCY && queue.length) {
    const item = queue.shift();
    const job = jobs.get(item.jobId);
    if (!job || job.status !== "queued") continue; // expired or already handled
    active++;
    job.status = "running";
    job.startedAt = Date.now();
    item.run().finally(() => {
      active--;
      pump();
    });
  }
}

// 1-based place in line; 0 once the job has left the queue.
function queuePosition(jobId) {
  const i = queue.findIndex((q) => q.jobId === jobId);
  return i === -1 ? 0 : i + 1;
}

// Rough wait for the job at `position`: how many full batches run before it.
function etaSeconds(position) {
  if (position <= 0) return 0;
  return Math.ceil(position / CONCURRENCY) * avgScanSeconds();
}

// Identify the client for rate limiting. X-Forwarded-For is a comma-separated
// chain "client, proxy1, proxy2"; a client can PREPEND fake entries, so the
// leftmost value is attacker-controlled and must never be trusted. Behind a
// trusted reverse proxy (Railway) the real client IP is the entry the proxy
// itself appended: count VIBEGUARD_PROXY_HOPS back from the end (1 = one proxy).
// Locally (no PUBLIC / no proxy) we use the raw socket address instead.
function clientIp(req) {
  const chain = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (PUBLIC && chain.length) {
    const hops = Math.max(1, Number(process.env.VIBEGUARD_PROXY_HOPS) || 1);
    return chain[chain.length - hops] || req.socket.remoteAddress || "unknown";
  }
  return req.socket.remoteAddress || "unknown";
}

function rateLimited(ip) {
  const now = Date.now();
  const recent = (ipHits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (recent.length >= RATE_MAX) {
    ipHits.set(ip, recent);
    return true;
  }
  recent.push(now);
  ipHits.set(ip, recent);
  return false;
}

// The live Supabase check sends requests to a real production database, so it
// is gated on an explicit ownership affirmation from the user and never runs by
// default. Returns { live } to pass to runScan, or { error } to reject with.
//
// Probing a stranger's database because they pasted someone else's repo is the
// failure mode this exists to prevent — the affirmation is recorded with the
// job so there is a record of who asked for it.
const LIVE_MAX = Number(process.env.VIBEGUARD_LIVE_MAX || 3); // probes per project per window
const LIVE_WINDOW_MS = Number(process.env.VIBEGUARD_LIVE_WINDOW_MS || 60 * 60 * 1000);
const liveHits = new Map(); // project ref -> timestamp[]

function liveRateLimited(ref) {
  const now = Date.now();
  const recent = (liveHits.get(ref) || []).filter((t) => now - t < LIVE_WINDOW_MS);
  if (recent.length >= LIVE_MAX) {
    liveHits.set(ref, recent);
    return true;
  }
  recent.push(now);
  liveHits.set(ref, recent);
  return false;
}

function resolveLiveOptions(payload) {
  const raw = payload.live;
  if (!raw || typeof raw !== "object" || !raw.enabled) return { live: null };

  // No affirmation, no probe. This is the whole gate.
  if (raw.consent !== true) {
    return { error: "To check the live database, confirm you own this app or have permission to test it." };
  }

  const url = String(raw.url || "").trim();
  const anonKey = String(raw.anonKey || "").trim();

  // Validate anything pasted up front so the user gets the error immediately
  // instead of several minutes into a queued scan. Blank means "find it in the
  // repo", which is resolved later once the files are loaded.
  let ref = null;
  if (url) {
    const parsed = parseProjectUrl(url);
    if (parsed.error) return { error: parsed.error };
    ref = parsed.ref;
  }
  if (anonKey) {
    const key = validateAnonKey(anonKey);
    if (key.error) return { error: key.error };
  }
  if (Boolean(url) !== Boolean(anonKey)) {
    return { error: "Give both the Supabase project URL and the anon key, or leave both blank to use the ones in your repo." };
  }

  if (ref && liveRateLimited(ref)) {
    return { error: `That Supabase project has been checked ${LIVE_MAX} times in the last hour. Try again later.` };
  }

  return { live: { enabled: true, url: url || null, anonKey: anonKey || null }, ref };
}

function pruneJobs() {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (job.finishedAt && now - job.finishedAt > JOB_TTL_MS) jobs.delete(id);
  }
  // Drop rate-limit history for IPs whose window has fully elapsed, otherwise
  // the map grows for the life of the process.
  for (const [ip, hits] of ipHits) {
    if (hits.every((t) => now - t >= RATE_WINDOW_MS)) ipHits.delete(ip);
  }
}

// Returns an error string if the target is not allowed, else null.
async function validateTarget(target) {
  if (!target) return "Paste a public git repository URL.";

  if (isGitUrl(target)) {
    let u;
    try {
      u = new URL(target);
    } catch {
      return "That does not look like a valid URL.";
    }
    if (PUBLIC) {
      if (u.protocol !== "https:") return "Only https:// git URLs are allowed.";
      const host = u.hostname.toLowerCase();
      if (!ALLOWED_GIT_HOSTS.includes(host)) {
        return `Only these git hosts are allowed: ${ALLOWED_GIT_HOSTS.join(", ")}.`;
      }
    }
    return null;
  }

  // Not a git URL => a local path. Never allowed on a public server.
  if (PUBLIC) {
    return "Enter a public https git URL, e.g. https://github.com/you/your-app.";
  }
  try {
    const s = await stat(target);
    if (!s.isDirectory()) return "That path is not a folder.";
  } catch {
    return "That folder does not exist on this machine. For remote repos, paste the full https:// git URL.";
  }
  return null;
}

async function readBody(req) {
  let body = "";
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body too large.");
    body += chunk;
  }
  return body;
}

// POST /api/scan -> start a job, return { jobId }. The scan runs in the
// background; the client polls GET /api/scan/:id. This keeps us off the
// hosting proxy's request-timeout, which would kill a multi-minute scan.
async function startScan(req, res) {
  pruneJobs();

  let body;
  try {
    body = await readBody(req);
  } catch (e) {
    return json(res, 413, { error: e.message });
  }

  let payload;
  try {
    payload = JSON.parse(body || "{}");
  } catch {
    return json(res, 400, { error: "Invalid JSON body." });
  }

  const target = String(payload.target || "").trim();
  const err = await validateTarget(target);
  if (err) return json(res, 400, { error: err });

  // Optional: email the report when the scan finishes. Only honored if the
  // server has email configured; a bad address is rejected up front.
  const email = String(payload.email || "").trim();
  if (email) {
    if (!emailConfig().enabled) return json(res, 400, { error: "Email delivery isn't enabled on this server." });
    if (!isValidEmail(email)) return json(res, 400, { error: "That email address doesn't look right." });
  }

  const liveOpts = resolveLiveOptions(payload);
  if (liveOpts.error) return json(res, 400, { error: liveOpts.error });

  const ip = clientIp(req);
  if (PUBLIC && rateLimited(ip)) {
    return json(res, 429, { error: `Rate limit reached (${RATE_MAX} scans/hour). Try again later.` });
  }

  if (queue.length >= MAX_QUEUE) {
    return json(res, 429, {
      error: `We're at capacity right now (${queue.length} scans waiting). Try again in a few minutes.`,
    });
  }

  const jobId = randomUUID();
  const queuedAt = Date.now();
  jobs.set(jobId, { status: "queued", queuedAt });

  // Keep a record of the ownership affirmation alongside the job it authorised.
  if (liveOpts.live) {
    const consent = { at: new Date().toISOString(), ip, target, project: liveOpts.ref || "from-repo" };
    jobs.get(jobId).liveConsent = consent;
    console.error(`[live] consent recorded: ${JSON.stringify(consent)}`);
  }

  enqueue(jobId, async () => {
    // pump() set status/startedAt before calling us.
    const startedAt = jobs.get(jobId).startedAt;
    const liveConsent = jobs.get(jobId).liveConsent || null;
    try {
      const { findings, markdown, fileCount, ai, live } = await runScan(target, { live: liveOpts.live });
      const finishedAt = Date.now();
      const seconds = Math.round((finishedAt - startedAt) / 100) / 10;
      recordDuration(seconds);
      jobs.set(jobId, {
        status: "done",
        queuedAt,
        startedAt,
        finishedAt,
        liveConsent,
        emailed: email ? "pending" : null,
        result: { findings, markdown, fileCount, ai, live, seconds, emailed: email ? "pending" : null },
      });

      // Fire-and-forget the report email. Runs server-side after the scan, so it
      // still sends even if the user closed the tab. Never affects the result.
      if (email && emailConfig().enabled) {
        sendReportEmail({ to: email, target, findings, markdown, ai, seconds, fileCount })
          .then(() => {
            const j = jobs.get(jobId);
            if (j?.result) j.result.emailed = "sent";
            console.error(`[email] report sent to ${email} for ${target}`);
          })
          .catch((e) => {
            const j = jobs.get(jobId);
            if (j?.result) j.result.emailed = "failed";
            console.error(`[email] send failed for ${email}: ${e.message}`);
          });
      }
    } catch (e) {
      jobs.set(jobId, {
        status: "error",
        queuedAt,
        startedAt,
        finishedAt: Date.now(),
        liveConsent,
        error: e.message,
        code: e.code || null,
      });
    }
  });

  // enqueue() may have started the job already, in which case position is 0.
  const position = queuePosition(jobId);
  return json(res, 202, { jobId, position, etaSeconds: etaSeconds(position) });
}

// GET /api/scan/:id -> poll job status/result.
function getJob(res, jobId) {
  pruneJobs();
  const job = jobs.get(jobId);
  if (!job) return json(res, 404, { error: "Unknown or expired scan. Start a new one." });

  if (job.status === "queued") {
    const position = queuePosition(jobId);
    return json(res, 200, {
      status: "queued",
      position,
      etaSeconds: etaSeconds(position),
      waited: Math.round((Date.now() - job.queuedAt) / 100) / 10,
    });
  }
  if (job.status === "running") {
    return json(res, 200, { status: "running", seconds: Math.round((Date.now() - job.startedAt) / 100) / 10 });
  }
  if (job.status === "error") {
    return json(res, 200, { status: "error", error: job.error, code: job.code });
  }
  return json(res, 200, { status: "done", ...job.result });
}

// Minimal markdown -> HTML for our own TERMS.md / PRIVACY.md (headings, bold,
// links, lists, paragraphs — nothing else is used in those files). Content is
// authored by us, not user input, but we escape anyway.
function mdToHtml(md) {
  const escapeHtml = (s) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const inline = (s) =>
    escapeHtml(s)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, `<a href="$2">$1</a>`);

  const out = [];
  let inList = false;
  for (const line of md.split("\n")) {
    const h = line.match(/^(#{1,3}) (.*)$/);
    const li = line.match(/^- (.*)$/);
    if (inList && !li) {
      out.push("</ul>");
      inList = false;
    }
    if (h) out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`);
    else if (li) {
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      out.push(`<li>${inline(li[1])}</li>`);
    } else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  if (inList) out.push("</ul>");
  return out.join("\n");
}

async function serveMarkdownPage(res, file, title) {
  let md;
  try {
    md = await readFile(path.join(here, file), "utf8");
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain", ...securityHeaders() });
    return res.end("Not found");
  }
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title} — VibeGuard</title>
<style>
  body { margin: 0; background: #12141a; color: #e8eaf0; font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
  .wrap { max-width: 720px; margin: 0 auto; padding: 32px 16px 60px; }
  h1 { font-size: 22px; } h2 { font-size: 17px; margin-top: 28px; }
  a { color: #4ade80; }
  p, li { color: #c7ccdb; }
  strong { color: #e8eaf0; }
  .back { font-size: 13px; }
</style></head><body><div class="wrap">
<p class="back"><a href="/">&larr; VibeGuard Scanner</a></p>
${mdToHtml(md)}
</div></body></html>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...securityHeaders() });
  res.end(html);
}

function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  };
}

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json", ...securityHeaders() });
  res.end(JSON.stringify(obj));
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;

  if (req.method === "POST" && pathname === "/api/scan") return startScan(req, res);

  const jobMatch = pathname.match(/^\/api\/scan\/([\w-]+)$/);
  if (req.method === "GET" && jobMatch) return getJob(res, jobMatch[1]);

  if (req.method === "GET" && pathname === "/healthz") {
    return json(res, 200, { ok: true, active, queued: queue.length, concurrency: CONCURRENCY });
  }

  if (req.method === "GET" && pathname === "/api/config") return json(res, 200, { emailEnabled: emailConfig().enabled });

  if (req.method === "GET" && pathname === "/privacy") return serveMarkdownPage(res, "PRIVACY.md", "Privacy notice");
  if (req.method === "GET" && pathname === "/terms") return serveMarkdownPage(res, "TERMS.md", "Terms of use");

  if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
    try {
      const html = await readFile(path.join(here, "public", "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...securityHeaders() });
      return res.end(html);
    } catch {
      res.writeHead(500);
      return res.end("public/index.html missing");
    }
  }

  res.writeHead(404, { "Content-Type": "text/plain", ...securityHeaders() });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(
    `VibeGuard scanner UI running at http://localhost:${PORT}` +
      ` [${CONCURRENCY} concurrent scan${CONCURRENCY === 1 ? "" : "s"}, queue up to ${MAX_QUEUE}]` +
      (PUBLIC ? " [PUBLIC mode: git URLs only, rate-limited]" : " [local mode]")
  );
});
