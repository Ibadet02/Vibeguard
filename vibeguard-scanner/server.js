import "./lib/env.js";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { runScan, isGitUrl } from "./lib/scan.js";

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

let scanning = false; // one scan at a time (matches the single-account AI backend)
const ipHits = new Map(); // ip -> timestamp[]
const jobs = new Map(); // jobId -> { status, startedAt, finishedAt?, result?, error?, code? }

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

function pruneJobs() {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (job.finishedAt && now - job.finishedAt > JOB_TTL_MS) jobs.delete(id);
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

  const ip = clientIp(req);
  if (PUBLIC && rateLimited(ip)) {
    return json(res, 429, { error: `Rate limit reached (${RATE_MAX} scans/hour). Try again later.` });
  }

  if (scanning) {
    return json(res, 429, { error: "A scan is already running. Please wait a moment and retry." });
  }

  scanning = true;
  const jobId = randomUUID();
  const startedAt = Date.now();
  jobs.set(jobId, { status: "running", startedAt });

  (async () => {
    try {
      const { findings, markdown, fileCount, ai } = await runScan(target);
      const finishedAt = Date.now();
      jobs.set(jobId, {
        status: "done",
        startedAt,
        finishedAt,
        result: { findings, markdown, fileCount, ai, seconds: Math.round((finishedAt - startedAt) / 100) / 10 },
      });
    } catch (e) {
      jobs.set(jobId, {
        status: "error",
        startedAt,
        finishedAt: Date.now(),
        error: e.message,
        code: e.code || null,
      });
    } finally {
      scanning = false;
    }
  })();

  return json(res, 202, { jobId });
}

// GET /api/scan/:id -> poll job status/result.
function getJob(res, jobId) {
  pruneJobs();
  const job = jobs.get(jobId);
  if (!job) return json(res, 404, { error: "Unknown or expired scan. Start a new one." });

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

  if (req.method === "GET" && pathname === "/healthz") return json(res, 200, { ok: true });

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
      (PUBLIC ? " [PUBLIC mode: git URLs only, rate-limited]" : " [local mode]")
  );
});
