import "./lib/env.js";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runScan, isGitUrl } from "./lib/scan.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3488;

let scanning = false; // one scan at a time; this is a local operator tool

async function handleScan(req, res) {
  let body = "";
  for await (const chunk of req) body += chunk;
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return json(res, 400, { error: "Invalid JSON body." });
  }

  const target = (payload.target || "").trim();
  if (!target) return json(res, 400, { error: "Paste a repo URL or a local folder path." });

  // Local paths must exist and be directories; URLs must look like git remotes.
  if (!isGitUrl(target)) {
    try {
      const s = await stat(target);
      if (!s.isDirectory()) return json(res, 400, { error: "That path is not a folder." });
    } catch {
      return json(res, 400, { error: "That folder does not exist on this machine. For remote repos, paste the full https:// git URL." });
    }
  }

  if (scanning) return json(res, 429, { error: "A scan is already running, wait for it to finish." });
  scanning = true;
  try {
    const t0 = Date.now();
    const { findings, markdown, fileCount, ai } = await runScan(target);
    return json(res, 200, {
      findings,
      markdown,
      fileCount,
      ai,
      seconds: Math.round((Date.now() - t0) / 100) / 10,
    });
  } catch (e) {
    return json(res, 500, { error: e.message });
  } finally {
    scanning = false;
  }
}

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
}

const server = createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/api/scan") return handleScan(req, res);
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    try {
      const html = await readFile(path.join(here, "public", "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(html);
    } catch {
      res.writeHead(500);
      return res.end("public/index.html missing");
    }
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`VibeGuard scanner UI running at http://localhost:${PORT}`);
});
