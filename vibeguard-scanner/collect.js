#!/usr/bin/env node
// Collect public repo URLs for apps built with Lovable, to feed batch.js.
//
// Two modes, picked automatically:
//
//   With GITHUB_TOKEN set  -> code search for the `lovable-tagger` dependency.
//                             Precise, and the only way to search file contents.
//   Without a token        -> repository search (name/description/readme), then
//                             every candidate is VERIFIED by fetching its
//                             package.json and looking for the real marker.
//
// The verification step is the important part. Searching for "lovable" by name
// pulls in a lot of repos that just have the word in them, and a study built on
// an unverified list is a study of nothing.
//
//   node collect.js --out repos.txt --limit 60
//   GITHUB_TOKEN=ghp_... node collect.js --out repos.txt --limit 60
//
// Everything it touches is public and read-only. The output is a list of repos
// to scan privately — do not publish individual repo names in a write-up.

import { writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

const args = process.argv.slice(2);
const flag = (n, d) => {
  const i = args.indexOf(`--${n}`);
  return i === -1 ? d : args[i + 1];
};
const OUT = flag("out", "repos.txt");
const LIMIT = Number(flag("limit", 60));
const TOKEN = process.env.GITHUB_TOKEN || "";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Lovable injects this dev dependency into every project it generates. It is
// the most reliable marker; the word "lovable" in a repo name is not.
const MARKERS = [/"lovable-tagger"/, /lovable\.dev/i, /lovable-uploads/i];

function ghHeaders() {
  const h = { accept: "application/vnd.github+json", "user-agent": "vibeguard-research" };
  if (TOKEN) h.authorization = `Bearer ${TOKEN}`;
  return h;
}

async function ghSearch(path) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`https://api.github.com${path}`, { headers: ghHeaders() });
    if (res.ok) return res.json();

    // Search is 10 req/min unauthenticated, 30 with a token. Wait it out.
    if (res.status === 403 || res.status === 429) {
      const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
      const waitMs = Math.max(5000, Math.min(70000, reset - Date.now() + 2000));
      console.error(`  rate limited, waiting ${Math.round(waitMs / 1000)}s...`);
      await sleep(waitMs);
      continue;
    }
    throw new Error(`GitHub search returned HTTP ${res.status}`);
  }
  throw new Error("gave up after repeated rate limits");
}

// Confirm a candidate really is a Lovable app by reading its package.json.
// raw.githubusercontent.com is a CDN, so this is cheap and unmetered.
async function verify(fullName, branch) {
  for (const b of [branch, "main", "master"].filter(Boolean)) {
    try {
      const res = await fetch(`https://raw.githubusercontent.com/${fullName}/${b}/package.json`);
      if (!res.ok) continue;
      const text = await res.text();
      if (MARKERS.some((re) => re.test(text))) return true;
      return false; // package.json exists but has no marker: not a Lovable app
    } catch {}
  }
  return false;
}

async function collectViaCodeSearch() {
  const found = new Map();
  const queries = [
    "lovable-tagger+in:file+filename:package.json",
    "lovable-uploads+in:file+extension:tsx",
  ];
  for (const q of queries) {
    for (let page = 1; page <= 5 && found.size < LIMIT * 2; page++) {
      const data = await ghSearch(`/search/code?q=${q}&per_page=100&page=${page}`);
      const items = data.items || [];
      for (const it of items) {
        const r = it.repository;
        if (r && !found.has(r.full_name)) found.set(r.full_name, r);
      }
      console.error(`  code search "${q.slice(0, 30)}" page ${page}: ${items.length} hits, ${found.size} repos`);
      if (items.length < 100) break;
      await sleep(2500);
    }
  }
  return [...found.values()];
}

async function collectViaRepoSearch() {
  const found = new Map();
  const queries = [
    "lovable+in:name,description+language:typescript",
    "lovable+in:readme+supabase",
    '"lovable.dev"+in:readme',
    "lovable+in:name+react+vite",
  ];
  for (const q of queries) {
    for (let page = 1; page <= 3 && found.size < LIMIT * 4; page++) {
      const data = await ghSearch(`/search/repositories?q=${q}&sort=updated&per_page=100&page=${page}`);
      const items = data.items || [];
      for (const r of items) if (!found.has(r.full_name)) found.set(r.full_name, r);
      console.error(`  repo search "${q.slice(0, 30)}" page ${page}: ${items.length} hits, ${found.size} candidates`);
      if (items.length < 100) break;
      await sleep(7000); // unauthenticated search allows ~10/min
    }
  }
  return [...found.values()];
}

async function main() {
  console.error(TOKEN ? "Using code search (GITHUB_TOKEN found)\n" : "No GITHUB_TOKEN: using repo search + verification\n");

  const candidates = TOKEN ? await collectViaCodeSearch() : await collectViaRepoSearch();
  console.error(`\n${candidates.length} candidate(s). Verifying against package.json...\n`);

  const usable = candidates.filter((r) => !r.fork && !r.archived);
  const confirmed = [];
  let checked = 0;

  // Verification hits a CDN, so a little parallelism is fine.
  const queue = [...usable];
  await Promise.all(
    Array.from({ length: 6 }, async () => {
      while (queue.length && confirmed.length < LIMIT) {
        const r = queue.shift();
        checked++;
        if (await verify(r.full_name, r.default_branch)) {
          // Re-check after the await: several workers can pass the loop
          // condition before any of them pushes, which overshoots the limit.
          if (confirmed.length >= LIMIT) break;
          confirmed.push(r);
          console.error(`  [${confirmed.length}/${LIMIT}] ${r.full_name}`);
        }
      }
    })
  );

  // Keep anything already in the file so repeated runs grow the list.
  const existing = existsSync(OUT)
    ? (await readFile(OUT, "utf8")).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    : [];
  const urls = [...new Set([...existing, ...confirmed.map((r) => r.html_url)])];

  await writeFile(OUT, `# Lovable repos, verified via package.json marker\n# collected ${new Date().toISOString().slice(0, 10)}\n${urls.join("\n")}\n`);

  console.error(`\nchecked ${checked} candidates, confirmed ${confirmed.length}`);
  console.error(`${urls.length} total repo(s) in ${OUT}`);
  console.error(`\nnext: node batch.js ${OUT} --out lovable-study`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
