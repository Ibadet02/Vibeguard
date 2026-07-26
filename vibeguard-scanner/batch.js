#!/usr/bin/env node
// Batch-scan a list of public repos and print aggregate stats.
//
// Built for research posts: "I scanned N Lovable repos, here's how often X
// actually happens." The numbers it prints are the ones you'd cite, so it also
// writes every per-repo result to a .jsonl file — if someone asks you to show
// your work, that file is the answer.
//
// Repo-only by design. It never contacts anyone's database: the live Supabase
// check needs the owner's consent and that cannot exist for a stranger's repo.
// The AI pass is forced off too, so a run costs nothing.
//
//   node batch.js repos.txt                 # one repo URL per line, # for comments
//   node batch.js repos.txt --out run1      # write run1.jsonl / run1.md
//   node batch.js repos.txt --concurrency 2
//
// Re-running with the same --out skips repos already in the .jsonl, so a crash
// or a Ctrl-C costs you nothing.

import { readFile, appendFile, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { runScan } from "./lib/scan.js";

// Never spend money or touch a third party's database from a batch run.
process.env.VIBEGUARD_AI = "0";

const args = process.argv.slice(2);
const listFile = args.find((a) => !a.startsWith("--"));
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};
const outBase = flag("out", "batch");
const CONCURRENCY = Math.max(1, Number(flag("concurrency", 3)));

if (!listFile) {
  console.error("usage: node batch.js <repos.txt> [--out name] [--concurrency n]");
  process.exit(1);
}

const jsonlPath = `${outBase}.jsonl`;
const mdPath = `${outBase}.md`;

// Buckets we care about for a write-up. Each tests a finding's title, so they
// stay correct as long as checks.js keeps its wording.
const BUCKETS = [
  { key: "service_role_frontend", label: "service_role key in frontend code", re: /^Supabase service_role key exposed in frontend code$/ },
  { key: "service_role_any", label: "service_role key anywhere in the repo", re: /^Supabase service_role key/ },
  { key: "hardcoded_key_frontend", label: "any API key hardcoded in frontend code", re: /hardcoded in frontend code$/ },
  { key: "hardcoded_key_any", label: "any API key hardcoded in the repo", re: /hardcoded in (frontend|source) code$/ },
  { key: "public_env_secret", label: "secret in a public-by-design env var (VITE_/NEXT_PUBLIC_)", re: /is public by design but holds a secret$/ },
  { key: "env_committed_leak", label: ".env committed AND holding a real secret", re: /is committed to git, with secrets in it$/ },
  { key: "env_committed_unclear", label: ".env committed, contents unclear", re: /^\.env[^,]* is committed to git$/ },
  { key: "env_committed_harmless", label: ".env committed but only public config (not a leak)", re: /is committed to git, but nothing secret is in it$/ },
  { key: "env_committed_any", label: ".env committed to git (any kind)", re: / is committed to git/ },
  { key: "no_gitignore", label: "no .gitignore at all", re: /^No \.gitignore/ },
  { key: "gitignore_gap", label: ".gitignore does not cover .env", re: /^\.gitignore does not cover/ },
  { key: "rls_missing", label: "a table created without RLS (in migrations)", re: /is created without Row Level Security$/ },
  { key: "supabase_no_migrations", label: "uses Supabase but ships no migrations to check", re: /^Supabase detected, but no migrations/ },
  { key: "unauth_route", label: "an API route with no visible auth check", re: /has no auth check that I can see$/ },
  { key: "trusted_header", label: "identity trusted from a request header", re: /^Auth bypass: user identity trusted/ },
  { key: "idor", label: "a possible IDOR pattern", re: /^Possible IDOR/ },
  { key: "prod_cve", label: "a production dependency with a known CVE", re: /dependencies? with known (critical|high) vulnerabilities$/ },
  { key: "injection_file", label: "an agent-instruction file trying to steer code review", re: /^Repository contains text that tries to manipulate/ },
];

// Works on titles, not finding objects, so the summary can be re-derived from a
// finished .jsonl after you edit BUCKETS — without re-cloning 50 repos. Buckets
// frozen at scan time would silently read as 0% for any bucket added later.
function classify(titles) {
  const hits = {};
  for (const b of BUCKETS) hits[b.key] = titles.some((t) => b.re.test(t));
  return hits;
}

async function main() {
  const raw = await readFile(listFile, "utf8");
  const repos = [
    ...new Set(
      raw
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"))
    ),
  ];

  // Resume: skip anything already recorded.
  const done = new Set();
  if (existsSync(jsonlPath)) {
    for (const line of readFileSync(jsonlPath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        done.add(JSON.parse(line).repo);
      } catch {}
    }
  }
  const todo = repos.filter((r) => !done.has(r));
  console.error(`${repos.length} repo(s), ${done.size} already done, ${todo.length} to scan\n`);

  let n = 0;
  const runOne = async (repo) => {
    const i = ++n;
    const started = Date.now();
    let record;
    try {
      const { findings, fileCount } = await runScan(repo);
      const counts = { critical: 0, high: 0, medium: 0, info: 0 };
      for (const f of findings) counts[f.severity]++;
      record = {
        repo,
        ok: true,
        fileCount,
        seconds: Math.round((Date.now() - started) / 100) / 10,
        counts,
        buckets: classify(findings.map((f) => f.title)),
        titles: findings.map((f) => f.title),
      };
      console.error(
        `[${i}/${todo.length}] ${repo}\n    ${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.info}I` +
          `  (${fileCount} files, ${record.seconds}s)`
      );
    } catch (e) {
      record = { repo, ok: false, error: String(e.message).slice(0, 300) };
      console.error(`[${i}/${todo.length}] ${repo}\n    FAILED: ${record.error}`);
    }
    // Append as we go so a crash never loses completed work.
    await appendFile(jsonlPath, JSON.stringify(record) + "\n");
  };

  const queue = [...todo];
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
      while (queue.length) await runOne(queue.shift());
    })
  );

  await report();
}

async function report() {
  const records = readFileSync(jsonlPath, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));

  const ok = records.filter((r) => r.ok);
  const failed = records.filter((r) => !r.ok);
  if (!ok.length) {
    console.error("\nNo successful scans.");
    return;
  }

  const pct = (n) => `${Math.round((n / ok.length) * 1000) / 10}%`;
  const withCrit = ok.filter((r) => r.counts.critical > 0).length;
  const withCritOrHigh = ok.filter((r) => r.counts.critical + r.counts.high > 0).length;
  const clean = ok.filter((r) => r.counts.critical + r.counts.high + r.counts.medium === 0).length;

  const rows = BUCKETS.map((b) => {
    const hits = ok.filter((r) => classify(r.titles)[b.key]).length;
    return { label: b.label, hits, pct: pct(hits) };
  }).sort((a, b) => b.hits - a.hits);

  let md = `# Batch scan results\n\n`;
  md += `Scanned **${ok.length}** repos (${failed.length} failed to clone or scan). `;
  md += `Repo contents only: no database, no live app, no AI pass.\n\n`;
  md += `- **${withCrit}** (${pct(withCrit)}) had at least one CRITICAL finding\n`;
  md += `- **${withCritOrHigh}** (${pct(withCritOrHigh)}) had at least one critical or high\n`;
  md += `- **${clean}** (${pct(clean)}) had nothing above info level\n\n`;
  md += `| Issue | Repos | % |\n| --- | ---: | ---: |\n`;
  for (const r of rows) md += `| ${r.label} | ${r.hits} | ${r.pct} |\n`;

  if (failed.length) {
    md += `\n## Failed (${failed.length})\n\n`;
    for (const f of failed.slice(0, 20)) md += `- ${f.repo} — ${f.error}\n`;
  }

  md += `\n---\n\nPer-repo detail: \`${jsonlPath}\`. Individual repos are deliberately not named in the summary.\n`;

  await writeFile(mdPath, md);
  console.error(`\n${md}`);
  console.error(`written: ${mdPath} and ${jsonlPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
