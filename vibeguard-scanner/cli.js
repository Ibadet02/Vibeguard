#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { runScan } from "./lib/scan.js";
import { renderConsole } from "./lib/report.js";

function usage() {
  console.log(`VibeGuard, security scanner for AI-built apps

Usage:
  node cli.js <path-to-repo>            scan a local folder
  node cli.js <git-url>                 clone (shallow) and scan
  Options:
    --out <file>    where to write the markdown report (default: vibeguard-report.md)
    --json          also print findings as JSON
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help")) return usage();

  const outIdx = args.indexOf("--out");
  const outFile = outIdx !== -1 ? args[outIdx + 1] : "vibeguard-report.md";
  const wantJson = args.includes("--json");
  const target = args.find((a) => !a.startsWith("--") && a !== outFile);
  if (!target) return usage();

  console.log(`Scanning ${target} ...`);
  const { findings, markdown } = await runScan(target);

  await writeFile(outFile, markdown, "utf8");
  console.log(renderConsole({ findings }));
  console.log(`Full plain-English report: ${outFile}`);
  if (wantJson) console.log(JSON.stringify(findings, null, 2));

  process.exit(findings.some((f) => f.severity === "critical") ? 1 : 0);
}

main().catch((e) => {
  console.error("Scan failed:", e.message);
  process.exit(2);
});
