import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadFiles } from "./walk.js";
import {
  checkSecretsInCode,
  checkFallbackSecrets,
  checkEnvFiles,
  checkSupabaseRls,
  checkUnprotectedRoutes,
  checkIdorPatterns,
  checkDependencies,
  checkSecurityHeaders,
  checkCors,
} from "./checks.js";
import { renderReport } from "./report.js";

const exec = promisify(execFile);

export function isGitUrl(target) {
  return /^(https?:\/\/|git@)/.test(target);
}

// Runs the full scan against a local path or git URL.
// Returns { findings, markdown, fileCount }. Throws with a friendly message on failure.
export async function runScan(target) {
  let root = target;
  let cleanup = null;

  if (isGitUrl(target)) {
    const tmp = await mkdtemp(path.join(tmpdir(), "vibeguard-"));
    try {
      await exec("git", ["clone", "--depth", "1", target, tmp], { timeout: 120000 });
    } catch (e) {
      await rm(tmp, { recursive: true, force: true });
      throw new Error(`Could not clone ${target}. Is it public and reachable? (${firstLine(e.message)})`);
    }
    root = tmp;
    cleanup = () => rm(tmp, { recursive: true, force: true });
  }

  try {
    const files = await loadFiles(root);
    if (files.length === 0) {
      throw new Error("No readable files found at that path.");
    }

    const findings = [
      ...checkSecretsInCode(files),
      ...checkFallbackSecrets(files),
      ...(await checkEnvFiles(files, root)),
      ...checkSupabaseRls(files),
      ...checkUnprotectedRoutes(files),
      ...checkIdorPatterns(files),
      ...(await checkDependencies(root, files)),
      ...checkSecurityHeaders(files),
      ...checkCors(files),
    ];

    const markdown = renderReport({
      target,
      findings,
      checkedAt: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC",
    });

    return { findings, markdown, fileCount: files.length };
  } finally {
    if (cleanup) await cleanup();
  }
}

function firstLine(s) {
  return String(s || "").split("\n")[0].slice(0, 200);
}
