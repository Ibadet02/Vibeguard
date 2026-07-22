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
  checkTrustedIdentityHeader,
  checkDependencies,
  checkSecurityHeaders,
  checkCors,
} from "./checks.js";
import { aiReview, aiConfig, applyTriage } from "./ai-review.js";
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
      ...checkTrustedIdentityHeader(files),
      ...(await checkDependencies(root, files)),
      ...checkSecurityHeaders(files),
      ...checkCors(files),
    ];

    // Optional AI reasoning pass. Layers logic/authorization findings on top of
    // the deterministic checks. Env-gated and non-fatal: if it is disabled or
    // the model is unreachable, we just keep the deterministic findings.
    const ai = await aiReview({
      files,
      deterministicFindings: findings,
      log: (m) => console.error(m),
    });
    // Let the model correct the pattern checks' false positives / wrong
    // severities (in place), then add the logic bugs it found on top.
    const triaged = applyTriage(findings, ai.triage);
    findings.push(...ai.findings);

    // Surface whether the reasoning pass actually ran, so a silent skip (no key,
    // or a blocked/failed call) is visible in the report instead of looking like
    // a suspiciously fast "clean-ish" scan.
    const aiStatus = {
      status: ai.skipped ? "skipped" : ai.error ? "error" : "ran",
      count: ai.findings.length,
      triaged,
      error: ai.error,
      model: aiConfig().model,
    };

    const markdown = renderReport({
      target,
      findings,
      checkedAt: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC",
      ai: aiStatus,
    });

    return { findings, markdown, fileCount: files.length, ai: aiStatus };
  } finally {
    if (cleanup) await cleanup();
  }
}

function firstLine(s) {
  return String(s || "").split("\n")[0].slice(0, 200);
}
