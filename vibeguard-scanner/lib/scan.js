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
import { quarantineAgentInstructions, quarantineFindings, isQuarantined } from "./sanitize.js";
import { checkSupabaseLive, harvestCredentials } from "./supabase.js";
import { renderReport } from "./report.js";

const exec = promisify(execFile);

export function isGitUrl(target) {
  return /^(https?:\/\/|git@)/.test(target);
}

// Runs the full scan against a local path or git URL.
//
// `opts.live` opts into the live Supabase check. It is OFF unless the caller
// passes it, and server.js only passes it after the user has affirmed they own
// the app — sending requests to someone else's production database is not
// something a scan should ever do by default. Credentials given here win; with
// none, we look for the app's public key in the repo.
//
// Returns { findings, markdown, fileCount, ai, live }. Throws with a friendly
// message on failure.
export async function runScan(target, opts = {}) {
  let root = target;
  let cleanup = null;
  let cloned = false;

  if (isGitUrl(target)) {
    const tmp = await mkdtemp(path.join(tmpdir(), "vibeguard-"));
    try {
      await exec("git", ["clone", "--depth", "1", target, tmp], { timeout: 120000 });
    } catch (e) {
      await rm(tmp, { recursive: true, force: true });
      throw new Error(`Could not clone ${target}. Is it public and reachable? (${firstLine(e.message)})`);
    }
    root = tmp;
    cloned = true;
    cleanup = () => rm(tmp, { recursive: true, force: true });
  }

  try {
    // Take agent-instruction files out of the review before anything reads the
    // repo. The AI pass would otherwise obey a CLAUDE.md planted by whoever owns
    // the code it is meant to be judging. On a clone we delete them outright; on
    // a local scan the files belong to the operator, so we only exclude them.
    const quarantine = await quarantineAgentInstructions(root, { deleteFromDisk: cloned });

    const loaded = await loadFiles(root);
    const files = quarantine.removed.length
      ? loaded.filter((f) => !isQuarantined(f.rel, quarantine.removed))
      : loaded;
    if (files.length === 0) {
      throw new Error("No readable files found at that path.");
    }

    const findings = [
      ...quarantineFindings(quarantine),
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

    // Optional live Supabase check. Runs before the AI pass so the model can
    // triage what we actually observed against the code it reads.
    const live = await runLiveCheck(opts.live, files, (m) => console.error(m));
    findings.push(...live.findings);

    // Optional AI reasoning pass. Layers logic/authorization findings on top of
    // the deterministic checks. Env-gated and non-fatal: if it is disabled or
    // the model is unreachable, we just keep the deterministic findings.
    const ai = await aiReview({
      files,
      root,
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
      model: ai.servedModel || aiConfig().model,
      // Operator-facing: what this scan actually cost to run.
      cost: ai.cost || null,
    };

    const markdown = renderReport({
      target,
      findings,
      checkedAt: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC",
      ai: aiStatus,
    });

    return { findings, markdown, fileCount: files.length, ai: aiStatus, live: live.status };
  } finally {
    if (cleanup) await cleanup();
  }
}

// Resolve credentials and run the live check. Never throws: a failure here is a
// note in the report, not a failed scan.
async function runLiveCheck(live, files, log) {
  if (!live || !live.enabled) return { findings: [], status: { status: "off" } };

  let url = live.url;
  let anonKey = live.anonKey;
  let source = "pasted";
  if (!url || !anonKey) {
    const found = harvestCredentials(files);
    url = url || found.url;
    anonKey = anonKey || found.anonKey;
    source = "repo";
  }

  if (!url || !anonKey) {
    return {
      findings: [
        {
          severity: "info",
          title: "Live database check skipped: no Supabase details found",
          file: null,
          line: null,
          detail:
            "You asked us to check the live database, but we couldn't find your Supabase project URL and public key in the repo. Apps built with Lovable or Bolt usually have both in the frontend code; yours may keep them somewhere we don't look, like a hosting dashboard.",
          fix: "Re-run the scan and paste your project URL and anon (public) key into the live-check fields. Both are in Supabase under Settings > API, and the anon key is safe to share — it already ships inside your app.",
          source: "supabase",
        },
      ],
      status: { status: "skipped", reason: "no-credentials" },
    };
  }

  log(`supabase: live check via ${source} credentials`);
  const res = await checkSupabaseLive({ url, anonKey, log });

  if (res.status === "error") {
    return {
      findings: [
        {
          severity: "info",
          title: "Live database check could not run",
          file: null,
          line: null,
          detail: `We tried to check your live Supabase project but couldn't: ${res.error} Everything else in this report still applies.`,
          fix: "Check the project URL and anon key, then re-run. If the project is paused in Supabase, resume it first.",
          source: "supabase",
        },
      ],
      status: { status: "error", error: res.error },
    };
  }

  return {
    findings: res.findings,
    status: {
      status: "ran",
      source,
      tablesExposedToApi: res.tablesExposedToApi,
      tablesProbed: res.tablesProbed,
      tablesReadable: res.tablesReadable,
    },
  };
}

function firstLine(s) {
  return String(s || "").split("\n")[0].slice(0, 200);
}
