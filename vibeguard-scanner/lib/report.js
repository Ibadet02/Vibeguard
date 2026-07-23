const SEV_ORDER = ["critical", "high", "medium", "info"];

const SEV_LABEL = {
  critical: "CRITICAL, fix today",
  high: "HIGH, fix this week",
  medium: "MEDIUM, worth fixing",
  info: "GOOD TO KNOW",
};

const SEV_EMOJI = { critical: "🔴", high: "🟠", medium: "🟡", info: "🔵" };

function aiStatusLine(ai) {
  if (!ai) return "";
  if (ai.status === "ran") {
    const t = ai.triaged ? `, corrected ${ai.triaged} pattern-check false positive${ai.triaged === 1 ? "" : "s"}` : "";
    return `**AI reasoning pass:** ran (${ai.model}), found ${ai.count} issue${ai.count === 1 ? "" : "s"} the pattern checks missed${t}\n`;
  }
  if (ai.status === "error") {
    return `**AI reasoning pass:** attempted but did not complete, so this report is pattern-checks only. Reason: ${ai.error}\n`;
  }
  // skipped
  return `**AI reasoning pass:** not run, this is a fast pattern-only scan. Set VIBEGUARD_LLM_API_KEY (and VIBEGUARD_LLM_BASE_URL / VIBEGUARD_LLM_MODEL) to enable the deep logic review.\n`;
}

export function renderReport({ target, findings, checkedAt, ai }) {
  const bySev = Object.fromEntries(SEV_ORDER.map((s) => [s, []]));
  for (const f of findings) bySev[f.severity]?.push(f);

  const counts = SEV_ORDER.map((s) => ({ s, n: bySev[s].length })).filter((x) => x.n > 0);
  const worst = counts[0]?.s;

  let md = `# VibeGuard security report\n\n`;
  md += `**App:** ${target}\n**Scanned:** ${checkedAt}\n${aiStatusLine(ai)}\n`;

  if (findings.length === 0) {
    md += `## Verdict: clean scan\n\nNone of the checks found a problem. That does not guarantee the app is safe (no scanner can), but the most common ways vibe-coded apps get burned are not present.\n\n---\n\n*This report is informational, not a security audit. No scanner catches everything. Provided as is, use at your own risk.*\n`;
    return md;
  }

  md += `## The short version\n\n`;
  md += counts.map(({ s, n }) => `- ${SEV_EMOJI[s]} **${n}** ${SEV_LABEL[s].split(",")[0].toLowerCase()}${n > 1 ? " issues" : " issue"}`).join("\n") + "\n\n";

  if (worst === "critical") {
    md += `Start with the critical items. Each one is the kind of thing that ends up as a "my app got hacked" post. All of them have step-by-step fixes below, most take under 30 minutes.\n\n`;
  } else if (worst === "high") {
    md += `No five-alarm fires, but the high items are real risks with real fixes below. Most take under 30 minutes.\n\n`;
  } else {
    md += `Nothing urgent. The items below are worth a pass when you have an hour.\n\n`;
  }

  for (const sev of SEV_ORDER) {
    if (bySev[sev].length === 0) continue;
    md += `## ${SEV_EMOJI[sev]} ${SEV_LABEL[sev]}\n\n`;
    for (const f of bySev[sev]) {
      md += `### ${f.title}\n\n`;
      if (f.file) md += `**Where:** \`${f.file}${f.line ? `:${f.line}` : ""}\`\n\n`;
      if (f.source === "ai") md += `**Found by:** AI reasoning pass (reviews app logic, not just patterns)\n\n`;
      md += `**What this means:** ${f.detail}\n\n`;
      md += `**How to fix:** ${f.fix}\n\n`;
    }
  }

  md += `---\n\n*Scanned by [VibeGuard](https://vibeguard-6809.netlify.app), a security scanner for AI-built apps. Checks: hardcoded keys and tokens, hardcoded fallback secrets, secrets in frontend bundles, committed .env files, Supabase Row Level Security, unauthenticated API routes, identity trusted from request headers, IDOR patterns, dependency CVEs, security headers, CORS.*\n\n`;
  md += `*This report is informational, not a security audit. No scanner catches everything, and individual findings can be wrong, so verify before acting on them. Provided as is, use at your own risk.*\n`;
  return md;
}

export function renderConsole({ findings }) {
  const bySev = Object.fromEntries(SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s)]));
  let out = "\n";
  for (const sev of SEV_ORDER) {
    for (const f of bySev[sev]) {
      out += `${SEV_EMOJI[sev]} [${sev.toUpperCase()}]${f.source === "ai" ? " (AI)" : ""} ${f.title}${f.file ? `  (${f.file}${f.line ? ":" + f.line : ""})` : ""}\n`;
    }
  }
  const c = bySev.critical.length, h = bySev.high.length;
  out += `\n${findings.length} finding${findings.length === 1 ? "" : "s"}: ${c} critical, ${h} high, ${bySev.medium.length} medium, ${bySev.info.length} info\n`;
  return out;
}
