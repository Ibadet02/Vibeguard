// Optional "email me the report" feature. Zero runtime dependencies: we POST to
// the Resend HTTP API with fetch. Entirely env-gated and non-fatal — if it is
// not configured or the send fails, the scan result is unaffected.
//
// Env:
//   VIBEGUARD_EMAIL_API_KEY   Resend API key (also accepts VIBEGUARD_RESEND_API_KEY). Enables the feature.
//   VIBEGUARD_EMAIL_FROM      verified sender, e.g. "VibeGuard <reports@yourdomain.com>"
//   VIBEGUARD_EMAIL_BCC       optional: blind-copy this address on every report (your lead list)
//   VIBEGUARD_APP_URL         optional: link back to the scanner in the email footer

const RESEND_ENDPOINT = "https://api.resend.com/emails";
const SEND_TIMEOUT_MS = 15000;

export function emailConfig() {
  const apiKey = process.env.VIBEGUARD_EMAIL_API_KEY || process.env.VIBEGUARD_RESEND_API_KEY || "";
  const from = process.env.VIBEGUARD_EMAIL_FROM || "";
  const bcc = process.env.VIBEGUARD_EMAIL_BCC || "";
  const appUrl = process.env.VIBEGUARD_APP_URL || "";
  // Need both a key and a verified From address to send anything.
  const enabled = Boolean(apiKey && from);
  return { enabled, apiKey, from, bcc, appUrl };
}

// Conservative single-line email check. Not RFC-perfect on purpose; just enough
// to reject typos and junk before we hand it to the provider.
export function isValidEmail(s) {
  const v = String(s || "").trim();
  return v.length >= 3 && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

const SEV_ORDER = ["critical", "high", "medium", "info"];
const SEV_COLOR = { critical: "#FF5C7A", high: "#FFB44C", medium: "#FACC15", info: "#60A5FA" };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", info: "Good to know" };

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function subjectFor(target, findings) {
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const repo = String(target || "").replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\.git$/, "");
  if (findings.length === 0) return `VibeGuard report: clean scan — ${repo}`;
  const parts = SEV_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  return `VibeGuard report: ${parts.join(", ")} — ${repo}`;
}

// Inline-styled HTML (email clients ignore <style>/external CSS). Kept simple
// and dark to match the app.
function renderEmailHtml({ target, findings, ai, seconds, fileCount, appUrl }) {
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  const wrap = (inner) =>
    `<div style="background:#0A0D15;padding:28px 0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
      <div style="max-width:620px;margin:0 auto;padding:0 20px;color:#EAEFF9;">${inner}</div>
    </div>`;

  const header =
    `<div style="font-size:20px;font-weight:700;color:#EAEFF9;">▲ VibeGuard security report</div>
     <div style="color:#95A0B8;font-size:13px;margin-top:6px;">${esc(target)} · ${fileCount} files · ${seconds}s</div>`;

  const summary = findings.length
    ? `<div style="margin:18px 0 8px;">` +
      SEV_ORDER.filter((s) => counts[s]).map((s) =>
        `<span style="display:inline-block;margin:0 8px 8px 0;padding:6px 12px;border-radius:8px;background:#121826;border:1px solid #232E44;font-size:13px;">
           <b style="color:${SEV_COLOR[s]};font-size:16px;">${counts[s]}</b> ${esc(SEV_LABEL[s].toLowerCase())}</span>`
      ).join("") +
      `</div>`
    : `<div style="margin:18px 0;padding:14px 16px;border-radius:10px;background:rgba(70,214,160,0.08);border:1px solid rgba(70,214,160,0.3);color:#EAEFF9;">
         <b>Clean scan.</b> None of the checks found a problem. No scanner can guarantee safety, but the common ways vibe-coded apps get burned are not present.</div>`;

  const cards = sorted.map((f) => {
    const c = SEV_COLOR[f.severity] || "#33415C";
    const src = f.source === "ai" ? ` · AI reasoning` : f.triaged ? ` · AI-triaged` : "";
    return `<div style="background:#121826;border:1px solid #232E44;border-left:4px solid ${c};border-radius:10px;padding:14px 16px;margin:10px 0;">
      <div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:${c};text-transform:uppercase;">${esc(f.severity)}${src}</div>
      <div style="font-size:15px;font-weight:600;margin:5px 0;color:#EAEFF9;">${esc(f.title)}</div>
      ${f.file ? `<div style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#95A0B8;margin-bottom:8px;">${esc(f.file)}${f.line ? ":" + esc(f.line) : ""}</div>` : ""}
      <div style="font-size:14px;color:#C7CCDB;margin:6px 0;">${esc(f.detail)}</div>
      <div style="font-size:14px;color:#C7CCDB;margin:6px 0;"><span style="color:#2FE4C7;font-weight:600;">Fix:</span> ${esc(f.fix)}</div>
    </div>`;
  }).join("");

  const aiLine = ai && ai.status === "ran"
    ? `<div style="color:#95A0B8;font-size:12px;margin-top:6px;">AI reasoning pass ran (${esc(ai.model || "")}), found ${ai.count} issue(s) the pattern checks missed${ai.triaged ? `, corrected ${ai.triaged} false positive(s)` : ""}.</div>`
    : "";

  const footer =
    `<div style="margin-top:26px;padding-top:16px;border-top:1px solid #232E44;color:#5A6479;font-size:12px;">
       ${appUrl ? `Scanned at <a href="${esc(appUrl)}" style="color:#95A0B8;">VibeGuard</a>. ` : ""}This report is informational, not a security audit. No scanner catches everything, and individual findings can be wrong, so verify before acting on them. Provided as is, use at your own risk.
     </div>`;

  return wrap(header + aiLine + summary + cards + footer);
}

// Sends the report. Resolves { ok:true } or throws (caller catches; never fatal).
export async function sendReportEmail({ to, target, findings, markdown, ai, seconds, fileCount }) {
  const cfg = emailConfig();
  if (!cfg.enabled) throw new Error("email not configured");
  if (!isValidEmail(to)) throw new Error("invalid recipient");

  const payload = {
    from: cfg.from,
    to: [to],
    subject: subjectFor(target, findings),
    html: renderEmailHtml({ target, findings, ai, seconds, fileCount, appUrl: cfg.appUrl }),
    text: markdown || "",
  };
  if (cfg.bcc) payload.bcc = [cfg.bcc];

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), SEND_TIMEOUT_MS);
  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${cfg.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Resend HTTP ${res.status}: ${body.slice(0, 300)}`);
    }
    return { ok: true };
  } finally {
    clearTimeout(timer);
  }
}
