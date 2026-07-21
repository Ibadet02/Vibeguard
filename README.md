# VibeGuard

**Security scans for AI-built apps.** Point it at an app someone built with AI (Lovable, Bolt, v0, Cursor, Replit, Claude Code…) and it reports the security holes in plain English, before someone else finds them.

Status: **validation stage** (landing page + concierge, no product built yet).

---

## Why this idea

Picked over ~10 alternatives because it survives the key test: *"what does this have besides AI reading a file?"*

- **Moat beyond AI:** integrates into the dev workflow (GitHub / every deploy), combines AI with real security scanners, and reaches builders who'd never think to prompt ChatGPT for a security audit.
- **Founder fit:** solo-buildable, low starting cost, and the founder is the customer (understands the pain, can reach the community for free).
- **Rising market:** the number of non-technical people shipping AI-built apps is growing fast.

**Biggest risk to validate:** this is "insurance," not a painkiller, do builders worry enough to *pay* before getting burned? The free-scan offer is designed to convert that fear into action and test exactly this.

## The product (once validated)

`ingest repo → real security scanners + AI analysis → plain-English report + fixes → (later) auto-fix + continuous re-scan on every deploy`

The moat compounds: scanning many AI-built apps builds a dataset of which vulnerabilities each AI tool tends to produce, detection nobody else has.

---

## This repo

| File | What it is |
|---|---|
| `index.html` | The landing page, self-contained (inline CSS/JS), form-capture wired for Netlify Forms. |
| `outreach.md` | Where to find buyers + ready-to-post messages and DMs. |
| `concierge-playbook.md` | How to deliver a real security scan by hand for early signups. |

**🟢 LIVE:** https://vibeguard-6809.netlify.app  ·  Admin: https://app.netlify.com/projects/vibeguard-6809
Forms (`vg-repo`, `vg-email`) are detected and capturing. Enable an email alert: Netlify → Forms → Notifications.

## Deploy (free, ~10 min)

1. Sign up at [netlify.com](https://netlify.com).
2. Drag this folder onto the Netlify "Sites" area → instant deploy to a `*.netlify.app` URL.
3. Site config → Forms → enable. The `vg-repo` and `vg-email` forms capture every signup.
4. Test the form, confirm it lands in Netlify → Forms.

Buy a custom domain later, only if signal is good.

---

## Validation plan (1-week test)

1. ✅ Landing page
2. ✅ Deploy live + capture emails, https://vibeguard-6809.netlify.app
3. ✅ **Concierge playbook** written, `concierge-playbook.md`
4. ✅ **Outreach kit** written, `outreach.md`
5. ⬜ **Post + DM** in the communities → drive first ~50 visitors
6. ⬜ **Deliver free scans** by hand → ask "would you pay?"

**Go/no-go signal:** several people request scans **and** at least one says "I'd pay to have this run automatically on every deploy." → build. Crickets → adjust or pivot to the next finalist (dental EOB posting, freight rate-confirmations).
