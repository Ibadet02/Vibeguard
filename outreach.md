# VibeGuard: Outreach kit

Goal: get the first ~50 targeted visitors and a handful of free-scan requests. **No ads.** Be genuinely useful first; pitch once, lightly.

Live link to share: **https://vibeguard-6809.netlify.app**

---

## The offer (your one line everywhere)

> "I'll run a free security scan on your AI-built app and send back a plain-English report of what to fix. No catch, I'm just testing an idea."

This works because it's free, low-risk, and gives them something valuable whether or not they ever pay.

## Where your buyers are

**Reddit:** r/vibecoding · r/lovable · r/cursor · r/boltnewbuilders · r/nocode · r/SaaS · r/indiehackers · r/webdev (careful, more expert)
**Discord:** Lovable, Bolt, Cursor community servers (help / show-your-project channels)
**X/Twitter:** #buildinpublic, #vibecoding; reply to people shipping AI-built apps
**Indie Hackers:** the "share your project" and "feedback" areas

## The rules (so you're not "that spammer")

1. Spend a few days just being helpful. Answer questions, no link.
2. Lead with value; mention VibeGuard once, only when relevant.
3. One link per post. Never copy-paste the same text everywhere.
4. When someone shows an app they built → offer a free scan in a friendly reply.

---

## Templates

### A) Value-first community post (Reddit / IH)
**Title:** I've been finding the same 3 security holes in almost every AI-built app

> If you built your app with Lovable / Bolt / Cursor / v0, check these before you share it publicly:
>
> 1. **API keys in the front-end.** Open your site, right-click → Inspect → Sources. If your OpenAI/Stripe key is in there, anyone can take it. Move it to a server/env variable.
> 2. **Database left open.** On Supabase, if Row Level Security is off, any user can read everyone's data. Turn RLS on and add a policy.
> 3. **No login on admin routes.** AI often builds an /admin page with no auth check. Add one.
>
> I kept seeing these so often I started building a little tool that scans for them automatically and explains the fix in plain English. Happy to run it on your app for free if you want, just drop a link or DM me. Either way, check those three. 🙂

### B) Short DM / reply (when someone shows an AI-built app)
> Nice work shipping this! Quick heads-up: apps built with AI tools often ship with hidden security holes (exposed keys, open databases). I'm testing a free tool that scans for exactly that. Want me to run it on yours and send back what to fix? Totally free.

### C) X / Twitter post
> Built something with Lovable/Bolt/Cursor? Before you launch, 3 things AI almost always gets wrong:
> • API keys exposed in the browser
> • database open to everyone
> • admin pages with no login
> I'll scan your app for these free → [link]  #buildinpublic

---

## Track it (simple)
For each week, note: posts made · scan requests · scans delivered · "would you pay?" yeses.
**Go signal:** several scan requests + ≥1 person says "I'd pay to have this run automatically."
