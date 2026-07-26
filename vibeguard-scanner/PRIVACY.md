# Privacy notice

Last updated: 2026-07-25

VibeGuard is a security scanner for public code repositories. This page explains what happens to your data when you run a scan. Plain English, no tricks.

## What we collect

- **The repository URL you submit.** We use it to clone the repo and run the scan. It may appear in server logs.
- **Your IP address.** Held in memory only, used for rate limiting. Not written to a database.
- **Your email address, only if you choose to enter it** to have the report emailed to you (see "If you give us your email" below).
- **Scan results.** Kept in server memory for about 15 minutes so your browser can fetch them, then discarded. We do not keep a history of reports.

We do not use accounts, cookies, or analytics trackers. We do not sell or share any of the above.

## What happens to your code

- We **shallow-clone** the repository to a temporary folder on our server.
- The scan runs against that copy.
- The clone is **deleted immediately after the scan finishes**, whether it succeeds or fails. Nothing is kept.

## The AI review sends code to a third party

The deep review is powered by a third-party AI provider. During the scan, portions of your repository (file listings and file contents the AI chooses to read) are sent to that provider so it can reason about your code. This means:

- Your code leaves our server for the duration of the scan.
- The provider processes it under their own terms. We do not use your code to train models, and we choose providers whose API terms state the same, but we cannot make guarantees on a third party's behalf.
- **Only scan public repositories, and never scan code containing secrets you cannot rotate.** If the scanner finds a live credential, treat it as exposed and rotate it.

The pattern-check layer runs entirely on our server and sends nothing to the AI provider.

## The live database check (optional, off by default)

You can ask VibeGuard to check your live Supabase project for tables that anyone on the internet can read. This is **switched off unless you turn it on**, and turning it on requires confirming that you own the app or have permission to test it. We record that confirmation, with your IP and the time, because this feature sends requests to a real database and we need a record of who authorised it.

If you turn it on:

- We use only your **anon (public) key** — the one that already ships inside your app's JavaScript, visible to anyone who opens your site. You may paste it, or we take it from your repo. **Never give us a service_role or secret key**, and we refuse them if you try.
- **We only read, and we never read your data.** To show a table is exposed we ask the database for its row *count*, which comes back in a response header with no rows attached. Column *names* come from the API's own public description. At no point do we fetch, see, log, or store the contents of any row. No customer of yours has their personal data pass through VibeGuard.
- **We never write.** No inserts, updates or deletes, not even to test whether they would be allowed. The report tells you writes were not tested.
- We hold the key in memory for the scan and discard it. It is never written to disk and never appears in a report.
- Only hosted `*.supabase.co` projects can be checked.

Because these requests come from our servers, they may appear in your Supabase logs as traffic from an unfamiliar IP. That's us, at your request.

## If you give us your email (optional)

Emailing yourself the report is optional. If you enter an email address:

- We use it to send you that scan's report, and it's passed to our email provider (Resend) to deliver the message. That's the only reason it leaves our server.
- Because we're early, we might email you once or twice to ask how the scan went or to tell you about VibeGuard. No spam, and you can reply "stop" any time and we'll remove you.
- We don't sell your email or share it beyond the email provider needed to deliver the message.

Leave the field blank and no email is collected at all.

## Your rights

Because we keep essentially nothing, there is little to delete: clones are removed after each scan and results expire within minutes. If you have a question or concern, contact us and we will do our best to help.

## Changes

If this notice changes in a way that matters, we will update the date at the top.
