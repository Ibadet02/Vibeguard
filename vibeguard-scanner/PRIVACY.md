# Privacy notice

Last updated: 2026-07-23

VibeGuard is a security scanner for public code repositories. This page explains what happens to your data when you run a scan. Plain English, no tricks.

## What we collect

- **The repository URL you submit.** We use it to clone the repo and run the scan. It may appear in server logs.
- **Your IP address.** Held in memory only, used for rate limiting. Not written to a database.
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

## Your rights

Because we keep essentially nothing, there is little to delete: clones are removed after each scan and results expire within minutes. If you have a question or concern, contact us and we will do our best to help.

## Changes

If this notice changes in a way that matters, we will update the date at the top.
