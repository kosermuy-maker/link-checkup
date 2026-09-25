---
inclusion: always
---

# Product: Link Checkup (可疑链接体检)

## Why it exists
People regularly receive links they are unsure about — an SMS "your parcel is on hold", a DM with a
"login to claim" page, a forwarded QR code. The owner of this project forwards such links to an assistant
to screen them *before* anyone clicks, so that no device, browser session or account is ever exposed.
Link Checkup is that screening step, made repeatable: paste a URL, get a risk verdict without the page
ever being rendered.

## Core promise (never break this)
- **The page is never opened.** No browser rendering, no JavaScript execution, no file downloads,
  no response bodies stored. Network contact with the target is limited to DNS, a TLS handshake and
  `HEAD` (or a zero-byte ranged `GET`) requests to read redirect headers.
- **No paid services, no API keys.** Every data source must be free and usable without an account
  (RDAP, DNS-over-HTTPS, URLhaus text feed, Phishing Army blocklist, local lookalike analysis).
- **Explainable.** Every point added to the score comes from a named finding with a human-readable reason.

## Users
- Non-technical people who want a yes/no-ish answer in one sentence ("Don't open this — it imitates PayPal
  and the domain is 3 days old").
- Helpers / assistants (human or AI) that triage links on someone else's behalf — served by the CLI,
  the MCP server and the `link-triage` Kiro agent.

## Output contract
- A risk score 0–100 and a level: `low` (0–24), `medium` (25–59), `high` (60–100).
- Per-check findings (id, severity, points, bilingual title/detail).
- One plain-language sentence in **English and Simplified Chinese**. English is primary in the UI
  (international judges); 中文 is one click away.

## Non-goals
- Not an antivirus, not a sandbox, not a crawler. We do not claim a link is "safe" — only "no red flags found".
- No user accounts, no history stored server-side.
