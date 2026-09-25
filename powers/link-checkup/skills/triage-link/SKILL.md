---
name: triage-link
description: Step-by-step procedure for screening a suspicious URL someone forwarded (SMS, email, chat, QR) without opening it, using the link-checkup MCP tools, and writing a bilingual verdict. Use when a user pastes a link and asks whether it is safe.
---

# Triage a forwarded link

1. **Extract** every URL from the message. Refang `hxxp://` → `http://` and `[.]` → `.`. Keep at most 5.
2. **Never open the link.** Do not use browsers, `curl`, `wget` or web-fetch tools on it.
3. For each URL call `check_url` (`lang: "en"`). For a bare domain or brand question, `check_lookalike` is enough.
4. Read the result:
   - `level` high (≥ 60) → tell them not to open it.
   - `level` medium (25–59) → be careful; verify with the sender through another channel.
   - `level` low → "no red flags found", still not a guarantee.
   - Findings with `points: 0` are context (registrar, certificate issuer). Checks marked `error`/`skipped` were **not checked**.
5. If `finalUrl` differs from the input, mention where the link really leads.
6. Answer English first, then 简体中文: verdict line with 🔴/🟠/🟢 + score, the one-sentence explanation, 2–4 reasons in plain words, and one concrete action.

## Examples (synthetic, safe to use in demos)
| Input | Expected |
|---|---|
| `http://paypa1.example/login` | high — homoglyph of paypal.com |
| `https://www.paypal.com.account-verify.example/signin` | high — brand in subdomain |
| `hxxps://secure-paypal-login[.]test` | medium/high — combosquat |
| `https://example.com` | low — no red flags |
