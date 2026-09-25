---
inclusion: always
---

# Tech stack & conventions

## Stack
- **Runtime:** Node.js ≥ 20, ESM only (`"type": "module"`), TypeScript executed directly with `tsx`
  (no build step — `npm start` is the one command).
- **Server:** plain `node:http` (no framework) serving `public/` and `POST /api/check`.
- **Frontend:** a single static page (`public/index.html` + `app.js` + `styles.css`), vanilla JS, no bundler.
  All UI strings live in `public/i18n.js` with `en` and `zh` keys.
- **Libraries (keep this list short):**
  - `tldts` — public-suffix aware domain parsing (registrable domain, subdomain).
  - `ipaddr.js` — IP range classification for the SSRF guard.
  - `@modelcontextprotocol/sdk` + `zod` — the stdio MCP server.
- **Tests:** `vitest` for unit tests, `fast-check` for property-based tests (Kiro Lesson 4).
  `npm test` must pass before every commit; `npm run typecheck` must be clean.

## Hard rules
1. **All outbound requests to user-supplied hosts go through `src/net/safeRequest.ts`.**
   Never call `fetch()`, `http.request()` or `tls.connect()` on a user-supplied host anywhere else.
   Fixed, trusted endpoints (rdap.org, cloudflare-dns.com, dns.google, urlhaus.abuse.ch, phishing.army)
   may use `fetchLimited()` from `src/net/limitedFetch.ts`.
2. Every network call has a timeout (default 6 s) and a byte cap. Never read a target's response body.
3. Checks are pure-ish modules that return `CheckResult` — they never throw; failures become
   `status: "error"` with an explanation and **zero** points (unknown ≠ dangerous).
4. Scoring lives only in `src/scoring.ts` and must stay a pure function of the findings list
   (monotonic, clamped to 0–100, critical findings force ≥ 90). Property tests guard this.
5. Findings carry bilingual text: `{ en: string; zh: string }`. Never ship an English-only finding.
6. No secrets, no API keys, no telemetry.

## Style
- Named exports, no default exports. Small functions, explicit return types on exported functions.
- `camelCase` for functions/vars, `PascalCase` for types, `kebab-case` for file names in `public/`,
  `camelCase.ts` for source files.
- Prefer `node:` built-ins over dependencies.

## Commands
- `npm start` — web UI on http://localhost:8787
- `npm run check -- <url> [--json] [--offline]` — CLI
- `npm run mcp` — stdio MCP server (used by `.kiro/settings/mcp.json`)
- `npm test` / `npm run typecheck`
