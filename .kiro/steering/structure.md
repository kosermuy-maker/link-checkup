---
inclusion: always
---

# Project structure

```
src/
  types.ts            Shared types: Finding, CheckResult, Report, Bilingual
  url/normalize.ts    Parse + normalise user input into a safe URL object (no network)
  checks/
    urlShape.ts       Structural red flags (IP host, userinfo "@", http, odd port, deep subdomains, TLD)
    lookalike.ts      Typosquat / homoglyph / punycode / combosquat detection vs brands.ts
    brands.ts         Official brand domains (data only)
    homoglyphs.ts     Confusable-character skeleton map (data + skeleton())
    rdap.ts           Domain age + registrar via rdap.org
    dns.ts            A/AAAA resolution via DNS-over-HTTPS (Cloudflare → Google fallback)
    redirects.ts      Redirect chain via HEAD / zero-byte GET, SSRF-guarded
    tls.ts            Certificate issuer / age / validity via a bare TLS handshake
    blocklist.ts      URLhaus online-URL feed + Phishing Army domain list (cached, keyless)
  net/
    ssrfGuard.ts      isBlockedAddress(), safeLookup() — the only place IP policy lives
    safeRequest.ts    headOnlyRequest(), tlsHandshake() for user-supplied hosts
    limitedFetch.ts   fetchLimited() for fixed trusted endpoints (timeout + byte cap)
  scoring.ts          computeScore(), levelFor() — pure
  explain.ts          One-sentence bilingual verdict
  checkup.ts          Orchestrator: runs checks in parallel, re-checks the final redirect target
  server.ts           HTTP server (static UI + POST /api/check)
  cli.ts              Command-line entry
  mcp/server.ts       MCP stdio server exposing check_url / check_lookalike
public/               Static bilingual UI
test/                 *.test.ts (examples) and *.property.test.ts (fast-check properties)
bin/                  npx entry points (tsx-registered shims)
powers/link-checkup/  Kiro power (plugin.json, mcp.json, skills/) — packaged for reuse
.kiro/                specs, steering, hooks, MCP settings, custom agents, skills
docs/                 Screenshots and extra docs
```

## Adding a new check (the checklist the `update-docs-on-new-check` hook enforces)
1. Create `src/checks/<name>.ts` exporting `async function <name>Check(ctx): Promise<CheckResult>`.
2. Add the id to `CheckId` in `src/types.ts` and register it in `src/checks/index.ts`.
3. Add bilingual labels in `public/i18n.js` (`checks.<id>`).
4. Add tests in `test/<name>.test.ts`; add a property test if the check has an invariant.
5. Update the "Checks" table in `README.md` and the list above.
