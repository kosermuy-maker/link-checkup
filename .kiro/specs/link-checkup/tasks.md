# Implementation Plan

- [ ] 1. Project scaffolding and shared types
  - Create `package.json` (ESM, `tsx`, `vitest`, `fast-check`), `tsconfig.json`, `vitest.config.ts`
  - Define `Finding`, `CheckResult`, `Report`, `Bilingual`, `CheckId` in `src/types.ts`
  - _Requirements: 10.1, 11.1_

- [ ] 2. Input normalisation
  - [ ] 2.1 Implement `normalizeInput()` in `src/url/normalize.ts`
    - Trim, default scheme, reject non-http(s), length and host validation, punycode/Unicode host forms
    - _Requirements: 1.1, 1.2, 1.3, 1.4_
  - [ ]* 2.2 Write property test for normalisation idempotence
    - **Property 9: Normalisation is idempotent**
    - **Validates: Requirements 1.5**

- [ ] 3. SSRF guard and safe networking
  - [ ] 3.1 Implement `isBlockedAddress()`, `safeLookup()` and `assertPublicHost()` in `src/net/ssrfGuard.ts`
    - Allow only global unicast; unwrap IPv4-mapped / NAT64 / 6to4 addresses; block if any answer is private
    - _Requirements: 3.1, 3.2, 3.3_
  - [ ]* 3.2 Write property test for private address blocking
    - **Property 8: Private addresses are always blocked**
    - **Validates: Requirements 3.1, 3.2**
  - [ ] 3.3 Implement `headOnlyRequest()` and `tlsHandshake()` in `src/net/safeRequest.ts`
    - HEAD, 405/501 → ranged GET, destroy on headers, ports 80/443 only, 6 s timeout, pinned lookup
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.3_
  - [ ] 3.4 Implement `fetchLimited()` for trusted endpoints (timeout + byte cap)
    - _Requirements: 2.4, 9.2_

- [ ] 4. Offline checks
  - [ ] 4.1 Implement `urlShapeCheck()` (IP host, userinfo, http, port, depth, TLD, length, shorteners)
    - _Requirements: 2.3, 7.4_
  - [ ] 4.2 Build `brands.ts` and `homoglyphs.ts` (confusable skeleton map)
    - _Requirements: 8.1, 8.2_
  - [ ] 4.3 Implement `analyzeLookalike()` with skeleton, Damerau–Levenshtein, combosquat, brand-in-subdomain, mixed-script punycode
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_
  - [ ]* 4.4 Write property test: no false positives on official domains
    - **Property 5: No false positives on official domains**
    - **Validates: Requirements 8.1**
  - [ ]* 4.5 Write property test: homoglyph substitution is detected
    - **Property 6: Homoglyph substitution is detected**
    - **Validates: Requirements 8.2**
  - [ ]* 4.6 Write property test: edit-distance metric sanity
    - **Property 7: Edit-distance metric sanity**
    - **Validates: Requirements 8.3**

- [ ] 5. Network checks (all dependencies injectable for tests)
  - [ ] 5.1 `rdapCheck()` + pure `parseRdap()` (registration/expiry/registrar, age thresholds 30/180 d)
    - _Requirements: 5.1, 5.2, 5.3_
  - [ ] 5.2 `dnsCheck()` via DoH (Cloudflare → Google), NXDOMAIN and private-answer findings
    - _Requirements: 6.1, 6.2, 6.3_
  - [ ] 5.3 `followRedirects()` + `redirectsCheck()` (≤ 8 hops, loop detection, https→http downgrade, guarded hops)
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 3.4_
  - [ ]* 5.4 Write property test: redirect following terminates
    - **Property 10: Redirect following terminates**
    - **Validates: Requirements 4.1, 4.3**
  - [ ] 5.5 `tlsCheck()` + pure `assessCertificate()` (trust, expiry, hostname, < 7 days)
    - _Requirements: 7.1, 7.2, 7.3_
  - [ ] 5.6 `blocklistCheck()` with URLhaus text feed + Phishing Army, 1 h cache, size cap, parent-domain match
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [ ] 6. Scoring and explanation
  - [ ] 6.1 Implement pure `computeScore()` / `levelFor()` in `src/scoring.ts`
    - _Requirements: 10.1, 10.2, 10.3, 10.4_
  - [ ]* 6.2 Write property tests for score bounds, monotonicity, critical dominance and level partition
    - **Property 1: Score is bounded** — **Validates: Requirements 10.1**
    - **Property 2: Score is monotonic** — **Validates: Requirements 10.4**
    - **Property 3: Critical findings dominate** — **Validates: Requirements 10.2, 10.3**
    - **Property 4: Level partition** — **Validates: Requirements 10.3**
  - [ ] 6.3 Implement bilingual one-sentence `explain()`
    - _Requirements: 10.5_

- [ ] 7. Orchestrator
  - [ ] 7.1 `runCheckup()` with parallel checks, 20 s budget, `safeCheck()` wrapper, final-URL re-check
    - _Requirements: 2.4, 4.4_
  - [ ] 7.2 End-to-end offline test of `runCheckup()` with injected fakes
    - _Requirements: 10.1, 10.5_

- [ ] 8. Interfaces
  - [ ] 8.1 HTTP server: static UI + `POST /api/check`, 8 KB body limit, 30/min rate limit
    - _Requirements: 11.1, 11.4_
  - [ ] 8.2 Bilingual UI (English primary, 中文 toggle), score gauge, per-check cards, redirect chain
    - _Requirements: 11.1, 10.5_
  - [ ] 8.3 CLI (`--json`, `--offline`, `--lang zh`)
    - _Requirements: 11.2_
  - [ ] 8.4 MCP stdio server with `check_url` and `check_lookalike`; register in `.kiro/settings/mcp.json`
    - _Requirements: 11.3_

- [ ] 9. Kiro integration and docs
  - [ ] 9.1 `link-triage` custom agent in `.kiro/agents/` using the MCP server
  - [ ] 9.2 Package the checker as a Kiro power in `powers/link-checkup/`
  - [ ] 9.3 README with lesson → file map, screenshots, MIT license
