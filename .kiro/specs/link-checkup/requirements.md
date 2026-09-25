# Requirements Document

## Introduction

Link Checkup (可疑链接体检) lets a person paste a suspicious URL and receive a risk assessment **without the
page ever being opened**: no browser rendering, no JavaScript execution, no downloads. It combines free,
keyless signals — domain registration age (RDAP), DNS resolution (DNS-over-HTTPS), the redirect chain
(HEAD-only), the TLS certificate (bare handshake), lookalike/typosquat analysis against popular brands (local)
and public blocklists (URLhaus, Phishing Army) — into a 0–100 score, per-check findings and a one-sentence
verdict in English and Simplified Chinese. The same engine is exposed as a web UI, a CLI and an MCP server
so that an assistant (e.g. the `link-triage` Kiro custom agent) can screen links on someone's behalf.

## Glossary

- **Checkup**: one full assessment of one URL.
- **Target**: the host named in the submitted URL (or any host in its redirect chain).
- **Finding**: a single named signal with severity, points and bilingual text.
- **Registrable domain**: the public-suffix-aware domain a person can register (e.g. `example.co.uk`).
- **Public address**: an IP address whose range is global unicast (not loopback, private, link-local, CGNAT,
  multicast, reserved or an IPv6 form embedding such an IPv4 address).
- **Brand list**: the curated list of official domains in `src/checks/brands.ts`.

## Requirements

### Requirement 1: Accept and normalise input safely

**User Story:** As a person who received a suspicious link, I want to paste it as-is (even without `https://`,
with whitespace or in mixed case), so that I don't have to clean it up before checking it.

#### Acceptance Criteria

1. WHEN the user submits text THE System SHALL trim whitespace and, if no scheme is present, assume `http://` for analysis.
2. IF the submitted scheme is not `http` or `https` (e.g. `javascript:`, `data:`, `file:`) THEN THE System SHALL reject the input with a bilingual error and SHALL NOT perform any network activity.
3. IF the input is longer than 2048 characters or has no valid host THEN THE System SHALL reject it with a bilingual error.
4. THE System SHALL lower-case the host, convert internationalised hosts to their ASCII (punycode) form for network use and keep the Unicode form for display.
5. WHEN the same input is normalised twice THE System SHALL produce the identical result (idempotence).

### Requirement 2: Never open the page

**User Story:** As a cautious user, I want assurance the tool never loads the page, so that checking a link cannot itself infect my device or leak my session.

#### Acceptance Criteria

1. THE System SHALL NOT execute JavaScript, render HTML, download files or store any response body from a Target.
2. WHEN contacting a Target over HTTP THE System SHALL use `HEAD`, and only if the Target answers 405 or 501 SHALL fall back to `GET` with `Range: bytes=0-0`, closing the connection as soon as headers are received.
3. THE System SHALL contact Targets only on ports 80 and 443; a URL using any other port SHALL produce a finding and SHALL NOT be contacted.
4. THE System SHALL apply a per-request timeout of at most 6 seconds and an overall checkup budget of at most 20 seconds.

### Requirement 3: SSRF protection

**User Story:** As the operator of a hosted instance, I want the checker to be unable to reach internal networks, so that it cannot be abused to probe private infrastructure.

#### Acceptance Criteria

1. WHEN a Target hostname resolves to any address that is not a Public address THE System SHALL refuse to connect and SHALL report a finding.
2. IF the Target host is an IP literal THEN THE System SHALL apply the same address policy before connecting.
3. THE System SHALL pin the vetted address for the connection so that a second DNS answer (DNS rebinding) cannot redirect the connection.
4. WHEN a redirect points to a non-public address, a non-http(s) scheme or a disallowed port THE System SHALL stop following the chain and report a finding.

### Requirement 4: Redirect chain

**User Story:** As a user, I want to see where a link really leads, so that shorteners and cloaking chains cannot hide the final destination.

#### Acceptance Criteria

1. WHEN the Target responds with a 3xx status and a `Location` header THE System SHALL resolve it relative to the current URL and follow it, up to 8 hops.
2. THE System SHALL record for every hop the URL, status code and elapsed time.
3. IF the chain exceeds 8 hops or loops THEN THE System SHALL stop and report a finding.
4. WHEN the final URL's registrable domain differs from the submitted one THE System SHALL run the lookalike and blocklist checks against the final URL as well.
5. WHEN a hop downgrades from `https` to `http` THE System SHALL report a finding.

### Requirement 5: Domain age and registrar (RDAP)

**User Story:** As a user, I want to know how old the domain is, so that I can spot throw-away domains registered days ago.

#### Acceptance Criteria

1. WHEN the host has a registrable domain THE System SHALL query RDAP (`https://rdap.org/domain/<domain>`) and extract the registration date, expiry date and registrar name.
2. IF the domain was registered less than 30 days ago THEN THE System SHALL add a high-severity finding; IF less than 180 days ago THEN a medium-severity finding.
3. IF RDAP is unavailable, times out or does not cover the TLD THEN THE System SHALL report the check as `error`/`skipped` with 0 points.

### Requirement 6: DNS resolution

**User Story:** As a user, I want to know whether the domain even resolves, so that dead or parked phishing domains are recognisable.

#### Acceptance Criteria

1. THE System SHALL resolve A and AAAA records via DNS-over-HTTPS (Cloudflare, falling back to Google).
2. IF the domain does not exist (NXDOMAIN) THEN THE System SHALL add a medium-severity finding.
3. IF any resolved address is not a Public address THEN THE System SHALL add a finding.

### Requirement 7: TLS certificate

**User Story:** As a user, I want to know who issued the site's certificate and how new it is, so that I can spot invalid or freshly minted certificates.

#### Acceptance Criteria

1. WHEN the final URL uses `https` THE System SHALL perform a TLS handshake (SNI = host) without sending an HTTP request and record issuer, subject, validity dates and whether the chain is trusted.
2. IF the certificate is untrusted, expired or does not match the host THEN THE System SHALL add a high-severity finding.
3. IF the certificate was issued less than 7 days ago THEN THE System SHALL add a low-severity finding.
4. IF the final URL uses plain `http` THEN THE System SHALL add a low-severity finding.

### Requirement 8: Lookalike / typosquat detection

**User Story:** As a user, I want the tool to notice when a domain only *looks* like a brand I trust, so that I am not fooled by `paypa1` or a Cyrillic `а`.

#### Acceptance Criteria

1. WHEN the registrable domain equals, or the host is a subdomain of, an official domain in the Brand list THE System SHALL NOT add any lookalike finding.
2. WHEN the domain label's confusable skeleton equals a brand label's skeleton but the label differs THE System SHALL add a high-severity homoglyph finding naming the brand.
3. WHEN the Damerau–Levenshtein distance between the label and a brand label (length ≥ 5) is 1 — or 2 for brand labels of length ≥ 9 — THE System SHALL add a high-severity typosquat finding.
4. WHEN the label contains a brand label (length ≥ 5) plus other words (e.g. `paypal-secure-login`) THE System SHALL add a combosquat finding.
5. WHEN an official brand domain appears inside the subdomain part of a different registrable domain (e.g. `paypal.com.verify.example`) THE System SHALL add a high-severity finding.
6. WHEN the host contains punycode labels that decode to mixed scripts THE System SHALL add a finding and show the decoded form.
7. The lookalike check SHALL run entirely offline.

### Requirement 9: Public blocklists

**User Story:** As a user, I want to know if a link is already known to be malicious, so that known threats are flagged immediately.

#### Acceptance Criteria

1. THE System SHALL use only keyless public feeds: URLhaus "online URLs" text feed and the Phishing Army domain blocklist.
2. THE System SHALL download each feed at most once per hour, enforce a size cap and cache it locally.
3. WHEN the exact URL, its host, or any parent domain of the host (down to the registrable domain) is listed THE System SHALL add a critical finding.
4. IF a feed cannot be downloaded THEN THE System SHALL mark the check `error` with 0 points and continue.

### Requirement 10: Score and explanation

**User Story:** As a non-technical user, I want a single number and one plain sentence, so that I know what to do without reading every detail.

#### Acceptance Criteria

1. THE System SHALL compute the score as the sum of finding points, clamped to 0–100.
2. WHEN any finding has severity `critical` THE System SHALL report a score of at least 90.
3. THE System SHALL map scores to levels: `low` 0–24, `medium` 25–59, `high` 60–100.
4. Adding a finding SHALL never decrease the score (monotonicity).
5. THE System SHALL produce exactly one sentence in English and one in Simplified Chinese that states the level, the score and the strongest reasons, and an action ("don't open", "be careful", "no red flags found").

### Requirement 11: Interfaces

**User Story:** As a user or an assistant, I want to use the checker from a browser, a terminal or an AI agent, so that it fits into how links reach me.

#### Acceptance Criteria

1. THE System SHALL serve a bilingual (English primary, 简体中文 toggle) web UI and a JSON API `POST /api/check` from one command (`npm start`).
2. THE System SHALL provide a CLI `npm run check -- <url> [--json] [--offline]`.
3. THE System SHALL provide an MCP stdio server exposing `check_url` and `check_lookalike` tools.
4. THE API SHALL rate-limit each client to 30 checkups per minute and reject bodies over 8 KB.
