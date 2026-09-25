export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Level = "low" | "medium" | "high";
export type Lang = "en" | "zh";

export interface Bilingual {
  en: string;
  zh: string;
}

export type CheckId = "urlShape" | "lookalike" | "rdap" | "dns" | "redirects" | "tls" | "blocklist";

export interface Finding {
  /** Stable id: `<check>.<reason>` */
  id: string;
  check: CheckId;
  severity: Severity;
  /** Contribution to the 0–100 score (non-negative). */
  points: number;
  title: Bilingual;
  detail: Bilingual;
}

export type CheckStatus = "ok" | "warn" | "error" | "skipped";

export interface CheckResult {
  check: CheckId;
  status: CheckStatus;
  findings: Finding[];
  /** Check-specific structured data (registrar, hops, certificate, …). */
  data?: unknown;
  durationMs: number;
}

export interface NormalizedUrl {
  /** Full URL with ASCII (punycode) host. */
  href: string;
  url: URL;
  protocol: "http:" | "https:";
  /** ASCII / punycode host, lower-case, no trailing dot, IPv6 without brackets. */
  asciiHost: string;
  /** Unicode form for display. */
  displayHost: string;
  port: number;
  isIp: boolean;
  /** Registrable domain (public-suffix aware) or null for IPs / bare TLDs. */
  registrableDomain: string | null;
  /** Registrable domain without the public suffix, e.g. "paypal" for paypal.co.uk */
  domainLabel: string | null;
  /** Subdomain part, e.g. "login.secure" */
  subdomain: string;
  publicSuffix: string | null;
  schemeAssumed: boolean;
}

export interface HopInfo {
  url: string;
  status: number | null;
  location?: string;
  method: "HEAD" | "GET";
  ms: number;
  error?: string;
}

export interface Report {
  input: string;
  normalizedUrl: string;
  displayHost: string;
  finalUrl: string;
  score: number;
  level: Level;
  explanation: Bilingual;
  checks: CheckResult[];
  findings: Finding[];
  checkedAt: string;
  durationMs: number;
  offline: boolean;
  version: string;
}

export function bi(en: string, zh: string): Bilingual {
  return { en, zh };
}
