/**
 * Unit tests for urlShapeFindings() — IP-host and non-standard-port signals.
 * Requirements: 12.1, 12.2, 12.3, 12.4
 *
 * No network calls are made; all fixtures are constructed locally.
 */
import { describe, it, expect } from "vitest";
import { urlShapeFindings } from "../src/checks/urlShape.ts";
import type { CheckContext } from "../src/checks/context.ts";
import type { NormalizedUrl } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Minimal context builder — only the fields urlShapeFindings() actually reads
// ---------------------------------------------------------------------------

function makeTarget(overrides: Partial<NormalizedUrl> & { href: string }): NormalizedUrl {
  const url = new URL(overrides.href);
  const base: NormalizedUrl = {
    href: url.href,
    url,
    protocol: (url.protocol as "http:" | "https:"),
    asciiHost: url.hostname,
    displayHost: url.hostname,
    port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80,
    isIp: false,
    registrableDomain: url.hostname,
    domainLabel: url.hostname.split(".")[0],
    subdomain: "",
    publicSuffix: url.hostname.split(".").slice(1).join(".") || null,
    schemeAssumed: false,
  };
  return { ...base, ...overrides };
}

function makeCtx(target: NormalizedUrl): CheckContext {
  return {
    target,
    now: new Date("2026-09-25T00:00:00Z"),
    offline: true,
    // Cast to satisfy the type — urlShapeFindings() never calls any dep
    deps: {} as CheckContext["deps"],
  };
}

// ---------------------------------------------------------------------------
// Requirement 12.1 — IPv4 literal host → urlShape.ipHost (medium, 25 pts)
// ---------------------------------------------------------------------------

describe("Requirement 12.1 — IPv4 literal host", () => {
  it("produces urlShape.ipHost for a plain IPv4 URL", () => {
    const target = makeTarget({ href: "https://93.184.215.14/", isIp: true, asciiHost: "93.184.215.14", displayHost: "93.184.215.14", port: 443 });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.ipHost");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("medium");
    expect(f!.points).toBe(25);
  });

  it("urlShape.ipHost finding names the IP in the bilingual detail", () => {
    const target = makeTarget({ href: "http://192.168.1.1/", isIp: true, asciiHost: "192.168.1.1", displayHost: "192.168.1.1", port: 80 });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.ipHost")!;
    expect(f.detail.en).toContain("192.168.1.1");
    expect(f.detail.zh).toContain("192.168.1.1");
  });
});

// ---------------------------------------------------------------------------
// Requirement 12.1 — IPv6 literal host → urlShape.ipHost (medium, 25 pts)
// ---------------------------------------------------------------------------

describe("Requirement 12.1 — IPv6 literal host", () => {
  it("produces urlShape.ipHost for an IPv6 URL", () => {
    // new URL strips the brackets from hostname; asciiHost is the bare address
    const target = makeTarget({
      href: "https://[2001:db8::1]/",
      isIp: true,
      asciiHost: "2001:db8::1",
      displayHost: "2001:db8::1",
      port: 443,
    });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.ipHost");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("medium");
    expect(f!.points).toBe(25);
  });
});

// ---------------------------------------------------------------------------
// Requirement 12.2 — Non-standard port → urlShape.unusualPort (low, 10 pts)
// ---------------------------------------------------------------------------

describe("Requirement 12.2 — Non-standard port", () => {
  it("produces urlShape.unusualPort for port 8080", () => {
    const target = makeTarget({ href: "http://example.com:8080/", port: 8080 });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.unusualPort");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("low");
    expect(f!.points).toBe(10);
  });

  it("produces urlShape.unusualPort for port 8443", () => {
    const target = makeTarget({ href: "https://example.com:8443/", port: 8443 });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.unusualPort");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("low");
    expect(f!.points).toBe(10);
  });

  it("finding title includes the port number", () => {
    const target = makeTarget({ href: "http://example.com:9000/", port: 9000 });
    const findings = urlShapeFindings(makeCtx(target));
    const f = findings.find((x) => x.id === "urlShape.unusualPort")!;
    expect(f.title.en).toContain("9000");
    expect(f.title.zh).toContain("9000");
  });
});

// ---------------------------------------------------------------------------
// Requirement 12.3 — IP literal AND non-standard port → both findings
// ---------------------------------------------------------------------------

describe("Requirement 12.3 — IP literal with non-standard port emits both findings", () => {
  it("emits urlShape.ipHost AND urlShape.unusualPort", () => {
    const target = makeTarget({
      href: "http://10.0.0.1:8080/",
      isIp: true,
      asciiHost: "10.0.0.1",
      displayHost: "10.0.0.1",
      port: 8080,
    });
    const findings = urlShapeFindings(makeCtx(target));
    const ids = findings.map((f) => f.id);
    expect(ids).toContain("urlShape.ipHost");
    expect(ids).toContain("urlShape.unusualPort");
  });

  it("the two findings are independent — they each contribute their own points", () => {
    const target = makeTarget({
      href: "http://10.0.0.1:9999/",
      isIp: true,
      asciiHost: "10.0.0.1",
      displayHost: "10.0.0.1",
      port: 9999,
    });
    const findings = urlShapeFindings(makeCtx(target));
    const ipF = findings.find((f) => f.id === "urlShape.ipHost")!;
    const portF = findings.find((f) => f.id === "urlShape.unusualPort")!;
    expect(ipF.points).toBe(25);
    expect(portF.points).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Requirement 12.4 — Normal domain on standard ports → no false positives
// ---------------------------------------------------------------------------

describe("Requirement 12.4 — No false positives on normal domain + standard ports", () => {
  it("does NOT emit urlShape.ipHost or urlShape.unusualPort for domain on port 443", () => {
    const target = makeTarget({ href: "https://example.com/", port: 443 });
    const findings = urlShapeFindings(makeCtx(target));
    const ids = findings.map((f) => f.id);
    expect(ids).not.toContain("urlShape.ipHost");
    expect(ids).not.toContain("urlShape.unusualPort");
  });

  it("does NOT emit urlShape.ipHost or urlShape.unusualPort for domain on port 80", () => {
    const target = makeTarget({ href: "http://example.com/", port: 80 });
    const findings = urlShapeFindings(makeCtx(target));
    const ids = findings.map((f) => f.id);
    expect(ids).not.toContain("urlShape.ipHost");
    expect(ids).not.toContain("urlShape.unusualPort");
  });

  it("does NOT emit urlShape.ipHost for a hostname that merely looks numeric (e.g. 1234.example.com)", () => {
    const target = makeTarget({ href: "https://1234.example.com/", isIp: false, port: 443 });
    const findings = urlShapeFindings(makeCtx(target));
    const ids = findings.map((f) => f.id);
    expect(ids).not.toContain("urlShape.ipHost");
  });
});
