import { describe, it, expect } from "vitest";
import { runCheckup, InputError } from "../src/checkup.ts";
import type { CheckDeps } from "../src/checks/context.ts";
import { explain } from "../src/explain.ts";
import { BlockedAddressError } from "../src/net/ssrfGuard.ts";

const NOW = new Date("2026-09-25T00:00:00Z");

/** Fully simulated network: no real request leaves the test. */
function fakeDeps(over: Partial<CheckDeps> = {}): CheckDeps {
  return {
    headRequest: async (url) => {
      if (url === "https://short.example.org/x") return { status: 301, location: "https://paypa1-account.com/verify", method: "HEAD" };
      return { status: 200, method: "HEAD" };
    },
    tlsHandshake: async () => ({ authorized: true, subjectAltNames: [], issuerO: "Test CA", validFrom: "Sep 24 00:00:00 2026 GMT", validTo: "Dec 24 00:00:00 2026 GMT" }),
    fetchText: async (url) => {
      if (url.startsWith("https://rdap.org/")) {
        return { status: 200, url, text: JSON.stringify({ events: [{ eventAction: "registration", eventDate: "2026-09-20T00:00:00Z" }] }) };
      }
      if (url.includes("dns")) return { status: 200, url, text: JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.215.14" }] }) };
      throw new Error("unexpected " + url);
    },
    loadBlocklists: async () => ({ urlhausUrls: new Set(), urlhausHosts: new Set(), phishingDomains: new Set(["listed-phish.example.net"]), fetchedAt: { phishingArmy: NOW.toISOString() }, errors: {} }),
    ...over,
  };
}

describe("runCheckup (simulated network)", () => {
  it("re-checks the final destination of a redirect chain", async () => {
    const r = await runCheckup("https://short.example.org/x", { offline: false, deps: fakeDeps(), now: NOW });
    expect(r.finalUrl).toBe("https://paypa1-account.com/verify");
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["redirects.crossDomain", "rdap.veryNew", "lookalike.combosquat.final"]));
    expect(r.level).toBe("high");
    expect(r.explanation.en).toMatch(/^High risk \(\d+\/100\): .+\.$/);
    expect(r.explanation.zh).toMatch(/^高风险/);
  });

  it("a blocklisted domain is always >= 90", async () => {
    const r = await runCheckup("https://login.listed-phish.example.net/", { offline: false, deps: fakeDeps(), now: NOW });
    expect(r.score).toBeGreaterThanOrEqual(90);
    expect(r.findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("network failures are 0-point unknowns, not dangers", async () => {
    const boom = async () => {
      throw new Error("network down");
    };
    const r = await runCheckup("https://example.org/", {
      offline: false, now: NOW,
      deps: fakeDeps({ fetchText: boom, headRequest: boom, tlsHandshake: boom, loadBlocklists: boom }),
    });
    expect(r.score).toBe(0);
    expect(r.checks.filter((c) => c.status === "error").map((c) => c.check)).toEqual(expect.arrayContaining(["rdap", "dns", "tls", "blocklist"]));
  });

  it("SSRF attempts are reported, not followed", async () => {
    const r = await runCheckup("https://intranet.example.org/", {
      offline: false, now: NOW,
      deps: fakeDeps({ headRequest: async () => { throw new BlockedAddressError("intranet.example.org", "10.0.0.8"); } }),
    });
    expect(r.findings.map((f) => f.id)).toContain("redirects.blockedTarget");
  });

  it("respects the time budget", async () => {
    const slow = () => new Promise<never>(() => {});
    const r = await runCheckup("https://example.org/", { offline: false, now: NOW, budgetMs: 300, deps: fakeDeps({ fetchText: slow, headRequest: slow, loadBlocklists: slow }) });
    expect(r.durationMs).toBeLessThan(2000);
    expect(r.checks.find((c) => c.check === "rdap")?.status).toBe("skipped");
  });

  it("offline mode runs only local checks", async () => {
    const r = await runCheckup("paypa1.example/login", { offline: true, now: NOW });
    expect(r.findings.map((f) => f.id)).toContain("lookalike.homoglyph");
    expect(r.level).toBe("high");
  });

  it("rejects dangerous schemes with a bilingual InputError", async () => {
    await expect(runCheckup("javascript:alert(1)")).rejects.toBeInstanceOf(InputError);
  });
});

describe("explain()", () => {
  it("produces exactly one sentence per language", () => {
    const e = explain(0, "low", [], 7);
    expect(e.en.split(/(?<=[.!?])\s/).length).toBe(1);
    expect(e.zh).toContain("低风险");
  });
});
