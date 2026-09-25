import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { followRedirects, redirectFindings, MAX_HOPS, type Transport } from "../src/checks/redirects.ts";
import { BlockedAddressError } from "../src/net/ssrfGuard.ts";

function fakeTransport(map: Record<string, { status: number; location?: string } | Error>): Transport & { calls: string[] } {
  const calls: string[] = [];
  const t = (async (url: string) => {
    calls.push(url);
    const r = map[url];
    if (r instanceof Error) throw r;
    if (!r) return { status: 200, method: "HEAD" as const };
    return { ...r, method: "HEAD" as const };
  }) as Transport & { calls: string[] };
  t.calls = calls;
  return t;
}

describe("followRedirects", () => {
  it("follows relative and absolute Location headers and records hops", async () => {
    const t = fakeTransport({
      "http://short.example/abc": { status: 301, location: "https://short.example/abc" },
      "https://short.example/abc": { status: 302, location: "/landing?x=1" },
      "https://short.example/landing?x=1": { status: 302, location: "https://final.example/" },
    });
    const chain = await followRedirects("http://short.example/abc", t);
    expect(chain.finalUrl).toBe("https://final.example/");
    expect(chain.hops.map((h) => h.status)).toEqual([301, 302, 302, 200]);
    const ids = redirectFindings("http://short.example/abc", chain).map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["redirects.long", "redirects.crossDomain"]));
  });

  it("detects loops", async () => {
    const t = fakeTransport({ "https://a.example/": { status: 302, location: "https://b.example/" }, "https://b.example/": { status: 302, location: "https://a.example/" } });
    const chain = await followRedirects("https://a.example/", t);
    expect(chain.stoppedReason).toBe("loop");
    expect(redirectFindings("https://a.example/", chain).map((f) => f.id)).toContain("redirects.tooMany");
  });

  it("stops at javascript: / data: targets", async () => {
    const t = fakeTransport({ "https://a.example/": { status: 302, location: "javascript:alert(1)" } });
    const chain = await followRedirects("https://a.example/", t);
    expect(chain.stoppedReason).toBe("badScheme");
    expect(redirectFindings("https://a.example/", chain)[0].id).toBe("redirects.badScheme");
  });

  it("reports redirects into private networks as blocked", async () => {
    const t = fakeTransport({
      "https://a.example/": { status: 302, location: "http://169.254.169.254/latest/meta-data" },
      "http://169.254.169.254/latest/meta-data": new BlockedAddressError("169.254.169.254", "169.254.169.254"),
    });
    const chain = await followRedirects("https://a.example/", t);
    expect(chain.stoppedReason).toBe("blocked");
    const ids = redirectFindings("https://a.example/", chain).map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["redirects.blockedTarget", "redirects.downgrade"]));
  });

  // Feature: link-checkup, Property 10: Redirect following terminates — Validates: Requirements 4.1, 4.3
  it("Property 10: terminates within MAX_HOPS + 1 requests for any redirect graph", async () => {
    const graph = fc.dictionary(
      fc.integer({ min: 0, max: 15 }).map(String),
      fc.oneof(fc.integer({ min: 0, max: 15 }).map((n) => ({ status: 302, to: n })), fc.constant({ status: 200, to: -1 })),
    );
    await fc.assert(
      fc.asyncProperty(graph, async (g) => {
        const t = fakeTransport(
          Object.fromEntries(
            Object.entries(g).map(([k, v]) => [`https://n${k}.example/`, v.to >= 0 ? { status: v.status, location: `https://n${v.to}.example/` } : { status: 200 }]),
          ),
        );
        const chain = await followRedirects("https://n0.example/", t);
        return t.calls.length <= MAX_HOPS + 1 && chain.hops.length <= MAX_HOPS + 1;
      }),
      { numRuns: 300 },
    );
  });
});
