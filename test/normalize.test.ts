import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { normalizeInput, refang } from "../src/url/normalize.ts";

describe("normalizeInput", () => {
  it("adds a scheme and lower-cases the host", () => {
    const r = normalizeInput("  WWW.Example.COM/Path?q=1#frag ");
    expect(r.ok && r.value.href).toBe("http://www.example.com/Path?q=1");
    expect(r.ok && r.value.schemeAssumed).toBe(true);
  });
  it("refangs defanged links", () => {
    expect(refang("hxxps://evil[.]example/login")).toBe("https://evil.example/login");
    const r = normalizeInput("hxxp://paypa1[.]example");
    expect(r.ok && r.value.asciiHost).toBe("paypa1.example");
  });
  it.each(["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "ftp://example.com", "vbscript:x"])("rejects %s with no network", (s) => {
    const r = normalizeInput(s);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.zh.length).toBeGreaterThan(0);
  });
  it("rejects empty, over-long and host-less input", () => {
    expect(normalizeInput("").ok).toBe(false);
    expect(normalizeInput("http://" + "a".repeat(2050) + ".com").ok).toBe(false);
    expect(normalizeInput("http://nodot/").ok).toBe(false);
  });
  it("keeps Unicode for display and punycode for the network", () => {
    const r = normalizeInput("https://аpple.example/");
    expect(r.ok && r.value.asciiHost).toBe("xn--pple-43d.example");
    expect(r.ok && r.value.displayHost).toBe("аpple.example");
  });
  it("parses registrable domains with multi-part suffixes", () => {
    const r = normalizeInput("https://login.example.co.uk");
    expect(r.ok && r.value.registrableDomain).toBe("example.co.uk");
    expect(r.ok && r.value.subdomain).toBe("login");
  });
  it("recognises IP hosts (including IPv6 and integer forms)", () => {
    const a = normalizeInput("http://[::1]:8080/");
    expect(a.ok && a.value.isIp && a.value.asciiHost).toBe("::1");
    const b = normalizeInput("http://2130706433/");
    expect(b.ok && b.value.asciiHost).toBe("127.0.0.1");
  });
});

describe("normalizeInput properties", () => {
  // Feature: link-checkup, Property 9: Normalisation is idempotent — Validates: Requirements 1.5
  it("Property 9: normalising an accepted href again yields the same href", () => {
    const label = fc.stringMatching(/^[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?$/);
    const input = fc.record({
      scheme: fc.constantFrom("", "http://", "https://", "HTTPS://"),
      labels: fc.array(label, { minLength: 1, maxLength: 3 }),
      tld: fc.constantFrom("com", "example", "co.uk", "test", "xyz"),
      path: fc.webPath(),
      query: fc.option(fc.webQueryParameters(), { nil: undefined }),
      frag: fc.option(fc.webFragments(), { nil: undefined }),
      upper: fc.boolean(),
    }).map(({ scheme, labels, tld, path, query, frag, upper }) => {
      const host = labels.join(".") + "." + tld;
      return `${scheme}${upper ? host.toUpperCase() : host}${path}${query ? "?" + query : ""}${frag ? "#" + frag : ""}`;
    });
    fc.assert(
      fc.property(input, (raw) => {
        const once = normalizeInput(raw);
        if (!once.ok) return true;
        const twice = normalizeInput(once.value.href);
        return twice.ok && twice.value.href === once.value.href;
      }),
      { numRuns: 300 },
    );
  });
});
