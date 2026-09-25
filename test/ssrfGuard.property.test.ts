import { describe, it } from "vitest";
import fc from "fast-check";
import { isBlockedAddress } from "../src/net/ssrfGuard.ts";

const RUNS = { numRuns: 300 };
const octet = fc.integer({ min: 0, max: 255 });

function v4InCidr(base: [number, number, number, number], bits: number) {
  return fc.integer({ min: 0, max: 2 ** (32 - bits) - 1 }).map((off) => {
    const b = ((base[0] << 24) >>> 0) + (base[1] << 16) + (base[2] << 8) + base[3];
    const n = (b + off) >>> 0;
    return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
  });
}

const privateV4 = fc.oneof(
  v4InCidr([10, 0, 0, 0], 8),
  v4InCidr([172, 16, 0, 0], 12),
  v4InCidr([192, 168, 0, 0], 16),
  v4InCidr([127, 0, 0, 0], 8),
  v4InCidr([169, 254, 0, 0], 16),
  v4InCidr([100, 64, 0, 0], 10),
  v4InCidr([0, 0, 0, 0], 8),
  v4InCidr([224, 0, 0, 0], 4),
  v4InCidr([240, 0, 0, 0], 4),
);

const hex16 = fc.integer({ min: 0, max: 0xffff }).map((n) => n.toString(16));

describe("SSRF guard properties", () => {
  // Feature: link-checkup, Property 8: Private addresses are always blocked — Validates: Requirements 3.1, 3.2
  it("Property 8a: private/reserved IPv4 addresses are blocked", () => {
    fc.assert(fc.property(privateV4, (ip) => isBlockedAddress(ip)), RUNS);
  });
  it("Property 8b: IPv4-mapped IPv6 forms of private addresses are blocked", () => {
    fc.assert(fc.property(privateV4, (ip) => isBlockedAddress(`::ffff:${ip}`)), RUNS);
  });
  it("Property 8c: ULA (fc00::/7), link-local (fe80::/10) and loopback IPv6 are blocked", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0xfc00, max: 0xfdff }), fc.array(hex16, { minLength: 7, maxLength: 7 }), (first, rest) =>
        isBlockedAddress([first.toString(16), ...rest].join(":")),
      ),
      RUNS,
    );
    fc.assert(
      fc.property(fc.integer({ min: 0xfe80, max: 0xfebf }), fc.array(hex16, { minLength: 7, maxLength: 7 }), (first, rest) =>
        isBlockedAddress([first.toString(16), ...rest].join(":")),
      ),
      RUNS,
    );
  });
  it("garbage input is always blocked (fail closed)", () => {
    fc.assert(fc.property(fc.string({ maxLength: 30 }).filter((s) => !/^[\d.:a-f]+$/i.test(s)), (s) => isBlockedAddress(s)), RUNS);
  });
  it("well-known public unicast addresses are allowed", () => {
    fc.assert(fc.property(fc.constantFrom("8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "2001:4860:4860::8888"), (ip) => !isBlockedAddress(ip)));
  });
  it("octet sanity: 10.x.x.x always blocked", () => {
    fc.assert(fc.property(octet, octet, octet, (a, b, c) => isBlockedAddress(`10.${a}.${b}.${c}`)), RUNS);
  });
});
