import { describe, it } from "vitest";
import fc from "fast-check";
import { domainToASCII } from "node:url";
import { analyzeLookalike, damerauLevenshtein } from "../src/checks/lookalike.ts";
import { BRANDS } from "../src/checks/brands.ts";
import { confusablesFor, skeleton } from "../src/checks/homoglyphs.ts";
import { labelArb } from "./helpers/arbitraries.ts";

const RUNS = { numRuns: 300 };
const officialDomains = BRANDS.flatMap((b) => b.domains);

describe("lookalike properties", () => {
  // Feature: link-checkup, Property 5: No false positives on official domains — Validates: Requirements 8.1
  it("Property 5: official brand domains and their subdomains are never flagged", () => {
    fc.assert(
      fc.property(fc.constantFrom(...officialDomains), fc.array(labelArb, { maxLength: 3 }), (domain, subs) => {
        const host = [...subs, domain].join(".");
        return analyzeLookalike(host).findings.length === 0;
      }),
      RUNS,
    );
  });

  // Feature: link-checkup, Property 6: Homoglyph substitution is detected — Validates: Requirements 8.2
  it("Property 6: substituting one character with a confusable is detected for that brand", () => {
    const brands = BRANDS.filter((b) => b.label.length >= 5);
    const cases = fc
      .constantFrom(...brands)
      .chain((b) => fc.record({ brand: fc.constant(b), pos: fc.nat(b.label.length - 1), pick: fc.nat(1000), tld: fc.constantFrom("com", "net", "example", "top", "xyz") }))
      .filter(({ brand, pos }) => confusablesFor(brand.label[pos]).some((c) => domainToASCII(`${c}x.test`) !== ""));
    fc.assert(
      fc.property(cases, ({ brand, pos, pick, tld }) => {
        const options = confusablesFor(brand.label[pos]).filter((c) => domainToASCII(`${c}x.test`) !== "");
        const glyph = options[pick % options.length];
        const label = brand.label.slice(0, pos) + glyph + brand.label.slice(pos + 1);
        const host = `${label}.${tld}`;
        const a = analyzeLookalike(host);
        if (a.official) return true; // IDNA mapped it back onto an official domain — not a lookalike by definition
        // Expect the specific homoglyph finding for this brand (or, if IDNA folded the glyph back to ASCII,
        // the "brand name on an unofficial domain" finding).
        return a.findings.some(
          (f) =>
            (f.id === "lookalike.homoglyph" && f.title.en.includes(brand.domains[0])) ||
            (f.id === "lookalike.unofficialDomain" && f.title.en.includes(brand.name)),
        );
      }),
      RUNS,
    );
  });

  // Feature: link-checkup, Property 7: Edit-distance metric sanity — Validates: Requirements 8.3
  it("Property 7: identity, symmetry and adjacent transposition", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 15 }), fc.string({ maxLength: 15 }), (a, b) => {
        return damerauLevenshtein(a, a) === 0 && damerauLevenshtein(a, b) === damerauLevenshtein(b, a);
      }),
      RUNS,
    );
    fc.assert(
      fc.property(fc.string({ minLength: 2, maxLength: 15 }), fc.nat(), (s, i) => {
        const chars = [...s];
        const k = i % (chars.length - 1);
        [chars[k], chars[k + 1]] = [chars[k + 1], chars[k]];
        return damerauLevenshtein(s, chars.join("")) <= 1;
      }),
      RUNS,
    );
  });

  it("skeleton is idempotent", () => {
    fc.assert(fc.property(fc.string({ maxLength: 20 }), (s) => skeleton(skeleton(s)) === skeleton(s)), RUNS);
  });
});
