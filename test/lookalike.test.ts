import { describe, it, expect } from "vitest";
import { analyzeLookalike, damerauLevenshtein, scriptsIn } from "../src/checks/lookalike.ts";

const ids = (host: string) => analyzeLookalike(host).findings.map((f) => f.id);

describe("lookalike examples (synthetic domains on reserved TLDs)", () => {
  it("flags digit-for-letter homoglyphs", () => {
    expect(ids("paypa1.example")).toContain("lookalike.homoglyph");
    expect(ids("rnicrosoft.example")).toContain("lookalike.homoglyph");
  });
  it("flags Cyrillic lookalikes and mixed scripts (punycode input too)", () => {
    expect(ids("аpple.example")).toEqual(expect.arrayContaining(["lookalike.homoglyph", "lookalike.mixedScript"]));
    expect(ids("xn--pple-43d.example")).toContain("lookalike.homoglyph");
  });
  it("flags typosquats", () => {
    expect(ids("githbu.example")).toContain("lookalike.typosquat");
    expect(ids("wellsfagro.example")).toContain("lookalike.typosquat");
  });
  it("flags combosquats and brand-in-subdomain", () => {
    expect(ids("secure-paypal-login.test")).toContain("lookalike.combosquat");
    expect(ids("www.paypal.com.account-verify.example")).toContain("lookalike.brandInSubdomain");
    expect(ids("paypal.example")).toContain("lookalike.unofficialDomain");
  });
  it("does not flag official domains or unrelated names", () => {
    expect(ids("login.github.com")).toEqual([]);
    expect(ids("mail.google.com")).toEqual([]);
    expect(ids("example.com")).toEqual([]);
    expect(ids("kiro.dev")).toEqual([]);
  });
  it("treats legitimate IDNs as info only", () => {
    const a = analyzeLookalike("中文.example");
    expect(a.findings.every((f) => f.points === 0)).toBe(true);
  });
  it("edit distance basics", () => {
    expect(damerauLevenshtein("paypal", "paypla")).toBe(1);
    expect(damerauLevenshtein("", "abc")).toBe(3);
    expect(damerauLevenshtein("kitten", "sitting")).toBe(3);
  });
  it("detects scripts", () => {
    expect(scriptsIn("аpple")).toEqual(["Latin", "Cyrillic"]);
  });
});
