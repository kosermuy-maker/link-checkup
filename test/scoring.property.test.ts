import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { computeScore, levelFor } from "../src/scoring.ts";
import { findingArb, findingsArb } from "./helpers/arbitraries.ts";

const RUNS = { numRuns: 300 };

describe("scoring properties", () => {
  // Feature: link-checkup, Property 1: Score is bounded — Validates: Requirements 10.1
  it("Property 1: score is an integer in [0, 100]", () => {
    fc.assert(
      fc.property(findingsArb, (fs) => {
        const s = computeScore(fs);
        return Number.isInteger(s) && s >= 0 && s <= 100;
      }),
      RUNS,
    );
  });

  // Feature: link-checkup, Property 2: Score is monotonic — Validates: Requirements 10.4
  it("Property 2: adding a finding never lowers the score", () => {
    fc.assert(fc.property(findingsArb, findingArb, (fs, f) => computeScore([...fs, f]) >= computeScore(fs)), RUNS);
  });

  // Feature: link-checkup, Property 3: Critical findings dominate — Validates: Requirements 10.2, 10.3
  it("Property 3: any critical finding forces score >= 90 and level high", () => {
    fc.assert(
      fc.property(findingsArb, findingArb, fc.nat(20), (fs, f, pos) => {
        const all = [...fs];
        all.splice(pos % (all.length + 1), 0, { ...f, severity: "critical" });
        const s = computeScore(all);
        return s >= 90 && levelFor(s) === "high";
      }),
      RUNS,
    );
  });

  // Feature: link-checkup, Property 4: Level partition — Validates: Requirements 10.3
  it("Property 4: levels partition 0..100 at 25 and 60", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 100 }), (s) => {
        const l = levelFor(s);
        return (s < 25 && l === "low") || (s >= 25 && s < 60 && l === "medium") || (s >= 60 && l === "high");
      }),
      RUNS,
    );
  });
});

describe("scoring examples", () => {
  it("empty findings score 0", () => {
    expect(computeScore([])).toBe(0);
    expect(levelFor(0)).toBe("low");
  });
  it("ignores negative or non-finite points defensively", () => {
    const base = { id: "x", check: "dns" as const, severity: "low" as const, title: { en: "", zh: "" }, detail: { en: "", zh: "" } };
    expect(computeScore([{ ...base, points: -50 }, { ...base, points: Number.NaN }, { ...base, points: 10 }])).toBe(10);
  });
});
