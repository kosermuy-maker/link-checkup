import fc from "fast-check";
import type { CheckId, Finding, Severity } from "../../src/types.ts";

const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
const checks: CheckId[] = ["urlShape", "lookalike", "rdap", "dns", "redirects", "tls", "blocklist"];

export const findingArb: fc.Arbitrary<Finding> = fc.record({
  id: fc.string({ minLength: 1, maxLength: 12 }),
  check: fc.constantFrom(...checks),
  severity: fc.constantFrom(...severities),
  points: fc.integer({ min: 0, max: 100 }),
  title: fc.record({ en: fc.string(), zh: fc.string() }),
  detail: fc.record({ en: fc.string(), zh: fc.string() }),
});

export const findingsArb = fc.array(findingArb, { maxLength: 20 });

export const labelArb = fc.stringMatching(/^[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?$/);
