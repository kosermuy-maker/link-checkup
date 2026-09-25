import type { Finding, Level } from "./types.ts";

export const LEVEL_THRESHOLDS = { medium: 25, high: 60 } as const;
export const CRITICAL_FLOOR = 90;

/**
 * Pure scoring function.
 * - sum of finding points, clamped to 0..100 and rounded
 * - any `critical` finding forces the score to at least 90
 * Monotonic by construction: adding a finding can only add non-negative points or raise the floor.
 */
export function computeScore(findings: readonly Finding[]): number {
  let sum = 0;
  let critical = false;
  for (const f of findings) {
    const p = Number.isFinite(f.points) ? Math.max(0, f.points) : 0;
    sum += p;
    if (f.severity === "critical") critical = true;
  }
  let score = Math.min(100, Math.round(sum));
  if (critical) score = Math.max(score, CRITICAL_FLOOR);
  return score;
}

export function levelFor(score: number): Level {
  if (score >= LEVEL_THRESHOLDS.high) return "high";
  if (score >= LEVEL_THRESHOLDS.medium) return "medium";
  return "low";
}
