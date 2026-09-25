import type { Bilingual, Finding, Level } from "./types.ts";

function lowerFirst(s: string): string {
  return s ? s[0].toLowerCase() + s.slice(1) : s;
}

/** Strongest findings first (critical first, then by points). */
export function topReasons(findings: readonly Finding[], n = 2): Finding[] {
  return [...findings]
    .filter((f) => f.points > 0)
    .sort((a, b) => Number(b.severity === "critical") - Number(a.severity === "critical") || b.points - a.points)
    .slice(0, n);
}

/** Exactly one plain-language sentence per language. */
export function explain(score: number, level: Level, findings: readonly Finding[], checksRun: number): Bilingual {
  const top = topReasons(findings);
  const en = top.map((f) => lowerFirst(f.title.en)).join(" and ");
  const zh = top.map((f) => f.title.zh).join("，并且");
  const s = `${score}/100`;
  if (level === "high") {
    return {
      en: `High risk (${s}): ${en} — don't open this link or enter any information.`,
      zh: `高风险（${s}）：${zh}——请不要打开此链接，也不要输入任何信息。`,
    };
  }
  if (level === "medium") {
    return {
      en: `Medium risk (${s}): ${en} — be careful, and confirm with the sender through another channel before opening.`,
      zh: `中等风险（${s}）：${zh}——请谨慎，先通过其他渠道向发送者确认后再打开。`,
    };
  }
  if (top.length) {
    return {
      en: `Low risk (${s}): only minor signals (${en}), so open it only if you were expecting this link.`,
      zh: `低风险（${s}）：只有轻微信号（${zh}），仅在你确实在等这个链接时再打开。`,
    };
  }
  return {
    en: `Low risk (${s}): no red flags found in ${checksRun} checks, but that is not a guarantee — open it only if you were expecting it.`,
    zh: `低风险（${s}）：${checksRun} 项检查未发现危险信号，但这不代表绝对安全——仅在你确实在等这个链接时再打开。`,
  };
}
