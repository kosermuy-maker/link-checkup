import { runCheckup, InputError } from "./checkup.ts";
import type { Lang, Report } from "./types.ts";

const COLORS = { low: "\x1b[32m", medium: "\x1b[33m", high: "\x1b[31m", reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m" };

export function formatReport(r: Report, lang: Lang, color = process.stdout.isTTY): string {
  const c = (k: keyof typeof COLORS, s: string) => (color ? COLORS[k] + s + COLORS.reset : s);
  const lines: string[] = [];
  lines.push(c("bold", `Link Checkup ${r.version} — ${r.displayHost}`));
  lines.push(`${c(r.level, `${r.level.toUpperCase()} ${r.score}/100`)}  ${r.explanation[lang]}`);
  if (r.finalUrl !== r.normalizedUrl) lines.push(c("dim", `→ final: ${r.finalUrl}`));
  for (const ch of r.checks) {
    lines.push(`\n${c("bold", ch.check)} ${c("dim", `[${ch.status}, ${ch.durationMs} ms]`)}`);
    for (const f of ch.findings) {
      const pts = f.points ? ` +${f.points}` : "";
      lines.push(`  ${f.points ? "•" : "·"} ${f.title[lang]}${c("dim", pts)}`);
      lines.push(c("dim", `    ${f.detail[lang]}`));
    }
  }
  return lines.join("\n");
}

async function main(argv: string[]): Promise<number> {
  const args = argv.filter((a) => !a.startsWith("--"));
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const langIdx = argv.indexOf("--lang");
  const lang: Lang = langIdx !== -1 && argv[langIdx + 1] === "zh" ? "zh" : flags.has("--zh") ? "zh" : "en";
  const url = args.filter((a) => a !== "zh" && a !== "en")[0];
  if (!url || flags.has("--help")) {
    console.log("Usage: npm run check -- <url> [--json] [--offline] [--lang zh]\nAssesses a URL without opening it.");
    return url ? 0 : 2;
  }
  try {
    const report = await runCheckup(url, { offline: flags.has("--offline") || undefined });
    console.log(flags.has("--json") ? JSON.stringify(report, null, 2) : formatReport(report, lang));
    return report.level === "high" ? 3 : 0;
  } catch (e) {
    if (e instanceof InputError) {
      console.error(e.messages[lang]);
      return 2;
    }
    throw e;
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("cli.ts")) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
