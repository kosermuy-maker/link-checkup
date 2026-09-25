import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runCheckup, InputError, VERSION } from "../checkup.ts";
import { analyzeLookalike } from "../checks/lookalike.ts";
import { computeScore, levelFor } from "../scoring.ts";
import type { Lang, Report } from "../types.ts";

/** Compact, agent-friendly text rendering of a report. */
export function reportToText(r: Report, lang: Lang): string {
  const lines = [
    `${r.level.toUpperCase()} RISK ${r.score}/100 — ${r.displayHost}`,
    r.explanation[lang],
    r.finalUrl !== r.normalizedUrl ? `Final destination: ${r.finalUrl}` : "",
    "",
    "Findings (points > 0):",
    ...(r.findings.some((f) => f.points > 0)
      ? r.findings.filter((f) => f.points > 0).map((f) => `- [${f.check}] ${f.title[lang]} (+${f.points}): ${f.detail[lang]}`)
      : ["- (none)"]),
    "",
    "Context:",
    ...r.findings.filter((f) => f.points === 0).map((f) => `- [${f.check}] ${f.title[lang]}: ${f.detail[lang]}`),
    "",
    `Checks: ${r.checks.map((c) => `${c.check}=${c.status}`).join(", ")}. The page was never opened (headers/DNS/TLS handshake only).`,
  ];
  return lines.filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n");
}

export function createMcpServer(): McpServer {
  const server = new McpServer({ name: "link-checkup", version: VERSION });

  server.registerTool(
    "check_url",
    {
      title: "Check a suspicious URL (without opening it)",
      description:
        "Assess the risk of a URL WITHOUT opening it: domain age/registrar (RDAP), DNS, redirect chain (HEAD only, SSRF-guarded), " +
        "TLS certificate, lookalike/typosquat analysis and public blocklists (URLhaus, Phishing Army). " +
        "Returns a 0-100 risk score, level, per-check findings and a one-sentence verdict in English and Chinese. " +
        "Use this instead of fetching or browsing a suspicious link.",
      inputSchema: {
        url: z.string().min(1).max(2048).describe("The suspicious URL as received (defanged forms like hxxp://example[.]com are accepted)"),
        lang: z.enum(["en", "zh"]).optional().describe("Language for the text summary (default en)"),
        offline: z.boolean().optional().describe("Only run offline checks (lookalike + URL structure); no network access"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ url, lang, offline }) => {
      try {
        const report = await runCheckup(url, { offline });
        return {
          content: [{ type: "text", text: reportToText(report, lang ?? "en") }],
          structuredContent: {
            score: report.score,
            level: report.level,
            explanation: report.explanation,
            finalUrl: report.finalUrl,
            findings: report.findings.map((f) => ({ id: f.id, check: f.check, severity: f.severity, points: f.points, title: f.title.en })),
          },
        };
      } catch (e) {
        if (e instanceof InputError) return { isError: true, content: [{ type: "text", text: `${e.messages.en} / ${e.messages.zh}` }] };
        throw e;
      }
    },
  );

  server.registerTool(
    "check_lookalike",
    {
      title: "Offline lookalike / typosquat check",
      description:
        "Offline check whether a domain imitates a well-known brand (homoglyphs like paypa1 or Cyrillic letters, typos, " +
        "brand + extra words, brand domain inside a subdomain, mixed alphabets). No network access.",
      inputSchema: { domain: z.string().min(1).max(253).describe("Host name, e.g. paypa1.example or xn--pple-43d.com") },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ domain }) => {
      const host = domain.replace(/^[a-z]+:\/\//i, "").split(/[/?#:]/)[0];
      const a = analyzeLookalike(host);
      const score = computeScore(a.findings);
      const text = a.official
        ? `${a.unicodeHost} is an official ${a.official.name} domain — not a lookalike.`
        : a.findings.length
          ? `${a.unicodeHost} (${a.asciiHost}) — lookalike score ${score}/100 (${levelFor(score)}):\n` +
            a.findings.map((f) => `- ${f.title.en} (+${f.points}): ${f.detail.en}`).join("\n")
          : `${a.unicodeHost}: no lookalike of the watched brands detected.`;
      return {
        content: [{ type: "text", text }],
        structuredContent: { host: a.asciiHost, unicodeHost: a.unicodeHost, official: a.official?.name ?? null, score, findings: a.findings.map((f) => ({ id: f.id, points: f.points, title: f.title.en })) },
      };
    },
  );

  return server;
}

const isMain = process.argv[1]?.endsWith("mcp/server.ts") || process.argv[1]?.endsWith("link-checkup-mcp.mjs") || process.env.LINK_CHECKUP_MCP_MAIN === "1";
if (isMain) {
  const transport = new StdioServerTransport();
  await createMcpServer().connect(transport);
  console.error(`link-checkup MCP server ${VERSION} ready on stdio`);
}
