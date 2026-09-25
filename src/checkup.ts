import { readFileSync } from "node:fs";
import { parse as parseDomain } from "tldts";
import { bi, type Bilingual, type CheckId, type CheckResult, type Report } from "./types.ts";
import { normalizeInput } from "./url/normalize.ts";
import {
  CHECK_ORDER, blocklistCheck, defaultDeps, dnsCheck, lookalikeCheck, rdapCheck, redirectsCheck, tlsCheck, urlShapeCheck,
  analyzeLookalike, type CheckContext, type CheckDeps,
} from "./checks/index.ts";
import type { ChainResult } from "./checks/redirects.ts";
import { computeScore, levelFor } from "./scoring.ts";
import { explain } from "./explain.ts";

export const VERSION: string = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
  } catch {
    return "0.0.0";
  }
})();

export class InputError extends Error {
  constructor(public readonly messages: Bilingual) {
    super(messages.en);
    this.name = "InputError";
  }
}

export interface CheckupOptions {
  offline?: boolean;
  deps?: Partial<CheckDeps>;
  now?: Date;
  budgetMs?: number;
}

/** Run a check with error isolation and a deadline. Errors are 0-point "unknown", never "dangerous". */
async function safeCheck(check: CheckId, run: () => Promise<CheckResult>, deadline: Promise<"timeout">): Promise<CheckResult> {
  const t0 = Date.now();
  try {
    const r = await Promise.race([run(), deadline]);
    if (r === "timeout") {
      return {
        check, status: "skipped", durationMs: Date.now() - t0,
        findings: [{ id: `${check}.timeout`, check, severity: "info", points: 0, title: bi("Took too long — skipped", "耗时过长——已跳过"), detail: bi("The overall time budget ran out before this check finished.", "在此检查完成前，总体时间预算已用完。") }],
      };
    }
    return r;
  } catch (e) {
    const msg = (e as Error)?.message ?? String(e);
    return {
      check, status: "error", durationMs: Date.now() - t0,
      findings: [{ id: `${check}.error`, check, severity: "info", points: 0, title: bi("Could not complete this check", "此项检查未能完成"), detail: bi(`${msg}. Unknown results add no points.`, `${msg}。未知结果不计分。`) }],
    };
  }
}

export async function runCheckup(input: string, options: CheckupOptions = {}): Promise<Report> {
  const started = Date.now();
  const norm = normalizeInput(input);
  if (!norm.ok) throw new InputError(norm.error);
  const offline = options.offline ?? process.env.LINK_CHECKUP_OFFLINE === "1";
  const budgetMs = options.budgetMs ?? 20_000;
  const ctrl = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => {
      ctrl.abort(new Error("Checkup time budget exceeded"));
      resolve("timeout");
    }, budgetMs);
  });

  const ctx: CheckContext = {
    target: norm.value,
    now: options.now ?? new Date(),
    offline,
    deps: { ...defaultDeps, ...options.deps },
    signal: ctrl.signal,
  };

  try {
    const independent = Promise.all([
      safeCheck("urlShape", () => urlShapeCheck(ctx), deadline),
      safeCheck("lookalike", () => lookalikeCheck(ctx), deadline),
      safeCheck("rdap", () => rdapCheck(ctx), deadline),
      safeCheck("dns", () => dnsCheck(ctx), deadline),
    ]);
    const chained = (async () => {
      const redirects = await safeCheck("redirects", () => redirectsCheck(ctx), deadline);
      const chain = redirects.data as ChainResult | undefined;
      const finalUrl = chain?.finalUrl ?? ctx.target.href;
      const hopUrls = (chain?.hops ?? []).map((h) => h.url);
      const [tls, blocklist] = await Promise.all([
        safeCheck("tls", () => tlsCheck(ctx, finalUrl), deadline),
        safeCheck("blocklist", () => blocklistCheck(ctx, [...hopUrls, finalUrl]), deadline),
      ]);
      return { redirects, tls, blocklist, finalUrl };
    })();

    const [[urlShape, lookalike, rdap, dns], { redirects, tls, blocklist, finalUrl }] = await Promise.all([independent, chained]);

    // Re-check the identity of the final destination if the chain changed site (Req 4.4).
    const startReg = ctx.target.registrableDomain;
    const finalHost = new URL(finalUrl).hostname;
    const finalReg = parseDomain(finalHost).domain;
    if (finalReg && finalReg !== startReg) {
      const extra = analyzeLookalike(finalHost).findings
        .filter((f) => f.points > 0)
        .map((f) => ({ ...f, id: f.id + ".final", title: bi(`Final site: ${f.title.en}`, `最终网站：${f.title.zh}`) }));
      if (extra.length) {
        lookalike.findings.push(...extra);
        lookalike.status = "warn";
      }
    }

    // http:// that immediately upgrades to https on the same site is normal — downgrade that finding to info.
    if (ctx.target.protocol === "http:" && finalUrl.startsWith("https:") && finalReg === startReg) {
      const f = urlShape.findings.find((x) => x.id === "urlShape.plainHttp");
      if (f) {
        f.points = 0;
        f.severity = "info";
        f.title = bi("Starts with http:// but upgrades to https://", "以 http:// 开头，但会升级到 https://");
        f.detail = bi("The server immediately redirects to the encrypted version of the same site.", "服务器会立即跳转到同一网站的加密版本。");
        if (!urlShape.findings.some((x) => x.points > 0)) urlShape.status = "ok";
      }
    }

    const byId = new Map<CheckId, CheckResult>([urlShape, lookalike, rdap, dns, redirects, tls, blocklist].map((c) => [c.check, c]));
    const checks = CHECK_ORDER.map((id) => byId.get(id)!).filter(Boolean);
    const findings = checks.flatMap((c) => c.findings);
    const score = computeScore(findings);
    const level = levelFor(score);
    const ran = checks.filter((c) => c.status === "ok" || c.status === "warn").length;
    return {
      input,
      normalizedUrl: ctx.target.href,
      displayHost: ctx.target.displayHost,
      finalUrl,
      score,
      level,
      explanation: explain(score, level, findings, ran),
      checks,
      findings,
      checkedAt: ctx.now.toISOString(),
      durationMs: Date.now() - started,
      offline,
      version: VERSION,
    };
  } finally {
    clearTimeout(timer);
    ctrl.abort();
  }
}
