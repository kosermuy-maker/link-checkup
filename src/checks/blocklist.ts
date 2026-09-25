import { parse as parseDomain } from "tldts";
import { bi, type CheckResult, type Finding } from "../types.ts";
import type { CheckContext } from "./context.ts";
import { canonicalUrlKey, type Blocklists } from "./blocklistData.ts";
import { isOfficialHost } from "./lookalike.ts";

export interface BlocklistMatch {
  source: "URLhaus" | "Phishing Army";
  kind: "url" | "host" | "domain";
  matched: string;
}

/** Host itself plus every parent domain down to (and including) the registrable domain. */
export function hostAndParents(host: string): string[] {
  const h = host.toLowerCase().replace(/\.$/, "");
  const reg = parseDomain(h).domain;
  const out = [h];
  if (!reg) return out;
  const labels = h.split(".");
  for (let i = 1; i < labels.length; i++) {
    const cand = labels.slice(i).join(".");
    if (cand.length < reg.length) break;
    out.push(cand);
  }
  return out;
}

export function matchBlocklists(url: string, lists: Blocklists): BlocklistMatch[] {
  const matches: BlocklistMatch[] = [];
  const key = canonicalUrlKey(url);
  if (lists.urlhausUrls.has(key)) matches.push({ source: "URLhaus", kind: "url", matched: key });
  let host = "";
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    return matches;
  }
  // URLhaus lists individual URLs; many sit on shared platforms (github.com, drive.google.com…),
  // so a host-level match only counts for hosts that are not official brand/platform domains.
  if (!matches.length && lists.urlhausHosts.has(host) && !isOfficialHost(host)) {
    matches.push({ source: "URLhaus", kind: "host", matched: host });
  }
  for (const cand of hostAndParents(host)) {
    if (lists.phishingDomains.has(cand)) {
      matches.push({ source: "Phishing Army", kind: "domain", matched: cand });
      break;
    }
  }
  return matches;
}

export function blocklistFindings(matches: BlocklistMatch[]): Finding[] {
  return matches.map((m): Finding => {
    if (m.kind === "host") {
      return {
        id: "blocklist.urlhausHost", check: "blocklist", severity: "high", points: 40,
        title: bi("Server is currently distributing malware (URLhaus)", "该服务器正在传播恶意软件（URLhaus）"),
        detail: bi(`Other links on ${m.matched} are listed as active malware downloads by abuse.ch URLhaus.`, `abuse.ch URLhaus 将 ${m.matched} 上的其他链接列为活跃的恶意软件下载地址。`),
      };
    }
    return {
      id: m.source === "URLhaus" ? "blocklist.urlhaus" : "blocklist.phishingArmy",
      check: "blocklist", severity: "critical", points: 90,
      title: bi(`Listed as malicious by ${m.source}`, `被 ${m.source} 列为恶意`),
      detail: bi(
        m.source === "URLhaus"
          ? `This exact URL is on abuse.ch URLhaus's list of active malware links.`
          : `${m.matched} is on the Phishing Army blocklist of known phishing domains.`,
        m.source === "URLhaus" ? "该网址在 abuse.ch URLhaus 的活跃恶意软件链接名单上。" : `${m.matched} 在 Phishing Army 已知钓鱼域名黑名单上。`,
      ),
    };
  });
}

export async function blocklistCheck(ctx: CheckContext, extraUrls: string[] = []): Promise<CheckResult> {
  const t0 = Date.now();
  if (ctx.offline) {
    return { check: "blocklist", status: "skipped", durationMs: 0, findings: [{ id: "blocklist.skipped", check: "blocklist", severity: "info", points: 0, title: bi("Blocklists not checked", "未检查黑名单"), detail: bi("Offline mode.", "离线模式。") }] };
  }
  const lists = await ctx.deps.loadBlocklists(ctx.signal);
  const sources = Object.keys(lists.fetchedAt);
  if (!sources.length) throw new Error(`Blocklist feeds unavailable: ${JSON.stringify(lists.errors)}`);
  const urls = [ctx.target.href, ...extraUrls.filter((u) => u !== ctx.target.href)];
  const seen = new Set<string>();
  const matches = urls.flatMap((u) => matchBlocklists(u, lists)).filter((m) => {
    const k = `${m.source}|${m.matched}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const findings = blocklistFindings(matches);
  if (!findings.length) {
    findings.push({
      id: "blocklist.clean", check: "blocklist", severity: "info", points: 0,
      title: bi("Not on public blocklists", "不在公开黑名单上"),
      detail: bi(
        `Checked ${urls.length} URL(s) against URLhaus (${lists.urlhausUrls.size.toLocaleString("en")} URLs) and Phishing Army (${lists.phishingDomains.size.toLocaleString("en")} domains). New threats may not be listed yet.`,
        `已将 ${urls.length} 个网址与 URLhaus（${lists.urlhausUrls.size.toLocaleString("en")} 条）和 Phishing Army（${lists.phishingDomains.size.toLocaleString("en")} 个域名）比对。新出现的威胁可能尚未收录。`,
      ),
    });
  }
  return {
    check: "blocklist", status: matches.length ? "warn" : "ok", findings,
    data: { sources: lists.fetchedAt, errors: lists.errors, matches, checkedUrls: urls },
    durationMs: Date.now() - t0,
  };
}
