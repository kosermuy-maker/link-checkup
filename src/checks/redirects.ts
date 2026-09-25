import { parse as parseDomain } from "tldts";
import { bi, type CheckResult, type Finding, type HopInfo } from "../types.ts";
import type { CheckContext } from "./context.ts";
import type { HeadResult } from "../net/safeRequest.ts";
import { isReservedHost } from "./reserved.ts";

export const MAX_HOPS = 8;

export type Transport = (url: string) => Promise<HeadResult>;

export interface ChainResult {
  hops: HopInfo[];
  finalUrl: string;
  stoppedReason?: "maxHops" | "loop" | "blocked" | "badScheme" | "error";
  stoppedDetail?: string;
}

/**
 * Follow a redirect chain using only response headers. Terminates after at most MAX_HOPS + 1 requests.
 */
export async function followRedirects(start: string, transport: Transport, maxHops = MAX_HOPS): Promise<ChainResult> {
  const hops: HopInfo[] = [];
  const seen = new Set<string>();
  let current = start;
  for (let i = 0; i <= maxHops; i++) {
    if (seen.has(current)) return { hops, finalUrl: current, stoppedReason: "loop" };
    seen.add(current);
    const t0 = Date.now();
    let res: HeadResult;
    try {
      res = await transport(current);
    } catch (e) {
      const err = e as Error;
      const blocked = err.name === "BlockedAddressError" || err.name === "DisallowedPortError";
      hops.push({ url: current, status: null, method: "HEAD", ms: Date.now() - t0, error: err.message });
      return { hops, finalUrl: current, stoppedReason: blocked ? "blocked" : "error", stoppedDetail: err.message };
    }
    const hop: HopInfo = { url: current, status: res.status, method: res.method, ms: Date.now() - t0 };
    const isRedirect = res.status >= 300 && res.status < 400 && res.status !== 304 && !!res.location;
    if (!isRedirect) {
      hops.push(hop);
      return { hops, finalUrl: current };
    }
    let next: URL;
    try {
      next = new URL(res.location!, current);
    } catch {
      hops.push({ ...hop, location: res.location });
      return { hops, finalUrl: current, stoppedReason: "error", stoppedDetail: "Invalid Location header" };
    }
    next.hash = "";
    hop.location = next.href;
    hops.push(hop);
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      return { hops, finalUrl: current, stoppedReason: "badScheme", stoppedDetail: next.protocol };
    }
    current = next.href;
  }
  return { hops, finalUrl: current, stoppedReason: "maxHops" };
}

function regDomain(u: string): string {
  try {
    const h = new URL(u).hostname;
    return parseDomain(h).domain ?? h;
  } catch {
    return u;
  }
}

export function redirectFindings(start: string, chain: ChainResult): Finding[] {
  const f: Finding[] = [];
  const redirects = chain.hops.filter((h) => h.location).length;
  const startDomain = regDomain(start);
  const finalDomain = regDomain(chain.finalUrl);

  if (chain.stoppedReason === "blocked") {
    f.push({
      id: "redirects.blockedTarget", check: "redirects", severity: "high", points: 30,
      title: bi("Leads to an internal address or unusual port", "指向内部地址或非常规端口"),
      detail: bi(`Stopped for safety: ${chain.stoppedDetail}. Public links should never point into private networks.`, `出于安全考虑已停止：${chain.stoppedDetail}。公开链接不应指向私有网络。`),
    });
  }
  if (chain.stoppedReason === "badScheme") {
    f.push({
      id: "redirects.badScheme", check: "redirects", severity: "high", points: 35,
      title: bi(`Redirects to a non-web scheme (${chain.stoppedDetail})`, `跳转到非网页协议（${chain.stoppedDetail}）`),
      detail: bi("Redirecting to javascript:, data: or app schemes is used to run code or open apps without asking.", "跳转到 javascript:、data: 或应用协议常被用来在未经同意时运行代码或打开应用。"),
    });
  }
  if (chain.stoppedReason === "maxHops" || chain.stoppedReason === "loop") {
    f.push({
      id: "redirects.tooMany", check: "redirects", severity: "medium", points: 15,
      title: bi(chain.stoppedReason === "loop" ? "Redirect loop" : `More than ${MAX_HOPS} redirects`, chain.stoppedReason === "loop" ? "循环跳转" : `超过 ${MAX_HOPS} 次跳转`),
      detail: bi("Long or looping chains are used to evade scanners (cloaking).", "过长或循环的跳转链常用于躲避安全扫描（伪装）。"),
    });
  } else if (redirects >= 3) {
    f.push({
      id: "redirects.long", check: "redirects", severity: "low", points: 10,
      title: bi(`${redirects} redirects before the destination`, `到达目的地前跳转了 ${redirects} 次`),
      detail: bi("Several hops can be legitimate (tracking), but also hide where you end up.", "多次跳转可能是正常的（统计追踪），也可能在隐藏最终去向。"),
    });
  }
  if (redirects > 0 && finalDomain !== startDomain) {
    f.push({
      id: "redirects.crossDomain", check: "redirects", severity: "low", points: 5,
      title: bi(`Ends up on a different site: ${finalDomain}`, `最终跳到另一个网站：${finalDomain}`),
      detail: bi(`The link starts at ${startDomain} but lands on ${finalDomain}. The final site is re-checked below.`, `链接从 ${startDomain} 出发，最终落在 ${finalDomain}。下方已对最终网站重新检查。`),
    });
  }
  for (const h of chain.hops) {
    if (h.location && h.url.startsWith("https:") && h.location.startsWith("http:")) {
      f.push({
        id: "redirects.downgrade", check: "redirects", severity: "low", points: 10,
        title: bi("Redirect drops encryption (https → http)", "跳转后丢失加密（https → http）"),
        detail: bi(`${h.url} → ${h.location}`, `${h.url} → ${h.location}`),
      });
      break;
    }
  }
  return f;
}

export async function redirectsCheck(ctx: CheckContext): Promise<CheckResult & { data?: ChainResult }> {
  const t0 = Date.now();
  const t = ctx.target;
  if (ctx.offline || isReservedHost(t.asciiHost)) {
    return {
      check: "redirects", status: "skipped", durationMs: 0, data: { hops: [], finalUrl: t.href },
      findings: [{ id: "redirects.skipped", check: "redirects", severity: "info", points: 0, title: bi("Redirects not followed", "未跟踪跳转"), detail: bi(ctx.offline ? "Offline mode." : "Reserved test domain — nothing to contact.", ctx.offline ? "离线模式。" : "保留的测试域名——无可连接对象。") }],
    };
  }
  const chain = await followRedirects(t.href, (u) => ctx.deps.headRequest(u, { timeoutMs: 6000, signal: ctx.signal }));
  const findings = redirectFindings(t.href, chain);
  const last = chain.hops[chain.hops.length - 1];
  if (!findings.length && last?.status) {
    findings.push({
      id: "redirects.none", check: "redirects", severity: "info", points: 0,
      title: bi(chain.hops.length > 1 ? `${chain.hops.length - 1} redirect(s), same site` : "No redirects", chain.hops.length > 1 ? `${chain.hops.length - 1} 次跳转，同一网站` : "没有跳转"),
      detail: bi(`Final response: HTTP ${last.status} (headers only, page not opened).`, `最终响应：HTTP ${last.status}（仅读取响应头，未打开页面）。`),
    });
  }
  if (chain.stoppedReason === "error") {
    findings.push({
      id: "redirects.unreachable", check: "redirects", severity: "info", points: 0,
      title: bi("Server did not answer", "服务器没有响应"),
      detail: bi(chain.stoppedDetail ?? "Unknown error", chain.stoppedDetail ?? "未知错误"),
    });
  }
  return { check: "redirects", status: findings.some((f) => f.points > 0) ? "warn" : chain.stoppedReason === "error" ? "error" : "ok", findings, data: chain, durationMs: Date.now() - t0 };
}
