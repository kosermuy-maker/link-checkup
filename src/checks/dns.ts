import { bi, type CheckResult, type Finding } from "../types.ts";
import type { CheckContext } from "./context.ts";
import { isBlockedAddress } from "../net/ssrfGuard.ts";
import { isReservedHost } from "./reserved.ts";

const RESOLVERS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];

export interface DohAnswer {
  status: number; // DNS RCODE: 0 NOERROR, 3 NXDOMAIN
  addresses: string[];
  cnames: string[];
}

interface DohJson {
  Status: number;
  Answer?: Array<{ type: number; data: string }>;
}

export function parseDoh(json: unknown): DohAnswer {
  const j = json as DohJson;
  const answers = j.Answer ?? [];
  return {
    status: j.Status,
    addresses: answers.filter((a) => a.type === 1 || a.type === 28).map((a) => a.data),
    cnames: answers.filter((a) => a.type === 5).map((a) => a.data.replace(/\.$/, "")),
  };
}

async function doh(ctx: CheckContext, name: string, type: "A" | "AAAA"): Promise<DohAnswer> {
  let lastErr: unknown;
  for (const base of RESOLVERS) {
    try {
      const res = await ctx.deps.fetchText(`${base}?name=${encodeURIComponent(name)}&type=${type}`, {
        timeoutMs: 5000, maxBytes: 64_000, headers: { accept: "application/dns-json" }, signal: ctx.signal,
      });
      if (res.status === 200) return parseDoh(JSON.parse(res.text));
      lastErr = new Error(`DoH ${new URL(base).host} HTTP ${res.status}`);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("DNS-over-HTTPS failed");
}

export function dnsFindings(host: string, a: DohAnswer, aaaa: DohAnswer): Finding[] {
  const f: Finding[] = [];
  if (a.status === 3 || aaaa.status === 3) {
    f.push({
      id: "dns.nxdomain", check: "dns", severity: "medium", points: 20,
      title: bi("Domain does not exist (NXDOMAIN)", "域名不存在（NXDOMAIN）"),
      detail: bi(`${host} does not resolve. It may be taken down already, not yet live, or fake.`, `${host} 无法解析。它可能已被下线、尚未启用，或是伪造的。`),
    });
    return f;
  }
  const addrs = [...a.addresses, ...aaaa.addresses];
  if (addrs.length === 0) {
    f.push({
      id: "dns.noAddress", check: "dns", severity: "low", points: 10,
      title: bi("Domain has no web address records", "域名没有网站地址记录"),
      detail: bi(`${host} exists but has no A/AAAA records, so there is no website behind it.`, `${host} 存在，但没有 A/AAAA 记录，背后没有网站。`),
    });
    return f;
  }
  const internal = addrs.filter((x) => isBlockedAddress(x));
  if (internal.length) {
    f.push({
      id: "dns.privateAddress", check: "dns", severity: "high", points: 30,
      title: bi("Points to a private / internal network address", "指向私有或内部网络地址"),
      detail: bi(`${host} resolves to ${internal.join(", ")}. Public websites never do this; it can be used to attack devices on your own network.`, `${host} 解析到 ${internal.join(", ")}。正规公开网站不会这样，这可能被用于攻击你所在网络中的设备。`),
    });
  } else {
    f.push({
      id: "dns.resolves", check: "dns", severity: "info", points: 0,
      title: bi(`Resolves to ${addrs.length} public address(es)`, `解析到 ${addrs.length} 个公网地址`),
      detail: bi(addrs.slice(0, 6).join(", "), addrs.slice(0, 6).join(", ")),
    });
  }
  return f;
}

export async function dnsCheck(ctx: CheckContext): Promise<CheckResult> {
  const t0 = Date.now();
  const host = ctx.target.asciiHost;
  if (ctx.target.isIp) {
    return { check: "dns", status: "skipped", durationMs: 0, findings: [{ id: "dns.skipped", check: "dns", severity: "info", points: 0, title: bi("No DNS lookup needed (IP address)", "无需 DNS 查询（IP 地址）"), detail: bi(host, host) }] };
  }
  if (isReservedHost(host)) {
    // Reserved names are guaranteed not to resolve (RFC 6761) — report without querying.
    const nx = { status: 3, addresses: [], cnames: [] };
    return { check: "dns", status: "warn", durationMs: Date.now() - t0, data: { a: nx, aaaa: nx, reserved: true }, findings: dnsFindings(host, nx, nx) };
  }
  if (ctx.offline) {
    return { check: "dns", status: "skipped", durationMs: 0, findings: [{ id: "dns.skipped", check: "dns", severity: "info", points: 0, title: bi("DNS not checked", "未检查 DNS"), detail: bi("Offline mode.", "离线模式。") }] };
  }
  const [a, aaaa] = await Promise.all([doh(ctx, host, "A"), doh(ctx, host, "AAAA")]);
  const findings = dnsFindings(host, a, aaaa);
  return { check: "dns", status: findings.some((f) => f.points > 0) ? "warn" : "ok", findings, data: { a, aaaa }, durationMs: Date.now() - t0 };
}
