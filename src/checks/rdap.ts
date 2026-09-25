import { bi, type CheckResult, type Finding } from "../types.ts";
import type { CheckContext } from "./context.ts";
import { isReservedHost } from "./reserved.ts";

export interface RdapSummary {
  domain: string;
  registered?: string;
  expires?: string;
  lastChanged?: string;
  registrar?: string;
  status: string[];
  ageDays?: number;
}

const DAY = 86_400_000;

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, Array<[string, unknown, string, unknown]>];
  entities?: RdapEntity[];
}
interface RdapJson {
  ldhName?: string;
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: RdapEntity[];
  status?: string[];
}

/** Pure parser for an RDAP domain response. */
export function parseRdap(json: unknown, domain: string, now: Date): RdapSummary {
  const j = (json ?? {}) as RdapJson;
  const ev = (name: string) => j.events?.find((e) => e.eventAction?.toLowerCase() === name)?.eventDate;
  const registered = ev("registration");
  const summary: RdapSummary = {
    domain: (j.ldhName ?? domain).toLowerCase(),
    registered,
    expires: ev("expiration"),
    lastChanged: ev("last changed"),
    registrar: findRegistrar(j.entities),
    status: j.status ?? [],
  };
  if (registered && !Number.isNaN(Date.parse(registered))) {
    summary.ageDays = Math.max(0, Math.floor((now.getTime() - Date.parse(registered)) / DAY));
  }
  return summary;
}

function findRegistrar(entities: RdapEntity[] | undefined): string | undefined {
  for (const e of entities ?? []) {
    if (e.roles?.includes("registrar")) {
      const fn = e.vcardArray?.[1]?.find((v) => v[0] === "fn");
      if (fn && typeof fn[3] === "string") return fn[3];
    }
    const nested = findRegistrar(e.entities);
    if (nested) return nested;
  }
  return undefined;
}

export function rdapFindings(s: RdapSummary): Finding[] {
  const f: Finding[] = [];
  if (s.ageDays !== undefined) {
    if (s.ageDays < 30) {
      f.push({
        id: "rdap.veryNew", check: "rdap", severity: "high", points: 35,
        title: bi(`Domain registered only ${s.ageDays} day(s) ago`, `域名仅在 ${s.ageDays} 天前注册`),
        detail: bi("Most phishing domains are used within days of registration and then abandoned.", "大多数钓鱼域名在注册后几天内就被使用，随后被弃用。"),
      });
    } else if (s.ageDays < 180) {
      f.push({
        id: "rdap.new", check: "rdap", severity: "medium", points: 15,
        title: bi(`Domain is young (${s.ageDays} days old)`, `域名较新（注册 ${s.ageDays} 天）`),
        detail: bi("Established services usually have domains that are years old.", "成熟的服务通常使用注册多年的域名。"),
      });
    } else {
      const years = (s.ageDays / 365).toFixed(1);
      f.push({
        id: "rdap.age", check: "rdap", severity: "info", points: 0,
        title: bi(`Domain registered ${years} years ago`, `域名注册于 ${years} 年前`),
        detail: bi(`Registered ${s.registered?.slice(0, 10)}${s.registrar ? ` via ${s.registrar}` : ""}.`, `注册日期 ${s.registered?.slice(0, 10)}${s.registrar ? `，注册商 ${s.registrar}` : ""}。`),
      });
    }
  }
  const holds = s.status.filter((x) => /hold|suspend|redemption|pending delete/i.test(x));
  if (holds.length) {
    f.push({
      id: "rdap.onHold", check: "rdap", severity: "medium", points: 20,
      title: bi("Registry has suspended / put this domain on hold", "注册局已暂停或冻结该域名"),
      detail: bi(`RDAP status: ${holds.join(", ")}. Registries do this to abusive domains.`, `RDAP 状态：${holds.join(", ")}。注册局通常对滥用域名采取此措施。`),
    });
  }
  return f;
}

export async function rdapCheck(ctx: CheckContext): Promise<CheckResult> {
  const t0 = Date.now();
  const domain = ctx.target.registrableDomain;
  const skip = (en: string, zh: string): CheckResult => ({
    check: "rdap", status: "skipped", durationMs: Date.now() - t0,
    findings: [{ id: "rdap.skipped", check: "rdap", severity: "info", points: 0, title: bi("Registration data not checked", "未检查注册信息"), detail: bi(en, zh) }],
  });
  if (!domain) return skip("The link uses an IP address, which has no domain registration.", "该链接使用 IP 地址，没有域名注册信息。");
  if (isReservedHost(domain)) return skip(`${domain} uses a reserved test ending that cannot be registered.`, `${domain} 使用保留的测试后缀，无法注册。`);
  if (ctx.offline) return skip("Offline mode.", "离线模式。");

  const res = await ctx.deps.fetchText(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    timeoutMs: 8000, maxBytes: 1_000_000, headers: { accept: "application/rdap+json, application/json" }, signal: ctx.signal,
  });
  if (res.status === 404) {
    return {
      check: "rdap", status: "warn", durationMs: Date.now() - t0, data: { domain },
      findings: [{
        id: "rdap.notFound", check: "rdap", severity: "low", points: 10,
        title: bi("No registration record found", "未找到注册记录"),
        detail: bi(`RDAP has no record for ${domain} (unregistered, deleted, or the registry doesn't publish RDAP).`, `RDAP 中没有 ${domain} 的记录（未注册、已删除，或该注册局未提供 RDAP）。`),
      }],
    };
  }
  if (res.status !== 200) throw new Error(`RDAP returned HTTP ${res.status}`);
  const summary = parseRdap(JSON.parse(res.text), domain, ctx.now);
  const findings = rdapFindings(summary);
  if (summary.registrar && !findings.some((f) => f.id === "rdap.age")) {
    findings.push({ id: "rdap.registrar", check: "rdap", severity: "info", points: 0, title: bi(`Registrar: ${summary.registrar}`, `注册商：${summary.registrar}`), detail: bi(`Registered ${summary.registered?.slice(0, 10) ?? "unknown"}.`, `注册日期 ${summary.registered?.slice(0, 10) ?? "未知"}。`) });
  }
  return { check: "rdap", status: findings.some((f) => f.points > 0) ? "warn" : "ok", findings, data: summary, durationMs: Date.now() - t0 };
}
