import { bi, type CheckResult, type Finding } from "../types.ts";
import type { CheckContext } from "./context.ts";
import type { TlsInfo } from "../net/safeRequest.ts";
import { isReservedHost } from "./reserved.ts";

const DAY = 86_400_000;

export function assessCertificate(info: TlsInfo, host: string, now: Date): Finding[] {
  const f: Finding[] = [];
  const from = info.validFrom ? Date.parse(info.validFrom) : NaN;
  const to = info.validTo ? Date.parse(info.validTo) : NaN;
  const issuer = info.issuerO ?? info.issuerCN ?? "unknown issuer";

  if (!info.authorized) {
    const err = info.authorizationError ?? "untrusted";
    const expired = !Number.isNaN(to) && to < now.getTime();
    f.push({
      id: "tls.invalid", check: "tls", severity: "high", points: 30,
      title: bi(expired ? "Certificate has expired" : "Certificate is not valid for this site", expired ? "证书已过期" : "证书对该网站无效"),
      detail: bi(
        `Browser would show a security warning (${err}). Never enter passwords on such a page.`,
        `浏览器会显示安全警告（${err}）。切勿在这样的页面输入密码。`,
      ),
    });
  }
  if (!Number.isNaN(from)) {
    const ageDays = Math.floor((now.getTime() - from) / DAY);
    if (ageDays >= 0 && ageDays < 7) {
      f.push({
        id: "tls.newCert", check: "tls", severity: "low", points: 5,
        title: bi(`Certificate issued ${ageDays} day(s) ago`, `证书于 ${ageDays} 天前签发`),
        detail: bi("Fresh certificates are normal for renewals, but also typical of brand-new phishing sites. Weak signal.", "新证书在续期时很常见，但也是新建钓鱼网站的特征。弱信号。"),
      });
    }
  }
  f.push({
    id: "tls.issuer", check: "tls", severity: "info", points: 0,
    title: bi(`Certificate by ${issuer}`, `证书签发者：${issuer}`),
    detail: bi(
      `For ${info.subjectCN ?? host}; valid ${info.validFrom ?? "?"} → ${info.validTo ?? "?"}. A padlock only means the connection is encrypted, not that the site is honest.`,
      `颁发给 ${info.subjectCN ?? host}；有效期 ${info.validFrom ?? "?"} → ${info.validTo ?? "?"}。小锁图标只代表连接加密，不代表网站可信。`,
    ),
  });
  return f;
}

export async function tlsCheck(ctx: CheckContext, finalUrl?: string): Promise<CheckResult> {
  const t0 = Date.now();
  const u = new URL(finalUrl ?? ctx.target.href);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const skipped = (en: string, zh: string): CheckResult => ({
    check: "tls", status: "skipped", durationMs: Date.now() - t0,
    findings: [{ id: "tls.skipped", check: "tls", severity: "info", points: 0, title: bi("Certificate not checked", "未检查证书"), detail: bi(en, zh) }],
  });
  if (ctx.offline) return skipped("Offline mode.", "离线模式。");
  if (isReservedHost(host)) return skipped("Reserved test domain — nothing to contact.", "保留的测试域名——无可连接对象。");
  if (u.protocol !== "https:") return skipped(`The final page uses plain http://, so there is no certificate.`, "最终页面使用 http://，没有证书。");
  const port = u.port ? Number(u.port) : 443;
  const info = await ctx.deps.tlsHandshake(host, { port, timeoutMs: 6000, signal: ctx.signal });
  const findings = assessCertificate(info, host, ctx.now);
  return { check: "tls", status: findings.some((f) => f.points > 0) ? "warn" : "ok", findings, data: { host, ...info }, durationMs: Date.now() - t0 };
}
