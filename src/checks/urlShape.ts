import { bi, type CheckResult, type Finding } from "../types.ts";
import type { CheckContext } from "./context.ts";
import { ALLOWED_PORTS } from "../net/safeRequest.ts";

/** TLDs disproportionately used for abuse in public phishing/malware reports (heuristic, low weight). */
export const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "xyz", "sbs", "cfd", "click", "cyou", "icu", "buzz", "rest", "monster", "quest",
  "gq", "ml", "cf", "tk", "ga", "work", "support", "country", "kim", "loan", "lol", "bond", "shop", "live",
]);

export const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
  "rb.gy", "t.ly", "s.id", "tiny.cc", "v.gd", "dwz.cn", "url.cn", "suo.im",
]);

const CREDENTIAL_WORDS = /(login|log-in|signin|sign-in|verify|verification|account|secure|update|unlock|wallet|password|bank|confirm|suspend|invoice|refund|prize|gift|claim)/i;

export function urlShapeFindings(ctx: CheckContext): Finding[] {
  const t = ctx.target;
  const f: Finding[] = [];
  const u = t.url;

  if (t.isIp) {
    f.push({
      id: "urlShape.ipHost", check: "urlShape", severity: "medium", points: 25,
      title: bi("Uses a raw IP address instead of a name", "使用裸 IP 地址而非域名"),
      detail: bi(`Legitimate services almost always use a domain name. ${t.asciiHost} hides who runs the server.`, `正规服务几乎都使用域名。${t.asciiHost} 隐藏了服务器的真实归属。`),
    });
  }
  if (u.username || u.password) {
    f.push({
      id: "urlShape.userinfo", check: "urlShape", severity: "medium", points: 25,
      title: bi('Contains an "@" trick', "包含“@”障眼法"),
      detail: bi(`Everything before "@" is ignored by browsers — the real destination is ${t.displayHost}.`, `浏览器会忽略 “@” 之前的内容——真正的目的地是 ${t.displayHost}。`),
    });
  }
  if (t.protocol === "http:" && !t.schemeAssumed) {
    f.push({
      id: "urlShape.plainHttp", check: "urlShape", severity: "low", points: 10,
      title: bi("Not encrypted (http://)", "未加密（http://）"),
      detail: bi("Anything typed on this page could be read or altered in transit. Login pages must use https.", "在此页面输入的任何内容都可能在传输中被窃取或篡改。登录页面必须使用 https。"),
    });
  }
  if (!ALLOWED_PORTS.has(t.port)) {
    f.push({
      id: "urlShape.unusualPort", check: "urlShape", severity: "low", points: 10,
      title: bi(`Unusual port ${t.port}`, `非常规端口 ${t.port}`),
      detail: bi("Normal websites use ports 80/443. For safety, Link Checkup does not contact other ports.", "普通网站使用 80/443 端口。出于安全考虑，本工具不会连接其他端口。"),
    });
  }
  const depth = t.subdomain ? t.subdomain.split(".").length : 0;
  if (depth >= 4) {
    f.push({
      id: "urlShape.deepSubdomain", check: "urlShape", severity: "low", points: 10,
      title: bi(`Very long chain of subdomains (${depth})`, `子域名层级过多（${depth} 层）`),
      detail: bi("Long subdomain chains are used to push the real domain out of view on phone screens.", "多层子域名常被用来把真实域名挤出手机屏幕的可视范围。"),
    });
  }
  const tld = t.publicSuffix?.split(".").pop() ?? "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    f.push({
      id: "urlShape.suspiciousTld", check: "urlShape", severity: "low", points: 10,
      title: bi(`Ending ".${tld}" is often abused`, `后缀“.${tld}”常被滥用`),
      detail: bi("This domain ending is cheap and appears frequently in phishing reports. Not proof on its own.", "该后缀注册便宜，在钓鱼举报中出现频率高。仅凭这一点不能下结论。"),
    });
  }
  if (t.registrableDomain && URL_SHORTENERS.has(t.registrableDomain)) {
    f.push({
      id: "urlShape.shortener", check: "urlShape", severity: "low", points: 5,
      title: bi("Link shortener hides the destination", "短链接隐藏了真实目的地"),
      detail: bi("See the redirect chain below for where it actually leads.", "请查看下方跳转链了解它的真实去向。"),
    });
  }
  const pathAndQuery = decodeSafe(u.pathname + u.search);
  if (CREDENTIAL_WORDS.test(pathAndQuery) || CREDENTIAL_WORDS.test(t.subdomain)) {
    f.push({
      id: "urlShape.credentialWords", check: "urlShape", severity: "low", points: 5,
      title: bi("Asks for login / verification", "涉及登录或验证字样"),
      detail: bi('Words like "login", "verify" or "account" are common in credential-phishing links.', "“login”“verify”“account”等字样在盗号钓鱼链接中很常见。"),
    });
  }
  if (t.href.length > 200) {
    f.push({
      id: "urlShape.longUrl", check: "urlShape", severity: "low", points: 5,
      title: bi(`Very long URL (${t.href.length} characters)`, `网址过长（${t.href.length} 个字符）`),
      detail: bi("Long, noisy URLs are used to hide the part that matters.", "冗长杂乱的网址常用来隐藏关键部分。"),
    });
  }
  return f;
}

function decodeSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export async function urlShapeCheck(ctx: CheckContext): Promise<CheckResult> {
  const t0 = Date.now();
  const findings = urlShapeFindings(ctx);
  return { check: "urlShape", status: findings.some((f) => f.points > 0) ? "warn" : "ok", findings, durationMs: Date.now() - t0 };
}
