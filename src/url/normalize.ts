import { domainToUnicode } from "node:url";
import { isIP } from "node:net";
import { parse as parseDomain } from "tldts";
import { bi, type Bilingual, type NormalizedUrl } from "../types.ts";

export const MAX_INPUT_LENGTH = 2048;

export type NormalizeResult = { ok: true; value: NormalizedUrl } | { ok: false; error: Bilingual };

const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const DANGEROUS_SCHEME = /^(javascript|data|file|vbscript|about|blob|ftp|mailto|tel|ws|wss|chrome|intent|sms):/i;

/**
 * Undo common "defanging" used when people forward suspicious links:
 * hxxp:// → http://, example[.]com → example.com, [:]// → ://
 */
export function refang(s: string): string {
  return s
    .replace(/^h[x*]{2}p(s?):\/\//i, "http$1://")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":");
}

export function normalizeInput(raw: string): NormalizeResult {
  if (typeof raw !== "string") return fail("Please paste a URL.", "请粘贴一个链接。");
  let s = stripEnclosing(raw.trim());
  if (!s) return fail("Please paste a URL.", "请粘贴一个链接。");
  if (s.length > MAX_INPUT_LENGTH) {
    return fail(
      `That URL is longer than ${MAX_INPUT_LENGTH} characters.`,
      `链接超过 ${MAX_INPUT_LENGTH} 个字符。`,
    );
  }
  s = refang(s);

  let schemeAssumed = false;
  if (!HAS_SCHEME.test(s)) {
    if (DANGEROUS_SCHEME.test(s)) {
      return fail(
        "Only http:// and https:// links can be checked (this one uses a different scheme, which is itself a red flag).",
        "只能检查 http:// 和 https:// 链接（该链接使用了其他协议，这本身就是危险信号）。",
      );
    }
    s = "http://" + s;
    schemeAssumed = true;
  }

  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return fail("That doesn't look like a valid URL.", "这看起来不是一个有效的链接。");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return fail(
      "Only http:// and https:// links can be checked.",
      "只能检查 http:// 和 https:// 链接。",
    );
  }
  let asciiHost = url.hostname.toLowerCase().replace(/\.$/, "");
  if (asciiHost.startsWith("[") && asciiHost.endsWith("]")) asciiHost = asciiHost.slice(1, -1);
  if (!asciiHost || (!asciiHost.includes(".") && !isIP(asciiHost) && asciiHost !== "localhost")) {
    return fail("The URL has no valid host name.", "该链接没有有效的主机名。");
  }
  // Canonicalise: drop trailing dot in the URL itself, drop the fragment (never sent to servers).
  url.hostname = url.hostname.replace(/\.$/, "");
  url.hash = "";

  const isIp = isIP(asciiHost) !== 0;
  const parsed = parseDomain(asciiHost, { allowPrivateDomains: false });
  const registrableDomain = isIp ? null : parsed.domain ?? null;
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;

  return {
    ok: true,
    value: {
      href: url.href,
      url,
      protocol: url.protocol as "http:" | "https:",
      asciiHost,
      displayHost: isIp ? asciiHost : domainToUnicode(asciiHost) || asciiHost,
      port,
      isIp,
      registrableDomain,
      domainLabel: isIp ? null : parsed.domainWithoutSuffix ?? null,
      subdomain: isIp ? "" : parsed.subdomain ?? "",
      publicSuffix: isIp ? null : parsed.publicSuffix ?? null,
      schemeAssumed,
    },
  };
}

const CLOSER: Record<string, string> = { "<": ">", '"': '"', "'": "'", "`": "`" };

/** Remove quotes/angle brackets that wrap the whole input (e.g. <https://x>, "x"), but keep a quote that is part of the URL. */
function stripEnclosing(s: string): string {
  while (s.length >= 2 && CLOSER[s[0]] !== undefined && s.endsWith(CLOSER[s[0]])) s = s.slice(1, -1).trim();
  return s.replace(/^[<"'`]+/, "").trim();
}

function fail(en: string, zh: string): NormalizeResult {
  return { ok: false, error: bi(en, zh) };
}
