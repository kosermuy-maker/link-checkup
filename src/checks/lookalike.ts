import { domainToASCII, domainToUnicode } from "node:url";
import { parse as parseDomain } from "tldts";
import { bi, type CheckResult, type Finding } from "../types.ts";
import { BRANDS, OFFICIAL_DOMAINS, type Brand } from "./brands.ts";
import { skeleton } from "./homoglyphs.ts";
import type { CheckContext } from "./context.ts";

/** Optimal-string-alignment Damerau–Levenshtein distance. */
export function damerauLevenshtein(a: string, b: string): number {
  const A = [...a];
  const B = [...b];
  const n = A.length;
  const m = B.length;
  if (n === 0) return m;
  if (m === 0) return n;
  const d: number[][] = Array.from({ length: n + 1 }, (_, i) => {
    const row = new Array<number>(m + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= m; j++) d[0][j] = j;
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      const cost = A[i - 1] === B[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && A[i - 1] === B[j - 2] && A[i - 2] === B[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[n][m];
}

const SCRIPTS: Array<[string, RegExp]> = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
];

export function scriptsIn(label: string): string[] {
  return SCRIPTS.filter(([, re]) => re.test(label)).map(([name]) => name);
}

export function isOfficialHost(asciiHost: string): Brand | null {
  const h = asciiHost.toLowerCase().replace(/\.$/, "");
  for (const b of BRANDS) {
    for (const d of b.domains) if (h === d || h.endsWith("." + d)) return b;
  }
  return null;
}

export interface LookalikeAnalysis {
  asciiHost: string;
  unicodeHost: string;
  official: Brand | null;
  findings: Finding[];
}

/**
 * Pure, offline lookalike analysis of a host name (ASCII/punycode or Unicode).
 */
export function analyzeLookalike(host: string): LookalikeAnalysis {
  const asciiHost = (domainToASCII(host.trim().toLowerCase().replace(/\.$/, "")) || host).toLowerCase();
  const unicodeHost = domainToUnicode(asciiHost) || asciiHost;
  const findings: Finding[] = [];
  const official = isOfficialHost(asciiHost);
  if (official) return { asciiHost, unicodeHost, official, findings };

  const p = parseDomain(asciiHost);
  if (p.isIp || !p.domain) return { asciiHost, unicodeHost, official: null, findings };
  const labelAscii = p.domainWithoutSuffix ?? "";
  const label = domainToUnicode(labelAscii) || labelAscii;
  const subLabels = (p.subdomain ?? "").split(".").filter(Boolean);
  const subUnicode = subLabels.map((s) => domainToUnicode(s) || s);
  const labelSkel = skeleton(label);
  const flagged = new Set<string>(); // one finding per brand per rule family

  const add = (key: string, f: Finding) => {
    if (flagged.has(key)) return;
    flagged.add(key);
    findings.push(f);
  };

  for (const brand of BRANDS) {
    const bl = brand.label;
    const bSkel = skeleton(bl);
    const official = brand.domains[0];

    // 1. exact name on an unofficial domain (paypal.example, paypal-login is handled by combosquat)
    if (label === bl) {
      add(`name:${bl}`, {
        id: "lookalike.unofficialDomain",
        check: "lookalike",
        severity: "medium",
        points: 20,
        title: bi(`Uses the name "${brand.name}" on an unofficial domain`, `在非官方域名上使用“${brand.name}”的名字`),
        detail: bi(
          `${p.domain} is not one of ${brand.name}'s known official domains (e.g. ${official}). Brands rarely use other endings.`,
          `${p.domain} 不是 ${brand.name} 已知的官方域名（例如 ${official}）。正规品牌很少使用其他后缀。`,
        ),
      });
      continue;
    }

    // 2. homoglyph: visually identical after skeleton mapping
    if (bl.length >= 4 && labelSkel === bSkel) {
      add(`glyph:${bl}`, {
        id: "lookalike.homoglyph",
        check: "lookalike",
        severity: "high",
        points: 45,
        title: bi(`Imitates ${official} with look-alike characters`, `用形近字符仿冒 ${official}`),
        detail: bi(
          `"${label}" is visually almost identical to "${bl}" (e.g. 1↔l, 0↔o, rn↔m, or Cyrillic/Greek letters) — a classic phishing trick.`,
          `“${label}” 与 “${bl}” 在视觉上几乎一样（例如 1↔l、0↔o、rn↔m 或西里尔/希腊字母），这是典型的钓鱼手法。`,
        ),
      });
      continue;
    }

    // 3. typosquat: small edit distance
    if (bl.length >= 5) {
      const dist = Math.min(damerauLevenshtein(label, bl), damerauLevenshtein(labelSkel, bSkel));
      const max = bl.length >= 9 ? 2 : 1;
      if (dist > 0 && dist <= max) {
        add(`typo:${bl}`, {
          id: "lookalike.typosquat",
          check: "lookalike",
          severity: "high",
          points: 35,
          title: bi(`One typo away from ${official}`, `与 ${official} 仅差一两个字符`),
          detail: bi(
            `"${label}" differs from "${bl}" by ${dist} character${dist > 1 ? "s" : ""} — typo-squatted domains catch people who misread or mistype.`,
            `“${label}” 与 “${bl}” 只差 ${dist} 个字符——抢注拼写错误域名是为了骗过看错或输错的人。`,
          ),
        });
        continue;
      }
    }

    // 4. combosquat: brand + extra words in the registrable label (paypal-secure-login)
    if (bl.length >= 5 && label !== bl && (label.includes(bl) || labelSkel.includes(bSkel))) {
      add(`combo:${bl}`, {
        id: "lookalike.combosquat",
        check: "lookalike",
        severity: "medium",
        points: 30,
        title: bi(`Brand name "${brand.name}" mixed with other words`, `品牌名“${brand.name}”混搭其他词`),
        detail: bi(
          `"${label}" contains "${bl}" but is not ${brand.name}'s domain. Phishers pad brand names with words like "secure", "login" or "verify".`,
          `“${label}” 包含 “${bl}”，但并不是 ${brand.name} 的域名。钓鱼者常在品牌名旁加上 “secure”“login”“verify” 等词。`,
        ),
      });
    }

    // 5. brand domain or brand name inside the subdomain part (paypal.com.verify.example)
    const subJoined = subUnicode.join(".");
    const brandDomainInSub = brand.domains.some((d) => subJoined === d || subJoined.endsWith("." + d) || subJoined.includes(d + ".") || subJoined.endsWith(d));
    if (brandDomainInSub) {
      add(`sub:${bl}`, {
        id: "lookalike.brandInSubdomain",
        check: "lookalike",
        severity: "high",
        points: 35,
        title: bi(`Pretends to be ${official} using a subdomain`, `用子域名冒充 ${official}`),
        detail: bi(
          `The address starts with "${subJoined}" but the real domain is ${p.domain}. Only the part right before the ending decides who owns a site.`,
          `网址开头是 “${subJoined}”，但真正的域名是 ${p.domain}。决定网站归属的是后缀前面的那一段。`,
        ),
      });
    } else if (bl.length >= 5 && subUnicode.some((s) => s === bl || skeleton(s) === bSkel)) {
      add(`sub:${bl}`, {
        id: "lookalike.brandInSubdomain",
        check: "lookalike",
        severity: "medium",
        points: 25,
        title: bi(`Brand name "${brand.name}" used as a subdomain`, `把品牌名“${brand.name}”用作子域名`),
        detail: bi(
          `"${brand.name}" appears before ${p.domain}, which is not an official ${brand.name} domain.`,
          `“${brand.name}” 出现在 ${p.domain} 前面，但后者不是 ${brand.name} 的官方域名。`,
        ),
      });
    }
  }

  // 6. punycode / mixed scripts
  const allLabels = [label, ...subUnicode];
  const mixed = allLabels.find((l) => scriptsIn(l).length > 1);
  if (mixed) {
    findings.push({
      id: "lookalike.mixedScript",
      check: "lookalike",
      severity: "medium",
      points: 20,
      title: bi("Mixes alphabets in one name", "同一名称中混用多种字母"),
      detail: bi(
        `"${mixed}" mixes ${scriptsIn(mixed).join(" + ")} letters. Real sites almost never do this; it is used to fake familiar names. ASCII form: ${asciiHost}`,
        `“${mixed}” 混用了 ${scriptsIn(mixed).join(" + ")} 字母。正规网站几乎不会这样做，这常用于伪造熟悉的名字。ASCII 形式：${asciiHost}`,
      ),
    });
  } else if (asciiHost.split(".").some((l) => l.startsWith("xn--"))) {
    findings.push({
      id: "lookalike.idn",
      check: "lookalike",
      severity: "info",
      points: 0,
      title: bi("Internationalised domain name", "国际化域名"),
      detail: bi(`Displayed as ${unicodeHost}, sent over the network as ${asciiHost}.`, `显示为 ${unicodeHost}，网络上实际为 ${asciiHost}。`),
    });
  }

  return { asciiHost, unicodeHost, official: null, findings };
}

export async function lookalikeCheck(ctx: CheckContext): Promise<CheckResult> {
  const t0 = Date.now();
  const a = analyzeLookalike(ctx.target.asciiHost);
  const official = a.official;
  if (official) {
    return {
      check: "lookalike",
      status: "ok",
      findings: [
        {
          id: "lookalike.official",
          check: "lookalike",
          severity: "info",
          points: 0,
          title: bi(`Official ${official.name} domain`, `${official.name} 官方域名`),
          detail: bi(
            `${a.unicodeHost} belongs to a known official ${official.name} domain. (Official sites can still host redirects — see the other checks.)`,
            `${a.unicodeHost} 属于已知的 ${official.name} 官方域名。（官方网站也可能被用于跳转——请参考其他检查项。）`,
          ),
        },
      ],
      data: { official: official.name, unicodeHost: a.unicodeHost },
      durationMs: Date.now() - t0,
    };
  }
  const scored = a.findings.filter((f) => f.points > 0);
  if (!scored.length) {
    a.findings.push({
      id: "lookalike.none", check: "lookalike", severity: "info", points: 0,
      title: bi(`Doesn't imitate any of ${BRANDS.length} watched brands`, `未发现仿冒 ${BRANDS.length} 个重点品牌`),
      detail: bi("Checked look-alike characters, typos, brand + extra words, brand names in subdomains and mixed alphabets.", "已检查形近字符、拼写错误、品牌名混搭、子域名中的品牌名以及混用字母。"),
    });
  }
  return {
    check: "lookalike",
    status: scored.length ? "warn" : "ok",
    findings: a.findings,
    data: { unicodeHost: a.unicodeHost, asciiHost: a.asciiHost },
    durationMs: Date.now() - t0,
  };
}
