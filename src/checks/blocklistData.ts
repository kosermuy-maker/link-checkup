import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchLimited } from "../net/limitedFetch.ts";

/**
 * Keyless public feeds. We only download and string-match them — listed URLs are never contacted.
 * - URLhaus (abuse.ch) "online URLs" plain-text feed — CC0.
 * - Phishing Army extended blocklist (domains) — CC BY-NC 4.0, fetched at runtime, not redistributed.
 */
export const FEEDS = {
  urlhaus: { url: "https://urlhaus.abuse.ch/downloads/text_online/", maxBytes: 20_000_000 },
  phishingArmy: { url: "https://phishing.army/download/phishing_army_blocklist.txt", maxBytes: 20_000_000 },
} as const;

export interface Blocklists {
  urlhausUrls: Set<string>;
  urlhausHosts: Set<string>;
  phishingDomains: Set<string>;
  fetchedAt: Record<string, string>;
  errors: Record<string, string>;
}

const TTL_MS = 60 * 60 * 1000;
const STALE_OK_MS = 24 * 60 * 60 * 1000;
let memo: { at: number; lists: Blocklists } | null = null;
let inflight: Promise<Blocklists> | null = null;

export function cacheDir(): string {
  return process.env.LINK_CHECKUP_CACHE_DIR ?? join(tmpdir(), "link-checkup-cache");
}

export function canonicalUrlKey(u: string): string {
  try {
    const x = new URL(u.trim());
    x.hash = "";
    return x.href.replace(/\/$/, "").toLowerCase();
  } catch {
    return u.trim().toLowerCase();
  }
}

export function parseUrlhaus(text: string): { urls: Set<string>; hosts: Set<string> } {
  const urls = new Set<string>();
  const hosts = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    urls.add(canonicalUrlKey(s));
    try {
      hosts.add(new URL(s).hostname.toLowerCase().replace(/^\[|\]$/g, ""));
    } catch {
      /* ignore malformed lines */
    }
  }
  return { urls, hosts };
}

export function parseDomainList(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim().toLowerCase();
    if (!s || s.startsWith("#")) continue;
    const d = s.split(/\s+/).pop()!; // tolerate hosts-file format "0.0.0.0 domain"
    if (d.includes(".")) out.add(d.replace(/\.$/, ""));
  }
  return out;
}

async function getFeed(name: keyof typeof FEEDS, signal?: AbortSignal): Promise<{ text: string; at: string }> {
  const dir = cacheDir();
  const file = join(dir, `${name}.txt`);
  try {
    const st = await stat(file);
    if (Date.now() - st.mtimeMs < TTL_MS) return { text: await readFile(file, "utf8"), at: st.mtime.toISOString() };
  } catch {
    /* no cache */
  }
  try {
    const res = await fetchLimited(FEEDS[name].url, { timeoutMs: 15000, maxBytes: FEEDS[name].maxBytes, signal });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    await mkdir(dir, { recursive: true });
    await writeFile(file, res.text);
    return { text: res.text, at: new Date().toISOString() };
  } catch (e) {
    try {
      const st = await stat(file);
      if (Date.now() - st.mtimeMs < STALE_OK_MS) return { text: await readFile(file, "utf8"), at: st.mtime.toISOString() };
    } catch {
      /* no stale cache either */
    }
    throw e;
  }
}

export async function loadBlocklists(signal?: AbortSignal): Promise<Blocklists> {
  if (memo && Date.now() - memo.at < TTL_MS) return memo.lists;
  if (inflight) return inflight;
  inflight = (async () => {
    const lists: Blocklists = { urlhausUrls: new Set(), urlhausHosts: new Set(), phishingDomains: new Set(), fetchedAt: {}, errors: {} };
    const [uh, pa] = await Promise.allSettled([getFeed("urlhaus", signal), getFeed("phishingArmy", signal)]);
    if (uh.status === "fulfilled") {
      const p = parseUrlhaus(uh.value.text);
      lists.urlhausUrls = p.urls;
      lists.urlhausHosts = p.hosts;
      lists.fetchedAt.urlhaus = uh.value.at;
    } else lists.errors.urlhaus = String((uh.reason as Error)?.message ?? uh.reason);
    if (pa.status === "fulfilled") {
      lists.phishingDomains = parseDomainList(pa.value.text);
      lists.fetchedAt.phishingArmy = pa.value.at;
    } else lists.errors.phishingArmy = String((pa.reason as Error)?.message ?? pa.reason);
    if (Object.keys(lists.fetchedAt).length) memo = { at: Date.now(), lists };
    return lists;
  })().finally(() => {
    inflight = null;
  });
  return inflight;
}
