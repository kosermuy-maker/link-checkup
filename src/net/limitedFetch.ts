/**
 * fetch() wrapper for FIXED, TRUSTED endpoints only (rdap.org, DoH resolvers, blocklist feeds).
 * Enforces a timeout and a byte cap on the response body. Never use this for user-supplied hosts —
 * use net/safeRequest.ts instead.
 */
export interface LimitedFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export interface LimitedResponse {
  status: number;
  url: string;
  text: string;
}

export async function fetchLimited(url: string, opts: LimitedFetchOptions = {}): Promise<LimitedResponse> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const maxBytes = opts.maxBytes ?? 1_000_000;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error(`Timed out after ${timeoutMs} ms`)), timeoutMs);
  const onAbort = () => ctrl.abort(opts.signal?.reason);
  opts.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const res = await fetch(url, {
      headers: { "user-agent": "LinkCheckup/0.1 (+https://github.com/kosermuy-maker/link-checkup)", ...opts.headers },
      signal: ctrl.signal,
      redirect: "follow",
    });
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new Error(`Response from ${new URL(url).host} exceeded ${maxBytes} bytes`);
        }
        chunks.push(value);
      }
    }
    return { status: res.status, url: res.url, text: Buffer.concat(chunks).toString("utf8") };
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}
