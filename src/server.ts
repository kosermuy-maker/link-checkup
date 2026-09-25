import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { runCheckup, InputError, VERSION } from "./checkup.ts";

const PUBLIC_DIR = fileURLToPath(new URL("../public/", import.meta.url));
const MAX_BODY = 8 * 1024;
const RATE_LIMIT = 30; // checkups per minute per client
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json",
};
const SECURITY_HEADERS = {
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const hits = new Map<string, number[]>();
export function rateLimited(client: string, now = Date.now()): boolean {
  const recent = (hits.get(client) ?? []).filter((t) => now - t < 60_000);
  recent.push(now);
  hits.set(client, recent);
  return recent.length > RATE_LIMIT;
}

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS, ...headers });
  res.end(data);
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function createServer(): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "POST" && url.pathname === "/api/check") {
        const client = req.socket.remoteAddress ?? "unknown";
        if (rateLimited(client)) return send(res, 429, { error: { en: "Too many checks — wait a minute.", zh: "检查过于频繁，请稍候一分钟。" } });
        let body: { url?: unknown; offline?: unknown };
        try {
          body = JSON.parse(await readBody(req));
        } catch {
          return send(res, 400, { error: { en: "Send JSON like {\"url\": \"…\"} (max 8 KB).", zh: "请发送 JSON，例如 {\"url\": \"…\"}（最大 8 KB）。" } });
        }
        try {
          const report = await runCheckup(String(body.url ?? ""), { offline: body.offline === true ? true : undefined });
          return send(res, 200, report);
        } catch (e) {
          if (e instanceof InputError) return send(res, 400, { error: e.messages });
          throw e;
        }
      }
      if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { ok: true, version: VERSION });
      if (req.method === "GET" || req.method === "HEAD") {
        const rel = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname).replace(/^\/+/, "");
        const file = normalize(join(PUBLIC_DIR, rel));
        if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, { error: "forbidden" });
        try {
          const data = await readFile(file);
          return send(res, 200, data, { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": "no-cache" });
        } catch {
          return send(res, 404, { error: "not found" });
        }
      }
      send(res, 405, { error: "method not allowed" });
    } catch (e) {
      console.error(e);
      send(res, 500, { error: { en: "Internal error.", zh: "服务器内部错误。" } });
    }
  });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? "127.0.0.1";
  createServer().listen(port, host, () => {
    console.log(`Link Checkup ${VERSION} → http://${host === "0.0.0.0" ? "localhost" : host}:${port}`);
  });
}
