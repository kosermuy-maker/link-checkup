import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { assertPublicHost, pinnedLookup, systemResolver, type Resolver } from "./ssrfGuard.ts";

export const ALLOWED_PORTS = new Set([80, 443]);
export const DEFAULT_TIMEOUT_MS = 6000;
export const USER_AGENT = "LinkCheckup/0.1 (+https://github.com/kosermuy-maker/link-checkup; header-only risk check)";

export class DisallowedPortError extends Error {
  constructor(public readonly port: number) {
    super(`Port ${port} is not contacted (only 80/443)`);
    this.name = "DisallowedPortError";
  }
}

export interface HeadResult {
  status: number;
  location?: string;
  method: "HEAD" | "GET";
  remoteAddress?: string;
}

export interface SafeRequestOptions {
  timeoutMs?: number;
  resolver?: Resolver;
  signal?: AbortSignal;
}

function portOf(u: URL): number {
  return u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
}

/**
 * Ask a user-supplied URL for its response *headers only*.
 * - SSRF-guarded (every resolved address must be public; the vetted address is pinned)
 * - HEAD first; on 405/501 falls back to GET with `Range: bytes=0-0`
 * - the socket is destroyed as soon as headers arrive: no body is ever read or stored
 */
export async function headOnlyRequest(target: string, opts: SafeRequestOptions = {}): Promise<HeadResult> {
  const u = new URL(target);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`Unsupported scheme ${u.protocol}`);
  const port = portOf(u);
  if (!ALLOWED_PORTS.has(port)) throw new DisallowedPortError(port);
  const vetted = await assertPublicHost(u.hostname, opts.resolver ?? systemResolver);

  const first = await rawHeaderRequest(u, "HEAD", vetted, opts);
  if (first.status === 405 || first.status === 501) {
    return rawHeaderRequest(u, "GET", vetted, opts);
  }
  return first;
}

function rawHeaderRequest(
  u: URL,
  method: "HEAD" | "GET",
  vetted: string[],
  opts: SafeRequestOptions,
): Promise<HeadResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const mod = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      u,
      {
        method,
        lookup: pinnedLookup(vetted) as never,
        headers: {
          "user-agent": USER_AGENT,
          accept: "*/*",
          ...(method === "GET" ? { range: "bytes=0-0" } : {}),
        },
        timeout: timeoutMs,
        // Certificate problems are assessed separately by the TLS check; here we only want headers.
        rejectUnauthorized: false,
        signal: opts.signal,
        maxHeaderSize: 16 * 1024,
        agent: false,
      },
      (res) => {
        const loc = res.headers.location;
        const result: HeadResult = {
          status: res.statusCode ?? 0,
          location: Array.isArray(loc) ? loc[0] : loc,
          method,
          remoteAddress: res.socket?.remoteAddress,
        };
        // Never read the body.
        res.destroy();
        req.destroy();
        resolve(result);
      },
    );
    req.on("timeout", () => req.destroy(new Error(`Timed out after ${timeoutMs} ms`)));
    req.on("error", reject);
    req.end();
  });
}

export interface TlsInfo {
  authorized: boolean;
  authorizationError?: string;
  protocol?: string | null;
  subjectCN?: string;
  subjectAltNames: string[];
  issuerO?: string;
  issuerCN?: string;
  validFrom?: string;
  validTo?: string;
  fingerprint256?: string;
}

/** TLS handshake only (SNI = host). No HTTP request is sent. */
export async function tlsHandshake(host: string, opts: SafeRequestOptions & { port?: number } = {}): Promise<TlsInfo> {
  const port = opts.port ?? 443;
  if (!ALLOWED_PORTS.has(port)) throw new DisallowedPortError(port);
  const vetted = await assertPublicHost(host, opts.resolver ?? systemResolver);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const isIpHost = /^[\d.]+$|:/.test(host);
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: isIpHost ? undefined : host,
      lookup: pinnedLookup(vetted) as never,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ALPNProtocols: ["http/1.1"],
    });
    const done = (fn: () => void) => {
      socket.removeAllListeners();
      socket.on("error", () => {});
      socket.destroy();
      fn();
    };
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate(false);
      const info: TlsInfo = {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        protocol: socket.getProtocol(),
        subjectCN: first(cert?.subject?.CN),
        subjectAltNames: (cert?.subjectaltname ?? "")
          .split(/,\s*/)
          .filter(Boolean)
          .map((s) => s.replace(/^DNS:/, "")),
        issuerO: first(cert?.issuer?.O),
        issuerCN: first(cert?.issuer?.CN),
        validFrom: cert?.valid_from,
        validTo: cert?.valid_to,
        fingerprint256: cert?.fingerprint256,
      };
      // Hostname check (rejectUnauthorized:false skips it, so do it explicitly).
      if (!isIpHost && cert && Object.keys(cert).length) {
        const err = tls.checkServerIdentity(host, cert);
        if (err) {
          info.authorized = false;
          info.authorizationError = info.authorizationError ?? "ERR_TLS_CERT_ALTNAME_INVALID";
        }
      }
      done(() => resolve(info));
    });
    socket.once("timeout", () => done(() => reject(new Error(`TLS handshake timed out after ${timeoutMs} ms`))));
    socket.once("error", (e) => done(() => reject(e)));
  });
}

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}
