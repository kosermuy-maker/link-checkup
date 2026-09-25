import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";

/**
 * The single place where the "which addresses may we connect to" policy lives.
 * Only global unicast addresses are allowed. Everything else — loopback, RFC1918,
 * link-local, CGNAT, multicast, reserved, documentation/benchmark ranges, ULA —
 * is blocked, including IPv6 forms that embed a blocked IPv4 address.
 */
export function isBlockedAddress(address: string): boolean {
  let ip = address.trim();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  const zone = ip.indexOf("%");
  if (zone !== -1) return true; // scoped (zone-id) addresses are link-local by definition
  if (!ipaddr.isValid(ip)) return true;
  // ipaddr.isValid accepts legacy forms like "0x7f.1" or "2130706433"; only accept canonical dotted/IPv6.
  if (isIP(ip) === 0) return true;

  const parsed = ipaddr.parse(ip);
  if (parsed.kind() === "ipv4") {
    return (parsed as ipaddr.IPv4).range() !== "unicast";
  }
  const v6 = parsed as ipaddr.IPv6;
  const range = v6.range();
  if (range === "ipv4Mapped") return isBlockedAddress(v6.toIPv4Address().toString());
  if (range === "rfc6052" || range === "6to4" || range === "teredo") {
    const embedded = embeddedIPv4(v6, range);
    return embedded === null ? true : isBlockedAddress(embedded);
  }
  // IPv4-compatible (deprecated ::a.b.c.d)
  const parts = v6.parts;
  if (parts.slice(0, 6).every((p) => p === 0)) return true;
  return range !== "unicast";
}

function embeddedIPv4(v6: ipaddr.IPv6, range: string): string | null {
  const p = v6.parts;
  if (range === "rfc6052") return `${p[6] >> 8}.${p[6] & 255}.${p[7] >> 8}.${p[7] & 255}`; // 64:ff9b::/96
  if (range === "6to4") return `${p[1] >> 8}.${p[1] & 255}.${p[2] >> 8}.${p[2] & 255}`; // 2002:AABB:CCDD::
  if (range === "teredo") {
    const a = p[6] ^ 0xffff;
    const b = p[7] ^ 0xffff;
    return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
  }
  return null;
}

export class BlockedAddressError extends Error {
  constructor(
    public readonly host: string,
    public readonly address: string,
  ) {
    super(`Refusing to connect: ${host} resolves to non-public address ${address}`);
    this.name = "BlockedAddressError";
  }
}

export type Resolver = (host: string) => Promise<string[]>;

export const systemResolver: Resolver = (host) =>
  new Promise((resolve, reject) => {
    dnsLookup(host, { all: true, verbatim: true }, (err, addrs: LookupAddress[]) => {
      if (err) reject(err);
      else resolve(addrs.map((a) => a.address));
    });
  });

/**
 * Resolve a host and ensure *every* address is public. Returns the vetted addresses.
 * IP literals are checked directly (Node skips `lookup` for them, so this matters).
 */
export async function assertPublicHost(host: string, resolver: Resolver = systemResolver): Promise<string[]> {
  const h = host.replace(/^\[|\]$/g, "");
  if (isIP(h)) {
    if (isBlockedAddress(h)) throw new BlockedAddressError(host, h);
    return [h];
  }
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) {
    throw new BlockedAddressError(host, h);
  }
  const addrs = await resolver(h);
  if (addrs.length === 0) throw new Error(`No addresses for ${host}`);
  for (const a of addrs) if (isBlockedAddress(a)) throw new BlockedAddressError(host, a);
  return addrs;
}

/**
 * A `lookup` function for http/https/tls options that only ever hands the socket
 * the address we already vetted — this pins the connection and defeats DNS rebinding.
 */
export function pinnedLookup(vetted: string[]) {
  return (
    _hostname: string,
    options: { all?: boolean } | number | undefined,
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
  ): void => {
    const addr = vetted[0];
    const family = isIP(addr);
    if (typeof options === "object" && options?.all) callback(null, [{ address: addr, family }]);
    else callback(null, addr, family);
  };
}
