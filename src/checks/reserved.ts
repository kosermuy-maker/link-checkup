/** RFC 2606 / 6761 reserved names: never exist on the public internet — used for safe demos and tests. */
const RESERVED_TLDS = new Set(["example", "test", "invalid", "localhost", "local", "internal", "onion"]);

export function isReservedHost(asciiHost: string): boolean {
  const labels = asciiHost.toLowerCase().split(".");
  const tld = labels[labels.length - 1];
  // Note: example.com / .net / .org are real IANA pages and are *not* treated as reserved.
  return RESERVED_TLDS.has(tld);
}
