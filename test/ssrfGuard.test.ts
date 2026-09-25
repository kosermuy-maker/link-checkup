import { describe, it, expect, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { assertPublicHost, BlockedAddressError, isBlockedAddress } from "../src/net/ssrfGuard.ts";
import { headOnlyRequest, tlsHandshake, DisallowedPortError } from "../src/net/safeRequest.ts";

describe("SSRF guard examples", () => {
  it.each(["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:c0a8:0101::1", "0.0.0.0", "2130706433"])(
    "blocks %s",
    (ip) => expect(isBlockedAddress(ip)).toBe(true),
  );

  it("rejects hosts whose DNS answer contains ANY private address", async () => {
    await expect(assertPublicHost("rebind.example", async () => ["93.184.215.14", "127.0.0.1"])).rejects.toBeInstanceOf(BlockedAddressError);
    await expect(assertPublicHost("ok.example", async () => ["93.184.215.14"])).resolves.toEqual(["93.184.215.14"]);
  });

  it("rejects localhost-style names without resolving", async () => {
    let called = false;
    await expect(assertPublicHost("printer.local", async () => ((called = true), ["8.8.8.8"]))).rejects.toBeInstanceOf(BlockedAddressError);
    expect(called).toBe(false);
  });
});

describe("safeRequest never reaches internal services", () => {
  let hits = 0;
  const server = http.createServer((_req, res) => {
    hits++;
    res.end("secret");
  });
  const ready = new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
  afterAll(() => server.close());

  it("refuses a loopback IP literal (checked before connecting)", async () => {
    await ready;
    await expect(headOnlyRequest("http://127.0.0.1/")).rejects.toBeInstanceOf(BlockedAddressError);
    expect(hits).toBe(0);
  });

  it("refuses non-80/443 ports before any connection", async () => {
    const port = await ready;
    await expect(headOnlyRequest(`http://127.0.0.1:${port}/`)).rejects.toBeInstanceOf(DisallowedPortError);
    expect(hits).toBe(0);
  });

  it("refuses a public-looking name that resolves to loopback (DNS rebinding)", async () => {
    await expect(headOnlyRequest("http://innocent.example/", { resolver: async () => ["127.0.0.1"] })).rejects.toBeInstanceOf(BlockedAddressError);
    await expect(tlsHandshake("innocent.example", { resolver: async () => ["10.0.0.5"] })).rejects.toBeInstanceOf(BlockedAddressError);
    expect(hits).toBe(0);
  });
});
