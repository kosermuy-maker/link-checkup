import { describe, it, expect } from "vitest";
import { parseRdap, rdapFindings } from "../src/checks/rdap.ts";
import { assessCertificate } from "../src/checks/tls.ts";
import { parseDoh, dnsFindings } from "../src/checks/dns.ts";
import { matchBlocklists, hostAndParents } from "../src/checks/blocklist.ts";
import { parseDomainList, parseUrlhaus } from "../src/checks/blocklistData.ts";

const NOW = new Date("2026-09-25T00:00:00Z");

describe("RDAP", () => {
  const json = {
    ldhName: "EXAMPLE-NEW.COM",
    status: ["client transfer prohibited"],
    events: [
      { eventAction: "registration", eventDate: "2026-09-22T10:00:00Z" },
      { eventAction: "expiration", eventDate: "2027-09-22T10:00:00Z" },
    ],
    entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]] }],
  };
  it("parses registration date, registrar and age", () => {
    const s = parseRdap(json, "example-new.com", NOW);
    expect(s).toMatchObject({ domain: "example-new.com", registrar: "Example Registrar, Inc.", ageDays: 2 });
    expect(rdapFindings(s)[0].id).toBe("rdap.veryNew");
  });
  it("grades 30–180 days as young and older as info", () => {
    expect(rdapFindings({ domain: "a", status: [], ageDays: 100 })[0].id).toBe("rdap.new");
    expect(rdapFindings({ domain: "a", status: [], ageDays: 4000, registered: "2015-01-01" })[0].points).toBe(0);
  });
  it("flags registry holds", () => {
    expect(rdapFindings({ domain: "a", status: ["client hold"], ageDays: 4000 }).map((f) => f.id)).toContain("rdap.onHold");
  });
});

describe("TLS assessment", () => {
  const good = { authorized: true, subjectAltNames: ["example.com"], issuerO: "Let's Encrypt", validFrom: "Sep 1 00:00:00 2026 GMT", validTo: "Nov 30 00:00:00 2026 GMT" };
  it("valid, older certificate → info only", () => {
    expect(assessCertificate(good, "example.com", NOW).every((f) => f.points === 0)).toBe(true);
  });
  it("untrusted / mismatched certificate → high", () => {
    const f = assessCertificate({ ...good, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID" }, "example.com", NOW);
    expect(f[0]).toMatchObject({ id: "tls.invalid", severity: "high" });
  });
  it("fresh certificate → weak signal", () => {
    const f = assessCertificate({ ...good, validFrom: "Sep 23 00:00:00 2026 GMT" }, "example.com", NOW);
    expect(f.map((x) => x.id)).toContain("tls.newCert");
  });
});

describe("DNS", () => {
  it("parses DoH JSON and grades NXDOMAIN / private answers", () => {
    const a = parseDoh({ Status: 0, Answer: [{ type: 5, data: "cdn.example." }, { type: 1, data: "10.0.0.7" }] });
    expect(a.cnames).toEqual(["cdn.example"]);
    expect(dnsFindings("x.example", a, { status: 0, addresses: [], cnames: [] })[0].id).toBe("dns.privateAddress");
    const nx = { status: 3, addresses: [], cnames: [] };
    expect(dnsFindings("x.example", nx, nx)[0].id).toBe("dns.nxdomain");
  });
});

describe("blocklists (synthetic entries only)", () => {
  const uh = parseUrlhaus("# comment\nhttp://bad-host.example/payload.bin\nhttp://github.com/someone/evil/raw/x.exe\n");
  const lists = { urlhausUrls: uh.urls, urlhausHosts: uh.hosts, phishingDomains: parseDomainList("# c\nphish-kit.example\n0.0.0.0 other.test\n"), fetchedAt: {}, errors: {} };

  it("matches exact URLs (critical)", () => {
    expect(matchBlocklists("http://bad-host.example/payload.bin", lists)[0]).toMatchObject({ source: "URLhaus", kind: "url" });
  });
  it("matches URLhaus hosts but not shared official platforms", () => {
    expect(matchBlocklists("http://bad-host.example/other", lists)[0]).toMatchObject({ kind: "host" });
    expect(matchBlocklists("https://github.com/kosermuy-maker/link-checkup", lists)).toEqual([]);
  });
  it("matches Phishing Army domains including subdomains", () => {
    expect(matchBlocklists("https://login.phish-kit.example/a", lists)[0]).toMatchObject({ source: "Phishing Army", matched: "phish-kit.example" });
    expect(matchBlocklists("https://other.test/", lists)[0]).toMatchObject({ source: "Phishing Army" });
  });
  it("walks parent domains only down to the registrable domain", () => {
    expect(hostAndParents("a.b.example.co.uk")).toEqual(["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"]);
  });
});
