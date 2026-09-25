---
inclusion: fileMatch
fileMatchPattern: ["src/net/**/*.ts", "src/checks/**/*.ts", "src/checkup.ts"]
---

# Network safety rules (loaded when editing networking or checks)

We analyse links that may be hostile. Treat every user-supplied URL as an attacker-controlled input.

- **SSRF:** resolve the hostname first and refuse to connect if *any* resolved address is not public
  unicast (loopback, RFC1918, link-local, CGNAT, multicast, reserved, IPv4-mapped/embedded private, ULA…).
  IP-literal hosts bypass DNS in Node, so they are checked explicitly before connecting.
  The vetted address is pinned through the socket `lookup` hook so DNS rebinding cannot swap it.
- **Ports:** only 80 and 443 are contacted. Anything else is reported as a finding and not contacted.
- **Methods:** `HEAD` first; if the server rejects HEAD (405/501) use `GET` with `Range: bytes=0-0`
  and destroy the socket as soon as headers arrive. Never pipe, buffer or save a body.
- **Limits:** ≤ 8 redirect hops, 6 s per request, 20 s per checkup, only `http:`/`https:` redirect targets.
- **Testing:** never use real phishing or malware URLs in tests, fixtures, docs or demos. Use benign
  domains (`example.com`, `github.com`) and synthetic lookalikes on reserved TLDs
  (`paypa1.example`, `secure-paypal-login.test`). Network checks are injected/mocked in unit tests.

Example — correct:
```ts
const res = await headOnlyRequest(url, { timeoutMs: 6000 }); // goes through safeLookup
```
Example — wrong (bypasses the guard):
```ts
const res = await fetch(userUrl); // ❌ never do this for user-supplied hosts
```
