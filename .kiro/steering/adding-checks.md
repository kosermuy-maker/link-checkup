---
inclusion: auto
name: adding-checks
description: How to add or modify a risk check, its findings, points and bilingual text. Use when creating a new file in src/checks or changing scoring weights.
---

# Adding or tuning a check

## Finding shape
```ts
{
  id: "lookalike.homoglyph",          // <check>.<reason>, stable, used by tests and the UI
  check: "lookalike",
  severity: "high",                   // info | low | medium | high | critical
  points: 45,                         // contribution to the 0–100 score
  title:  { en: "Imitates paypal.com", zh: "仿冒 paypal.com" },
  detail: { en: "…", zh: "…" }
}
```

## Point guide (keep the scale consistent)
| Signal strength | Points | Examples |
|---|---|---|
| Context only | 0 | registrar name, certificate issuer, official brand domain |
| Weak | 5–10 | plain http, long URL, new certificate, suspicious TLD |
| Moderate | 15–30 | domain < 180 days, TLD swap, combosquat, IP host, "@" in URL |
| Strong | 35–45 | homoglyph / typosquat of a brand, domain < 30 days, brand in subdomain |
| Critical | 90 (severity `critical`) | listed on a public blocklist |

Unknown results (timeouts, RDAP not available) are **0 points** with severity `info`.
Explain *why* a signal matters in `detail`, in both languages, in plain words.
