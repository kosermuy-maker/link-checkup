#!/usr/bin/env node
// Kiro hook helper: verify that public/i18n.js has the same keys for "en" and "zh".
import { readFileSync } from "node:fs";
import vm from "node:vm";

const src = readFileSync(new URL("../../public/i18n.js", import.meta.url), "utf8");
const sandbox = { window: {} };
vm.runInNewContext(src, sandbox);
const { en, zh } = sandbox.window.I18N;

function keys(obj, prefix = "") {
  return Object.entries(obj).flatMap(([k, v]) =>
    v && typeof v === "object" ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}
const a = new Set(keys(en));
const b = new Set(keys(zh));
const missingZh = [...a].filter((k) => !b.has(k));
const missingEn = [...b].filter((k) => !a.has(k));
if (missingZh.length || missingEn.length) {
  if (missingZh.length) console.error(`Missing in zh: ${missingZh.join(", ")}`);
  if (missingEn.length) console.error(`Missing in en: ${missingEn.join(", ")}`);
  process.exit(1);
}
console.log(`i18n OK: ${a.size} keys in en and zh`);
