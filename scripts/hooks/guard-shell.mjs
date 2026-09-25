#!/usr/bin/env node
// Kiro PreToolUse hook helper. Reads the hook event JSON from STDIN and blocks (exit 2) shell commands that
// would fetch or open a URL on a host that is not on the allowlist. Suspicious links must be analysed with
// Link Checkup (`npm run check -- <url>` or the check_url MCP tool), never opened directly.
const ALLOW = [
  "localhost", "127.0.0.1", "example.com", "example.org", "example.net", "github.com", "api.github.com",
  "raw.githubusercontent.com", "registry.npmjs.org", "nodejs.org", "kiro.dev", "rdap.org",
  "cloudflare-dns.com", "dns.google", "urlhaus.abuse.ch", "phishing.army",
];
const FETCHERS = /\b(curl|wget|http|httpie|xdg-open|open|start|google-chrome|chromium|firefox|lynx|w3m|aria2c|Invoke-WebRequest|iwr)\b/i;

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  // The schema of the event may evolve, so scan the whole payload for a shell command string.
  let text = input;
  try {
    const j = JSON.parse(input);
    text = JSON.stringify(j.tool_input ?? j.toolInput ?? j.input ?? j);
  } catch {
    /* plain text */
  }
  if (!FETCHERS.test(text)) process.exit(0);
  const urls = [...text.matchAll(/\b(?:https?|hxxps?):\/\/[^\s"'\\<>]+/gi)].map((m) => m[0]);
  const bad = urls.filter((u) => {
    try {
      const h = new URL(u.replace(/^hxxp/i, "http")).hostname.toLowerCase();
      return !ALLOW.some((a) => h === a || h.endsWith("." + a));
    } catch {
      return true;
    }
  });
  if (bad.length) {
    console.error(
      `Blocked by .kiro/hooks/guard-suspicious-fetch.json: do not open ${bad.join(", ")} directly. ` +
        `Use the link-checkup MCP tool check_url (or \`npm run check -- <url>\`) — it inspects the link without loading the page.`,
    );
    process.exit(2);
  }
  process.exit(0);
});
