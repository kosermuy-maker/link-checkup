// Headless screenshots of the local UI for the README.
// Usage: npm start (in another terminal), then
//   PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core/index.mjs CHROME=/usr/bin/google-chrome node scripts/screenshots.mjs
// Only benign domains and synthetic lookalikes on reserved TLDs are used.
const pw = await import(process.env.PLAYWRIGHT_CORE ?? "playwright-core");
const chromium = pw.chromium ?? pw.default.chromium;
const BASE = process.env.BASE_URL ?? "http://127.0.0.1:8787/";
const browser = await chromium.launch({ executablePath: process.env.CHROME ?? "/usr/bin/google-chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 1 });

const shots = [
  { name: "home-en", query: "?lang=en" },
  { name: "lookalike-en", query: "?lang=en&url=" + encodeURIComponent("http://paypa1.example/login") },
  { name: "subdomain-trick-zh", query: "?lang=zh&url=" + encodeURIComponent("https://www.paypal.com.account-verify.example/signin") },
  { name: "benign-redirect-en", query: "?lang=en&url=" + encodeURIComponent("http://github.com") },
];
for (const s of shots) {
  await page.goto(BASE + s.query, { waitUntil: "networkidle" });
  if (s.query.includes("url=")) await page.waitForSelector("#result:not([hidden])", { timeout: 30000 });
  await page.screenshot({ path: `docs/screenshots/${s.name}.png`, fullPage: true });
  console.log("saved", s.name);
}
await browser.close();
