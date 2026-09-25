// Smoke test: spawn the MCP server over stdio, list tools and call them (offline by default).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const online = process.argv.includes("--online");
const transport = new StdioClientTransport({ command: "node", args: ["bin/link-checkup-mcp.mjs"] });
const client = new Client({ name: "smoke", version: "1.0.0" });
await client.connect(transport);
const { tools } = await client.listTools();
console.log("tools:", tools.map((t) => t.name).join(", "));
const r1 = await client.callTool({ name: "check_lookalike", arguments: { domain: "paypa1.example" } });
console.log("\n# check_lookalike paypa1.example\n" + (r1.content as Array<{ text: string }>)[0].text);
const r2 = await client.callTool({ name: "check_url", arguments: { url: "https://www.paypal.com.account-verify.example/signin", offline: !online } });
console.log("\n# check_url (synthetic)\n" + (r2.content as Array<{ text: string }>)[0].text);
if (online) {
  const r3 = await client.callTool({ name: "check_url", arguments: { url: "https://example.com", lang: "zh" } });
  console.log("\n# check_url https://example.com (zh)\n" + (r3.content as Array<{ text: string }>)[0].text);
}
await client.close();
