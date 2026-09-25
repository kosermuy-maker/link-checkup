import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp/server.ts";

describe("MCP server", () => {
  it("exposes check_url and check_lookalike and answers offline", async () => {
    const [a, b] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer();
    await server.connect(a);
    const client = new Client({ name: "test", version: "1.0.0" });
    await client.connect(b);

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["check_lookalike", "check_url"]);

    const look = await client.callTool({ name: "check_lookalike", arguments: { domain: "https://paypa1.example/login" } });
    expect((look.content as Array<{ text: string }>)[0].text).toMatch(/Imitates paypal\.com/);

    const res = await client.callTool({ name: "check_url", arguments: { url: "hxxp://secure-paypal-login[.]test/verify", offline: true, lang: "zh" } });
    const text = (res.content as Array<{ text: string }>)[0].text;
    expect(text).toMatch(/RISK \d+\/100/);
    expect(text).toContain("风险");
    expect((res.structuredContent as { level: string }).level).toMatch(/medium|high/);

    const bad = await client.callTool({ name: "check_url", arguments: { url: "javascript:alert(1)" } });
    expect(bad.isError).toBe(true);
    await client.close();
  });
});
