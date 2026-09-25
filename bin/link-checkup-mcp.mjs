#!/usr/bin/env node
// npx entry point for the MCP server: registers tsx so the TypeScript sources run without a build step.
import { register } from "tsx/esm/api";
register();
process.env.LINK_CHECKUP_MCP_MAIN = "1";
await import("../src/mcp/server.ts");
