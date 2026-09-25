// Guards the .kiro/ files against the schema Kiro IDE actually enforces
// (kiro.kiro-agent extension: v2 hook loader + MCPConfigManager), so a typo
// cannot silently leave a hook or the MCP server inert.
import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const hooksDir = join(root, ".kiro", "hooks");

// Valid v2 triggers, as listed by the IDE's hook schema.
const TRIGGERS = [
  "PostFileCreate", "PostFileSave", "PostFileDelete", "PreToolUse", "PostToolUse",
  "UserPromptSubmit", "SessionStart", "Stop", "PreTaskExec", "PostTaskExec", "Manual",
];
const MATCHER_TRIGGERS = new Set(["PostFileCreate", "PostFileSave", "PostFileDelete", "PreToolUse", "PostToolUse"]);
const HOOK_KEYS = new Set(["name", "description", "trigger", "matcher", "action", "timeout", "enabled", "confirm"]);

const hookFiles = readdirSync(hooksDir).filter((f) => f.endsWith(".json"));
const hooks = hookFiles.flatMap((f) => {
  const doc = JSON.parse(readFileSync(join(hooksDir, f), "utf8"));
  expect(doc.version, f).toBe("v1");
  return (doc.hooks as any[]).map((h) => ({ file: f, ...h }));
});
const byFile = (f: string) => hooks.find((h) => h.file === f)!;

describe(".kiro/hooks", () => {
  it("every hook matches the IDE schema", () => {
    expect(hooks.length).toBeGreaterThanOrEqual(7);
    for (const { file, ...h } of hooks) {
      for (const k of Object.keys(h)) expect(HOOK_KEYS.has(k), `${file}: unknown key ${k}`).toBe(true);
      expect(typeof h.name, file).toBe("string");
      expect(TRIGGERS, file).toContain(h.trigger);
      if (h.matcher !== undefined) {
        expect(MATCHER_TRIGGERS.has(h.trigger), `${file}: matcher ignored for ${h.trigger}`).toBe(true);
        expect(() => new RegExp(h.matcher), file).not.toThrow();
      }
      expect(["command", "agent"], file).toContain(h.action.type);
      if (h.action.type === "command") expect(h.action.command, file).toBeTruthy();
      else expect(h.action.prompt, file).toBeTruthy();
    }
  });

  it("the shell guard matches Kiro's shell tool name", () => {
    const re = new RegExp(byFile("guard-suspicious-fetch.json").matcher);
    expect(re.test("run_command")).toBe(true);
    expect(re.test("execute_bash")).toBe(true);
    expect(re.test("fs_write")).toBe(false);
  });

  it("the test-on-save hook matches both relative and absolute paths", () => {
    const re = new RegExp(byFile("run-tests-on-save.json").matcher);
    expect(re.test("src/checks/urlShape.ts")).toBe(true);
    expect(re.test("/workspace/link-checkup/test/urlShape.test.ts")).toBe(true);
    expect(re.test("README.md")).toBe(false);
  });

  it("hook scripts referenced by command actions exist", () => {
    for (const h of hooks) {
      const m = /node\s+(\S+\.m?js)/.exec(h.action.command ?? "");
      if (m) expect(existsSync(join(root, m[1])), `${h.file}: ${m[1]}`).toBe(true);
    }
  });
});

describe(".kiro/agents", () => {
  it("custom agents do not redeclare MCP servers (profile servers are spawned without the workspace cwd and shadow mcp.json)", () => {
    const dir = join(root, ".kiro", "agents");
    for (const f of readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      const agent = JSON.parse(readFileSync(join(dir, f), "utf8"));
      expect(agent.mcpServers, f).toBeUndefined();
    }
  });
});

describe(".kiro/settings/mcp.json", () => {
  const cfg = JSON.parse(readFileSync(join(root, ".kiro", "settings", "mcp.json"), "utf8"));
  const server = cfg.mcpServers["link-checkup"];
  const ALLOWED = new Set([
    "command", "args", "cwd", "env", "timeout", "waitForReady", "disabledTools", "autoApprove",
    "versionNegotiation", "url", "headers", "oauth", "oauthScopes", "disabled", "type",
  ]);

  it("declares an enabled stdio server with only schema keys", () => {
    expect(server).toBeDefined();
    expect(server.disabled).not.toBe(true);
    for (const k of Object.keys(server)) expect(ALLOWED.has(k), `unknown key ${k}`).toBe(true);
    expect(server.command).toBe("node");
  });

  it("uses a workspace-relative entry point (the IDE spawns with cwd = workspace folder and does not expand ${workspaceFolder})", () => {
    const text = JSON.stringify(server);
    expect(text).not.toContain("${workspaceFolder}");
    expect(server.cwd).toBeUndefined();
    expect(existsSync(join(root, server.args[0]))).toBe(true);
  });
});
