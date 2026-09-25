# Kiro IDE: hooks don't fire / MCP panel is empty

Worked out from the Kiro logs and the bundled `kiro.kiro-agent` extension (Sep 2026 build).

## 1. The workspace was untrusted when the window started, and trust is only read at startup

- The hook module is built once per session with `workspaceTrusted` as a fixed value. When it is false,
  every trigger is swapped for a no-op, and the log shows `hooks.v2.executionDisabledUntrustedWorkspace`.
  The hook files are still *listed* (`v2 hooks loaded N standalone hooks from .kiro/hooks/`), which makes
  it look as if they should work.
- `MCPConfigManager.readAndMergeFileConfigs()` reads `<workspace>/.kiro/settings/mcp.json` only
  `if (this.workspaceTrusted)`. That flag is also captured at startup, so an untrusted start means the
  workspace server is never declared. The MCP panel stays blank, and `Kiro - MCP Logs` stays empty.
- The only `onDidGrantWorkspaceTrust` listener just clears the "untrusted" warning flag. Granting trust
  later changes nothing until the window is reloaded.

**Fix:** trust the folder (`Workspaces: Manage Workspace Trust` → Trust), then run
`Developer: Reload Window` (or restart Kiro). The first lines of `Kiro Logs` should then read
`[TrustMigration] starting (isTrusted=true)`, and the `executionDisabledUntrustedWorkspace` line should
be gone.

## 2. `mcpReason: "admin_disabled"` is not a block

`GovernanceService` starts with `mcpReason = "admin_disabled"` as its default value. It only sets
`mcpDisabled = true` for `Enterprise` / `ExternalIdp` logins whose profile turns MCP off. For a GitHub or
Google login (any plan), the log shows `"mcpDisabled":false`, so MCP is allowed.

## 3. File hooks only fire on agent edits

`PostFileSave` / `PostFileCreate` run from the agent's file-write tools, not from saving in the editor
yourself. To check that hooks run at all, use the **Manual** hook `Run the full test suite (manual)` in
the Agent Hooks panel.

## 4. mcp.json details the IDE enforces

- Keys: `command`, `args`, `cwd`, `env`, `timeout`, `disabled`, `autoApprove`, `disabledTools`, … (zod schema).
- Stdio servers are spawned with `cwd = config.cwd || <workspace folder>`, so `node bin/link-checkup-mcp.mjs` works.
- Only `${ENV_VAR}` placeholders are expanded. `${workspaceFolder}` would be passed through literally, so it isn't used here.
- A user-level `~/.kiro/settings/mcp.json` is optional.

`test/kiro-config.test.ts` checks the hook and MCP files against these rules.
