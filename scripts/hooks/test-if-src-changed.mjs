#!/usr/bin/env node
// Kiro PostToolUse hook helper for shell tools. File hooks (PostFileSave) only fire for the agent's file-write
// tools; an agent that edits code with a shell command (sed, echo >>, …) bypasses them. After every agent
// shell command this script fingerprints src/ and test/ (tracked diff + untracked files) and re-runs the test
// suite only when that fingerprint changed. Non-zero exit + stderr feeds failures back to the agent.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

process.stdin.resume();
process.stdin.on("data", () => {});
process.stdin.on("end", main);
if (process.stdin.isTTY) main();

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

function main() {
  let fingerprint;
  try {
    const h = createHash("sha256");
    h.update(git(["diff", "HEAD", "--", "src", "test"]));
    for (const f of git(["ls-files", "--others", "--exclude-standard", "--", "src", "test"]).split("\n").filter(Boolean)) {
      h.update(f).update(readFileSync(f));
    }
    fingerprint = h.digest("hex");
  } catch {
    process.exit(0); // not a git checkout: stay silent rather than break the agent's shell tool
  }
  const stamp = join(".cache", "hook-src-fingerprint");
  if (existsSync(stamp) && readFileSync(stamp, "utf8") === fingerprint) process.exit(0);
  mkdirSync(".cache", { recursive: true });
  writeFileSync(stamp, fingerprint);

  const r = spawnSync("npm", ["test", "--silent"], { encoding: "utf8" });
  if (r.status === 0) {
    console.log("src/ or test/ changed via shell: test suite passed.");
    process.exit(0);
  }
  console.error(`src/ or test/ changed via shell and the test suite FAILED:\n${(r.stdout ?? "") + (r.stderr ?? "")}`.slice(-8000));
  process.exit(2);
}
