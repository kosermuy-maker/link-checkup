#!/usr/bin/env node
import { register } from "tsx/esm/api";
register();
process.argv[1] = "cli.ts";
await import("../src/cli.ts");
