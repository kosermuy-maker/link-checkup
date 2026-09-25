import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20000,
    env: { LINK_CHECKUP_OFFLINE: "1" },
  },
});
