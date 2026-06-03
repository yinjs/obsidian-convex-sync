import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Default environment is node (crypto-core tests). Convex test files
    // opt into edge-runtime per-file via a `// @vitest-environment` pragma.
    environment: "node",
    include: ["tests/**/*.test.ts", "convex/**/*.test.ts"],
  },
});
