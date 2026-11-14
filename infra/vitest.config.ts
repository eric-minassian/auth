import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // Synthesizing a full stack (asset staging + validation plugins) takes a few seconds.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
